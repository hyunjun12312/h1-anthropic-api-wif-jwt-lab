#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const BASE_URL = process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
const VERSION = process.env.ANTHROPIC_VERSION || "2023-06-01";
const TUNNELS_BETA = process.env.ANTHROPIC_TUNNELS_BETA || "mcp-tunnels-2026-05-19";
const AUDIENCE = process.env.INPUT_AUDIENCE || "https://api.anthropic.com";
const OUT_DIR = "evidence";

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function redact(value, keyName = "") {
  if (Array.isArray(value)) return value.map((item) => redact(item, keyName));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        if (/access_token|refresh_token|authorization|assertion|token|secret|api[-_]?key/i.test(key)) {
          return [key, "[redacted:sensitive-field]"];
        }
        return [key, redact(child, key)];
      }),
    );
  }
  if (typeof value === "string") {
    let out = value
      .replace(/sk-ant-[A-Za-z0-9._-]+/g, "[redacted:anthropic-key]")
      .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
      .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[redacted:jwt]");
    if (/token|secret|api[-_]?key|authorization|assertion/i.test(keyName)) {
      out = `[redacted:${keyName}:sha256=${sha256(value).slice(0, 12)}:len=${value.length}]`;
    }
    return out.length > 6000 ? `${out.slice(0, 6000)}...[truncated]` : out;
  }
  return value;
}

function idFingerprint(value) {
  if (typeof value !== "string" || !value) return null;
  const prefix = value.includes("_") ? value.split("_")[0] : value.slice(0, 4);
  return `${prefix}_${value.slice(-6)}:${value.length}`;
}

async function getGithubOidc(audience) {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) throw new Error("Missing GitHub OIDC env. Need id-token: write.");
  const url = new URL(requestUrl);
  url.searchParams.set("audience", audience);
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${requestToken}`, accept: "application/json" },
  });
  const body = await res.json();
  if (!res.ok || typeof body.value !== "string") {
    throw new Error(`GitHub OIDC request failed: ${res.status}`);
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

function optional(value) {
  return value && String(value).trim() ? value : undefined;
}

async function exchange(assertion) {
  const body = {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
    organization_id: process.env.ANTHROPIC_ORGANIZATION_ID,
    federation_rule_id: process.env.ANTHROPIC_FEDERATION_RULE_ID,
    service_account_id: optional(process.env.ANTHROPIC_SERVICE_ACCOUNT_ID),
    workspace_id: optional(process.env.ANTHROPIC_WORKSPACE_ID),
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
  const parsedResponse = await parseJsonResponse(res);
  const accessToken = typeof parsedResponse.parsed?.access_token === "string" ? parsedResponse.parsed.access_token : null;
  return {
    accessToken,
    result: {
      status: res.status,
      ok: res.ok,
      content_type: parsedResponse.contentType,
      body_sha256: sha256(parsedResponse.text),
      access_token_returned: Boolean(accessToken),
      token_type: parsedResponse.parsed?.token_type ?? null,
      expires_in: parsedResponse.parsed?.expires_in ?? null,
      error_type: parsedResponse.parsed?.error?.type ?? parsedResponse.parsed?.error ?? null,
      error_message: parsedResponse.parsed?.error?.message ?? parsedResponse.parsed?.error_description ?? null,
      body_preview: redact(parsedResponse.parsed),
    },
  };
}

async function callApi(label, accessToken, method, path, extraHeaders = {}, body = undefined) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      "anthropic-version": VERSION,
      authorization: `Bearer ${accessToken}`,
      "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const parsedResponse = await parseJsonResponse(res);
  const parsed = parsedResponse.parsed;
  return {
    label,
    method,
    path,
    status: res.status,
    ok: res.ok,
    content_type: parsedResponse.contentType,
    body_sha256: sha256(parsedResponse.text),
    body_bytes: parsedResponse.text.length,
    data_count: Array.isArray(parsed?.data) ? parsed.data.length : null,
    next_page_present: typeof parsed?.next_page === "string",
    tunnel_fingerprints: Array.isArray(parsed?.data)
      ? parsed.data.map((item) => ({
          id: idFingerprint(item.id),
          domain_sha256_12: typeof item.domain === "string" ? sha256(item.domain).slice(0, 12) : null,
          workspace_id: idFingerprint(item.workspace_id),
          archived: Boolean(item.archived_at),
          type: item.type || null,
        }))
      : [],
    error_type: parsed?.error?.type ?? parsed?.error ?? null,
    error_message: parsed?.error?.message ?? null,
    body_preview: res.ok ? "[success body omitted]" : redact(parsed),
  };
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const assertion = await getGithubOidc(AUDIENCE);
  const exchangeResult = await exchange(assertion);
  const calls = [];
  if (exchangeResult.accessToken) {
    calls.push(
      await callApi(
        "list-tunnels-all",
        exchangeResult.accessToken,
        "GET",
        "/v1/organizations/tunnels?include_archived=true&limit=10",
        { "anthropic-beta": TUNNELS_BETA },
      ),
    );
    if (process.env.ANTHROPIC_WORKSPACE_ID) {
      calls.push(
        await callApi(
          "list-tunnels-workspace-filter",
          exchangeResult.accessToken,
          "GET",
          `/v1/organizations/tunnels?include_archived=true&limit=10&workspace_id=${encodeURIComponent(process.env.ANTHROPIC_WORKSPACE_ID)}`,
          { "anthropic-beta": TUNNELS_BETA },
        ),
      );
    }
    calls.push(await callApi("models-negative-scope-control", exchangeResult.accessToken, "GET", "/v1/models"));
    calls.push(
      await callApi(
        "tunnels-missing-beta-negative-control",
        exchangeResult.accessToken,
        "GET",
        "/v1/organizations/tunnels?include_archived=true&limit=1",
      ),
    );
  }
  const evidence = {
    generated_at: new Date().toISOString(),
    scope_asset: "api.anthropic.com / MCP tunnels / WIF",
    claim_tested:
      "Whether a GitHub Actions WIF token scoped to org:manage_tunnels can access MCP Tunnels API and whether it has non-tunnel API authority.",
    safety: {
      no_secrets_saved: true,
      github_oidc_token_not_saved: true,
      anthropic_access_token_not_saved: true,
      tunnel_token_not_requested: true,
      owned_repo_only: true,
    },
    config_fingerprints: {
      organization_id: idFingerprint(process.env.ANTHROPIC_ORGANIZATION_ID),
      workspace_id: idFingerprint(process.env.ANTHROPIC_WORKSPACE_ID),
      federation_rule_id: idFingerprint(process.env.ANTHROPIC_FEDERATION_RULE_ID),
      service_account_id: idFingerprint(process.env.ANTHROPIC_SERVICE_ACCOUNT_ID),
      audience_sha256_12: sha256(AUDIENCE).slice(0, 12),
      tunnels_beta: TUNNELS_BETA,
    },
    exchange: exchangeResult.result,
    calls,
    measured_facts: {
      access_token_returned: exchangeResult.result.access_token_returned,
      tunnel_list_2xx_count: calls.filter((item) => item.label.startsWith("list-tunnels") && item.ok).length,
      non_tunnel_models_2xx_count: calls.filter((item) => item.label === "models-negative-scope-control" && item.ok).length,
      missing_beta_2xx_count: calls.filter((item) => item.label === "tunnels-missing-beta-negative-control" && item.ok).length,
    },
    classification:
      exchangeResult.result.access_token_returned && calls.some((item) => item.label.startsWith("list-tunnels") && item.ok)
        ? "owner_control_ok_org_manage_tunnels_token"
        : "blocked_no_tunnels_owner_control",
  };
  const outPath = `${OUT_DIR}/wif-tunnel-scope-probe-evidence.json`;
  await writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      {
        outPath,
        classification: evidence.classification,
        measured_facts: evidence.measured_facts,
        calls: calls.map((item) => ({
          label: item.label,
          status: item.status,
          ok: item.ok,
          data_count: item.data_count,
          error_type: item.error_type,
          error_message: item.error_message,
        })),
        evidence_sha256: sha256(JSON.stringify(evidence)),
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
