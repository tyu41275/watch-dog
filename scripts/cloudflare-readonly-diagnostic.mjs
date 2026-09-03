import { readFileSync, writeFileSync } from "node:fs";

const API_ORIGIN = "https://api.cloudflare.com";
const WORKER_NAME = "watch-dog";
const ALLOWED_CLASSIFICATIONS = new Set([
  "AUTHENTICATION_OR_ACCOUNT_MISMATCH",
  "WORKER_ABSENCE",
  "STRICT_REMOTE_API_CONFIGURATION_DRIFT",
  "STRICT_REMOTE_DASHBOARD_CONFIGURATION_DRIFT",
  "LOCAL_BINDING_OR_VARIABLE_COLLIDES_WITH_REMOTE_SECRET",
  "WORKFLOW_OWNERSHIP_CONFLICT",
  "CLOUDFLARE_API_FAILURE",
  "OTHER_SAFELY_CLASSIFIABLE",
  "INCONCLUSIVE_SAFE_READ",
]);

const env = process.env;
const accountId = env.CLOUDFLARE_ACCOUNT_ID ?? "";
const apiToken = env.CLOUDFLARE_API_TOKEN ?? "";
const outputPath = env.DIAGNOSTIC_OUTPUT_PATH;
const config = JSON.parse(readFileSync("wrangler.jsonc", "utf8"));

const counts = {
  attempted: 0,
  succeeded: 0,
  denied: 0,
  not_found: 0,
  failed: 0,
};

const evidence = {
  credential_inputs_present: Boolean(accountId && apiToken),
  token_verified_active: false,
  account_worker_list_readable: false,
  worker_exists: false,
  worker_source_api: false,
  worker_source_dashboard: false,
  remote_metadata_complete: false,
  remote_config_drift: false,
  remote_secret_collision: false,
  workflow_conflict: false,
  cloudflare_api_failure: false,
  committed_config_authenticated: false,
  read_only_enforced: true,
  api_write_count: 0,
  provider_call_count: 0,
  remote_binding_count: 0,
  remote_secret_count: 0,
  config_mismatch_count: 0,
};

let classification = "INCONCLUSIVE_SAFE_READ";
let uncertainty = "NONE";
let remediation = "NONE";

function finish() {
  if (!ALLOWED_CLASSIFICATIONS.has(classification)) {
    classification = "INCONCLUSIVE_SAFE_READ";
    uncertainty = "INTERNAL_CLASSIFICATION_GUARD_TRIGGERED";
    remediation = "REVIEW_SANITIZED_DIAGNOSTIC_IMPLEMENTATION";
  }

  const result = {
    schema_version: 1,
    mode: "cloudflare_read_only_pre_redispatch",
    diagnostic_branch: env.GITHUB_REF_NAME ?? "LOCAL",
    diagnostic_head: env.GITHUB_SHA ?? "LOCAL",
    workflow_run_id: env.GITHUB_RUN_ID ?? "LOCAL",
    accepted_product_revision: env.EXPECTED_PRODUCT_SHA ?? "UNKNOWN",
    classification,
    evidence: {
      ...evidence,
      api_read_attempt_count: counts.attempted,
      api_read_success_count: counts.succeeded,
      api_read_denied_count: counts.denied,
      api_read_not_found_count: counts.not_found,
      api_read_failure_count: counts.failed,
    },
    remaining_uncertainty: uncertainty,
    remediation_code: remediation,
  };

  const serialized = `${JSON.stringify(result, null, 2)}\n`;
  if (outputPath) writeFileSync(outputPath, serialized, { mode: 0o600 });
  process.stdout.write(`DIAGNOSTIC_RESULT=${JSON.stringify(result)}\n`);
}

function classifyApiRead(read) {
  if (read.kind === "denied") {
    classification = "AUTHENTICATION_OR_ACCOUNT_MISMATCH";
    remediation = "REPLACE_OR_REALIGN_GITHUB_CLOUDFLARE_CREDENTIALS";
    uncertainty = "TOKEN_SCOPE_VS_ACCOUNT_ID_MISMATCH_NOT_DISTINGUISHABLE_WITHOUT_BROADER_ACCESS";
    return true;
  }
  if (read.kind === "failed") {
    classification = "CLOUDFLARE_API_FAILURE";
    remediation = "RETRY_READ_ONLY_DIAGNOSTIC_AFTER_CLOUDFLARE_API_RECOVERY";
    uncertainty = "TRANSIENT_VS_PERSISTENT_API_FAILURE";
    evidence.cloudflare_api_failure = true;
    return true;
  }
  return false;
}

async function apiGet(path) {
  if (!path.startsWith("/client/v4/") || path.includes("..")) {
    throw new Error("read endpoint allowlist rejected path");
  }
  counts.attempted += 1;
  try {
    const response = await fetch(new URL(path, API_ORIGIN), {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        Accept: "application/json",
      },
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      counts.failed += 1;
      return { kind: "failed" };
    }
    if (response.ok && body?.success === true) {
      counts.succeeded += 1;
      return { kind: "ok", result: body.result, resultInfo: body.result_info };
    }
    if (response.status === 401 || response.status === 403) {
      counts.denied += 1;
      return { kind: "denied" };
    }
    if (response.status === 404) {
      counts.not_found += 1;
      return { kind: "not_found" };
    }
    counts.failed += 1;
    return { kind: "failed" };
  } catch {
    counts.failed += 1;
    return { kind: "failed" };
  }
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

function sameStrings(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function configuredPlainBindingNames() {
  const names = new Set(Object.keys(config.vars ?? {}));
  for (const binding of array(config.durable_objects?.bindings)) names.add(binding.name);
  for (const key of [
    "workflows",
    "d1_databases",
    "kv_namespaces",
    "r2_buckets",
    "vectorize",
    "services",
    "dispatch_namespaces",
  ]) {
    for (const binding of array(config[key])) names.add(binding.binding);
  }
  return names;
}

function compareDashboardConfiguration(parts) {
  const mismatches = [];
  const script = parts.environment?.script ?? {};
  const bindings = array(parts.bindings).filter((binding) => binding?.type !== "secret_text");
  evidence.remote_binding_count = bindings.length;

  if (script.compatibility_date !== config.compatibility_date) mismatches.push("compatibility_date");
  if (!sameStrings(array(script.compatibility_flags), array(config.compatibility_flags))) {
    mismatches.push("compatibility_flags");
  }
  if (Boolean(parts.subdomain?.enabled) !== Boolean(config.workers_dev)) mismatches.push("workers_dev");
  if (Boolean(parts.subdomain?.previews_enabled) !== Boolean(config.preview_urls)) {
    mismatches.push("preview_urls");
  }
  if (array(parts.routes).length + array(parts.domains).length !== array(config.routes).length) {
    mismatches.push("trigger_surface");
  }
  if (array(parts.schedules?.schedules).length !== array(config.triggers?.crons).length) {
    mismatches.push("schedules");
  }
  if ((script.migration_tag ?? null) !== (array(config.migrations).at(-1)?.tag ?? null)) {
    mismatches.push("migration_tag");
  }
  if ((script.placement_mode ?? null) !== (config.placement?.mode ?? null)) mismatches.push("placement");
  if (Boolean(script.observability?.enabled) !== Boolean(config.observability?.enabled)) {
    mismatches.push("observability");
  }

  const expected = new Map([
    [config.assets?.binding, "assets"],
    ...array(config.durable_objects?.bindings).map((binding) => [binding.name, "durable_object_namespace"]),
  ].filter(([name]) => Boolean(name)));
  const actual = new Map(bindings.map((binding) => [binding?.name, binding?.type]));
  if (expected.size !== actual.size) {
    mismatches.push("binding_count");
  } else {
    for (const [name, type] of expected) {
      if (actual.get(name) !== type) mismatches.push("binding_shape");
    }
  }
  const expectedDo = array(config.durable_objects?.bindings).at(0);
  const remoteDo = bindings.find((binding) => binding?.name === expectedDo?.name);
  if (expectedDo && remoteDo?.class_name !== expectedDo.class_name) mismatches.push("durable_object_class");

  evidence.config_mismatch_count = new Set(mismatches).size;
  evidence.remote_config_drift = evidence.config_mismatch_count > 0;
}

async function main() {
  evidence.committed_config_authenticated =
    config.name === WORKER_NAME &&
    config.workers_dev === true &&
    config.preview_urls === false &&
    config.compatibility_date === "2026-08-31" &&
    config.assets?.binding === "ASSETS" &&
    array(config.durable_objects?.bindings).some(
      (binding) => binding.name === "SESSION_COORDINATOR" && binding.class_name === "SessionCoordinator",
    ) &&
    array(config.migrations).some(
      (migration) => migration.tag === "v1" && array(migration.new_sqlite_classes).includes("SessionCoordinator"),
    );

  if (!evidence.committed_config_authenticated) {
    classification = "OTHER_SAFELY_CLASSIFIABLE";
    remediation = "RESTORE_IMMUTABLE_COMMITTED_WRANGLER_CONFIGURATION";
    uncertainty = "COMMITTED_CONFIGURATION_IDENTITY_FAILED";
    return;
  }
  if (!evidence.credential_inputs_present) {
    classification = "AUTHENTICATION_OR_ACCOUNT_MISMATCH";
    remediation = "POPULATE_REQUIRED_GITHUB_CLOUDFLARE_CREDENTIALS";
    uncertainty = "MISSING_CREDENTIAL_INPUT";
    return;
  }

  const token = await apiGet("/client/v4/user/tokens/verify");
  if (classifyApiRead(token)) return;
  if (token.kind !== "ok" || token.result?.status !== "active") {
    classification = "AUTHENTICATION_OR_ACCOUNT_MISMATCH";
    remediation = "REPLACE_INACTIVE_GITHUB_CLOUDFLARE_API_TOKEN";
    uncertainty = "NONE";
    return;
  }
  evidence.token_verified_active = true;

  const encodedAccount = encodeURIComponent(accountId);
  const workerList = await apiGet(`/client/v4/accounts/${encodedAccount}/workers/scripts`);
  if (classifyApiRead(workerList)) return;
  evidence.account_worker_list_readable = workerList.kind === "ok";

  const service = await apiGet(
    `/client/v4/accounts/${encodedAccount}/workers/services/${encodeURIComponent(WORKER_NAME)}`,
  );
  if (classifyApiRead(service)) return;
  if (service.kind === "not_found") {
    classification = evidence.account_worker_list_readable
      ? "WORKER_ABSENCE"
      : "AUTHENTICATION_OR_ACCOUNT_MISMATCH";
    remediation = evidence.account_worker_list_readable
      ? "AMEND_REDISPATCH_FOR_AUTHORIZED_FIRST_WORKER_CREATION"
      : "REALIGN_GITHUB_CLOUDFLARE_ACCOUNT_ID";
    uncertainty = "NONE";
    return;
  }
  if (service.kind !== "ok") {
    classification = "INCONCLUSIVE_SAFE_READ";
    remediation = "REVIEW_CLOUDFLARE_READ_PERMISSIONS";
    uncertainty = "SERVICE_METADATA_UNREADABLE";
    return;
  }

  evidence.worker_exists = true;
  const defaultEnvironment = service.result?.default_environment;
  const source = defaultEnvironment?.script?.last_deployed_from;
  evidence.worker_source_api = source === "api";
  evidence.worker_source_dashboard = source === "dash";

  if (evidence.worker_source_api) {
    classification = "STRICT_REMOTE_API_CONFIGURATION_DRIFT";
    remediation = "AMEND_REDISPATCH_TO_AUTHORIZE_ONE_EXPLICIT_NON_STRICT_UPDATE_OF_EXISTING_API_MANAGED_WORKER";
    uncertainty = "NONE";
    evidence.remote_config_drift = true;
    return;
  }

  const environmentName = defaultEnvironment?.environment;
  if (typeof environmentName !== "string" || !environmentName) {
    classification = "OTHER_SAFELY_CLASSIFIABLE";
    remediation = "REPAIR_OR_RECREATE_WORKER_SERVICE_METADATA_UNDER_EXPLICIT_AMENDMENT";
    uncertainty = "DEFAULT_ENVIRONMENT_METADATA_ABSENT";
    return;
  }

  if (evidence.worker_source_dashboard) {
    const base = `/client/v4/accounts/${encodedAccount}`;
    const worker = encodeURIComponent(WORKER_NAME);
    const remoteEnvironment = encodeURIComponent(environmentName);
    const reads = await Promise.all([
      apiGet(`${base}/workers/services/${worker}/environments/${remoteEnvironment}/bindings`),
      apiGet(`${base}/workers/services/${worker}/environments/${remoteEnvironment}/routes?show_zonename=true`),
      apiGet(`${base}/workers/domains/records?page=0&per_page=5&service=${worker}&environment=${remoteEnvironment}`),
      apiGet(`${base}/workers/services/${worker}/environments/${remoteEnvironment}/subdomain`),
      apiGet(`${base}/workers/services/${worker}/environments/${remoteEnvironment}`),
      apiGet(`${base}/workers/scripts/${worker}/schedules`),
    ]);
    if (reads.some(classifyApiRead)) return;
    if (reads.some((read) => read.kind !== "ok")) {
      classification = "INCONCLUSIVE_SAFE_READ";
      remediation = "RETRY_WITH_COMPLETE_WORKERS_READ_SCOPE";
      uncertainty = "DASHBOARD_CONFIGURATION_METADATA_INCOMPLETE";
      return;
    }
    evidence.remote_metadata_complete = true;
    compareDashboardConfiguration({
      bindings: reads[0].result,
      routes: reads[1].result,
      domains: reads[2].result,
      subdomain: reads[3].result,
      environment: reads[4].result,
      schedules: reads[5].result,
    });
    if (evidence.remote_config_drift) {
      classification = "STRICT_REMOTE_DASHBOARD_CONFIGURATION_DRIFT";
      remediation = "AMEND_COMMITTED_WRANGLER_CONFIG_TO_MATCH_INTENDED_REMOTE_SETTINGS_BEFORE_REDISPATCH";
      uncertainty = "MISMATCH_VALUES_INTENTIONALLY_NOT_EMITTED";
      return;
    }
  }

  const secrets = await apiGet(
    `/client/v4/accounts/${encodedAccount}/workers/scripts/${encodeURIComponent(WORKER_NAME)}/secrets`,
  );
  if (classifyApiRead(secrets)) return;
  if (secrets.kind === "ok") {
    const remoteSecretNames = new Set(array(secrets.result).map((secret) => secret?.name).filter(Boolean));
    evidence.remote_secret_count = remoteSecretNames.size;
    const collisions = [...configuredPlainBindingNames()].filter((name) => remoteSecretNames.has(name));
    evidence.remote_secret_collision = collisions.length > 0;
    evidence.config_mismatch_count = collisions.length;
    if (evidence.remote_secret_collision) {
      classification = "LOCAL_BINDING_OR_VARIABLE_COLLIDES_WITH_REMOTE_SECRET";
      remediation = "AMEND_BINDING_OR_REMOTE_SECRET_TYPE_WITHOUT_EXPOSING_SECRET_VALUES_BEFORE_REDISPATCH";
      uncertainty = "COLLIDING_NAMES_INTENTIONALLY_NOT_EMITTED";
      return;
    }
  } else if (secrets.kind !== "not_found") {
    classification = "INCONCLUSIVE_SAFE_READ";
    remediation = "RETRY_WITH_WORKERS_SECRET_METADATA_READ_SCOPE";
    uncertainty = "REMOTE_SECRET_METADATA_UNREADABLE";
    return;
  }

  evidence.workflow_conflict = array(config.workflows).length > 0;
  if (evidence.workflow_conflict) {
    classification = "WORKFLOW_OWNERSHIP_CONFLICT";
    remediation = "AMEND_COMMITTED_WORKFLOW_BINDING_OWNERSHIP_BEFORE_REDISPATCH";
    uncertainty = "WORKFLOW_NAMES_INTENTIONALLY_NOT_EMITTED";
    return;
  }

  classification = "OTHER_SAFELY_CLASSIFIABLE";
  remediation = "CAPTURE_A_NEW_SANITIZED_WRANGLER_FAILURE_CLASS_UNDER_EXPLICIT_AMENDMENT";
  uncertainty = "READ_ONLY_PREUPLOAD_CHECKS_MATCH;UPLOAD_PHASE_REMAINS_UNOBSERVED";
}

await main();
finish();
