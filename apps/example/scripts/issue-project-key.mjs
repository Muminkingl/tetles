import { createHash, randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@supabase/supabase-js";

const projectId = process.argv[2];
const environment = process.argv[3] || "production";
const writeToEnv = process.argv[4] === "--write-env";
if (!isUuid(projectId)) {
  console.error("Usage: pnpm --filter tether-supabase-next-example issue-key -- <project-id> [production|development]");
  process.exitCode = 2;
} else if (environment !== "production" && environment !== "development") {
  console.error("Choose production or development for the API key environment.");
  process.exitCode = 2;
} else {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.NEXT_URL;
  const secretKey =
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.NEXT_SERVICE_ROLE_KEY;
  if (!url || !secretKey) {
    console.error("Set the Supabase URL and a server-only Supabase secret key in the root .env file.");
    process.exitCode = 2;
  } else {
    await issueKey(url, secretKey, projectId, environment, writeToEnv);
  }
}

async function issueKey(url, secretKey, targetProjectId, environment, writeToEnv) {
  const envPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../.env");
  if (writeToEnv && !await canWriteLicenseKey(envPath, targetProjectId)) {
    console.error("TETHER_KEY or TETHER_PROJECT_ID is already set to another value; no key was issued.");
    process.exitCode = 2;
    return;
  }

  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
  });
  const apiKey = `tk_${environment === "production" ? "live" : "test"}_${randomBytes(32).toString("base64url")}`;
  const keyHash = createHash("sha256").update(apiKey).digest("hex");
  const { error } = await supabase.from("api_keys").insert({
    project_id: targetProjectId,
    key_hash: keyHash,
    prefix: apiKey.slice(0, 16),
    env: environment,
  });
  if (error) {
    console.error("Could not issue a key. Check that the project exists and migrations are applied.");
    process.exitCode = 1;
    return;
  }

  if (writeToEnv) {
    await writeLicenseEnv(envPath, apiKey, targetProjectId);
    console.log("Issued key and stored TETHER_KEY plus TETHER_PROJECT_ID in ignored root .env.");
  } else {
    console.log("Copy this key now into the server-only TETHER_KEY setting; it is shown once:");
    console.log(apiKey);
  }
}

async function canWriteLicenseKey(envPath, targetProjectId) {
  let content = "";
  try {
    content = await readFile(envPath, "utf8");
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  const currentKey = envValue(content, "TETHER_KEY");
  const currentProject = envValue(content, "TETHER_PROJECT_ID");
  return currentKey.length === 0 && (currentProject.length === 0 || currentProject === targetProjectId);
}

async function writeLicenseEnv(envPath, apiKey, targetProjectId) {
  let content = "";
  try {
    content = await readFile(envPath, "utf8");
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  content = setEnvValue(content, "TETHER_KEY", apiKey);
  content = setEnvValue(content, "TETHER_PROJECT_ID", targetProjectId);
  await writeFile(envPath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
}

function envValue(content, key) {
  const line = content.split(/\r?\n/u).find((entry) => entry.startsWith(`${key}=`));
  return line === undefined ? "" : line.slice(key.length + 1).trim();
}

function setEnvValue(content, key, value) {
  const lines = content.split(/\r?\n/u);
  const matching = lines.findIndex((entry) => entry.startsWith(`${key}=`));
  if (matching < 0) lines.push(`${key}=${value}`);
  else lines[matching] = `${key}=${value}`;
  const selected = lines.findIndex((entry) => entry.startsWith(`${key}=`));
  return lines.filter((entry, index) => !entry.startsWith(`${key}=`) || index === selected).join("\n");
}

function isMissing(error) {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function isUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}
