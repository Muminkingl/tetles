import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const workspace = process.cwd();
const envPath = resolve(workspace, ".env");
const publicModulePath = resolve(workspace, "packages/core/src/license-public-keys.ts");
let envText = "";
try {
  envText = await readFile(envPath, "utf8");
} catch (error) {
  if (!isMissing(error)) throw error;
}

let existingPublicModule;
try {
  existingPublicModule = await readFile(publicModulePath, "utf8");
} catch (error) {
  if (!isMissing(error)) throw error;
}

let privateJwk = readJsonJwk(envText, "TETHER_LICENSE_SIGNING_PRIVATE_JWK_B64");
if (privateJwk === undefined) {
  if (existingPublicModule !== undefined) {
    throw new Error("A public license key already exists but its matching private key is absent. Restore the server secret; do not generate a replacement.");
  }
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  privateJwk = normalizePrivateJwk(privateKey.export({ format: "jwk" }));
  envText = upsertEnv(
    envText,
    "TETHER_LICENSE_SIGNING_PRIVATE_JWK_B64",
    Buffer.from(JSON.stringify(privateJwk), "utf8").toString("base64url"),
  );
}

const kid = readEnv(envText, "TETHER_LICENSE_SIGNING_KID") || `lic-${randomBytes(6).toString("hex")}`;
envText = upsertEnv(envText, "TETHER_LICENSE_SIGNING_KID", kid);
const publicJwk = {
  kty: "EC",
  crv: "P-256",
  x: privateJwk.x,
  y: privateJwk.y,
  kid,
  alg: "ES256",
  use: "sig",
  key_ops: ["verify"],
};

await writeFile(envPath, envText.endsWith("\n") ? envText : `${envText}\n`, "utf8");
await writeFile(
  publicModulePath,
  `import type { JSONWebKeySet } from "jose";\n\n` +
    `/** Generated from the matching server-only signing key. Public material only. */\n` +
    `export const LICENSE_SIGNING_JWKS = ${JSON.stringify({ keys: [publicJwk] })} satisfies JSONWebKeySet;\n`,
  "utf8",
);
process.stdout.write(`License signing key ready (${kid}). The private key remains in ignored .env.\n`);

function readEnv(text, key) {
  const line = text.split(/\r?\n/u).find((entry) => entry.startsWith(`${key}=`));
  if (line === undefined) return "";
  return unwrap(line.slice(key.length + 1).trim());
}

function readJsonJwk(text, key) {
  const encoded = readEnv(text, key);
  if (encoded.length === 0) return undefined;
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error(`${key} is set but is not a base64url-encoded JSON key.`);
  }
  return normalizePrivateJwk(parsed);
}

function normalizePrivateJwk(value) {
  if (
    typeof value !== "object" || value === null || value.kty !== "EC" ||
    value.crv !== "P-256" || typeof value.x !== "string" ||
    typeof value.y !== "string" || typeof value.d !== "string"
  ) {
    throw new Error("Configured Tether license key must be an ES256 P-256 private JWK.");
  }
  return { kty: "EC", crv: "P-256", x: value.x, y: value.y, d: value.d };
}

function upsertEnv(text, key, value) {
  const lines = text.split(/\r?\n/u);
  const matching = lines.findIndex((entry) => entry.startsWith(`${key}=`));
  if (matching < 0) lines.push(`${key}=${value}`);
  else lines[matching] = `${key}=${value}`;
  return lines.filter((entry, index) => !entry.startsWith(`${key}=`) || index === lines.indexOf(`${key}=${value}`)).join("\n");
}

function unwrap(value) {
  if (value.length >= 2 && value[0] === value.at(-1) && (value[0] === "'" || value[0] === '"')) {
    return value.slice(1, -1);
  }
  return value;
}

function isMissing(error) {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
