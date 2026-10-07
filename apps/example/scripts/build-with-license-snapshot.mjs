import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { config as loadDotEnv } from "dotenv";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const appDir = resolve(scriptDir, "..");
loadDotEnv({ path: resolve(appDir, "../../.env") });
const snapshotDir = resolve(appDir, ".tether");
const snapshotPath = resolve(snapshotDir, "license-snapshot.json");
const generatedModulePath = resolve(appDir, "lib/license-snapshot.generated.ts");
const args = process.argv.slice(2);
const build = args.includes("--build");
const pullOnly = args.includes("--pull-only");
const requestedEnvironment = args.includes("--production")
  ? "production"
  : args.includes("--development")
    ? "development"
    : undefined;

try {
  const environment = resolveEnvironment(requestedEnvironment, build);
  const snapshot = await pullSnapshot(environment);
  await mkdir(snapshotDir, { recursive: true });
  await writeFile(snapshotPath, `${JSON.stringify(snapshot)}\n`, "utf8");
  if (pullOnly) {
    process.stdout.write("Pulled and saved the signed Tether license snapshot in the ignored .tether directory.\n");
  } else if (build) {
    await buildWithSnapshot(snapshot);
  } else {
    throw new Error("Use --pull-only, --build, --production, or --development.");
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown license snapshot error.";
  process.stderr.write(`[Tether] License snapshot step failed: ${message}\n`);
  process.exitCode = 1;
}

function resolveEnvironment(override, forBuild) {
  const explicit = override || process.env.TETHER_ENV;
  if (explicit !== undefined && explicit !== "production" && explicit !== "development") {
    throw new Error("TETHER_ENV must be 'production' or 'development'.");
  }
  if (explicit !== undefined) return explicit;
  if (forBuild) return "production";
  return process.env.NODE_ENV === "development" ? "development" : "production";
}

async function pullSnapshot(environment) {
  const apiKey = process.env.TETHER_KEY;
  const projectId = process.env.TETHER_PROJECT_ID;
  const expectedPrefix = environment === "production" ? "tk_live_" : "tk_test_";
  if (apiKey === undefined || apiKey.length === 0) {
    throw new Error("TETHER_KEY is required to pull a license snapshot.");
  }
  if (!apiKey.startsWith(expectedPrefix)) {
    throw new Error(`The TETHER_KEY does not match ${environment}; expected a ${expectedPrefix} key.`);
  }
  if (projectId === undefined || projectId.length === 0) {
    throw new Error("TETHER_PROJECT_ID is required to pull a license snapshot.");
  }

  const issuer = process.env.TETHER_LICENSE_ISSUER ||
    (environment === "development" ? "http://localhost:3000" : undefined);
  if (issuer === undefined) throw new Error("TETHER_LICENSE_ISSUER is required in production.");
  const issuerUrl = new URL(issuer);
  if (
    issuerUrl.protocol !== "https:" &&
    !(environment === "development" && issuerUrl.protocol === "http:" && issuerUrl.hostname === "localhost")
  ) {
    throw new Error("TETHER_LICENSE_ISSUER must use HTTPS outside local development.");
  }

  const licenseEndpoint = process.env.TETHER_LICENSE_ENDPOINT || new URL("/v1/license", issuerUrl).href;
  const jwksEndpoint = process.env.TETHER_JWKS_ENDPOINT || new URL("/v1/jwks", issuerUrl).href;
  validateEndpoint(licenseEndpoint, "TETHER_LICENSE_ENDPOINT", environment);
  validateEndpoint(jwksEndpoint, "TETHER_JWKS_ENDPOINT", environment);
  const licenseResponse = await fetch(licenseEndpoint, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({ env: environment }),
    cache: "no-store",
  });
  if (!licenseResponse.ok) {
    throw new Error(`License endpoint returned HTTP ${licenseResponse.status}.`);
  }
  const licenseBody = await licenseResponse.json();
  if (
    typeof licenseBody !== "object" || licenseBody === null ||
    typeof licenseBody.token !== "string" || licenseBody.token.length === 0 ||
    licenseBody.token.length > 16_384
  ) {
    throw new Error("License endpoint returned an invalid token response.");
  }

  const jwksResponse = await fetch(jwksEndpoint, {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  if (!jwksResponse.ok) throw new Error(`JWKS endpoint returned HTTP ${jwksResponse.status}.`);
  const jwks = await jwksResponse.json();
  if (
    typeof jwks !== "object" || jwks === null || !Array.isArray(jwks.keys) ||
    jwks.keys.length === 0 || jwks.keys.length > 32 ||
    jwks.keys.some((key) => typeof key !== "object" || key === null || Object.hasOwn(key, "d"))
  ) {
    throw new Error("JWKS endpoint returned an invalid or private key set.");
  }
  return { token: licenseBody.token, jwks };
}

function validateEndpoint(value, name, environment) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" &&
    !(environment === "development" && url.protocol === "http:" && url.hostname === "localhost")
  ) {
    throw new Error(`${name} must use HTTPS outside local development.`);
  }
}

async function buildWithSnapshot(snapshot) {
  const originalModule = await readFile(generatedModulePath, "utf8");
  const generatedModule = [
    'import type { TetherLicenseSnapshot } from "@tether/next";',
    `export const tetherLicenseSnapshot: TetherLicenseSnapshot = ${JSON.stringify(snapshot)};`,
    "",
  ].join("\n");
  let buildExitCode = 1;
  try {
    await writeFile(generatedModulePath, generatedModule, "utf8");
    buildExitCode = await runNextBuild();
  } finally {
    // Keep the signed snapshot in the compiled server output, never in the source checkout.
    await writeFile(generatedModulePath, originalModule, "utf8");
  }
  if (buildExitCode !== 0) process.exitCode = buildExitCode;
}

function runNextBuild() {
  return new Promise((resolveBuild, rejectBuild) => {
    const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
    const child = spawn(command, ["exec", "next", "build"], {
      cwd: appDir,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    child.once("error", rejectBuild);
    child.once("exit", (code, signal) => {
      if (signal !== null) return rejectBuild(new Error(`Next.js build ended on signal ${signal}.`));
      resolveBuild(code ?? 1);
    });
  });
}
