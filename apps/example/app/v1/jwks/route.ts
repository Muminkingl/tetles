import { serveLicenseJwks } from "@/lib/server/license-service";

export const runtime = "nodejs";

export function GET(): Promise<Response> {
  return serveLicenseJwks();
}
