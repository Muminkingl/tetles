import { issueLicense } from "@/lib/server/license-service";

export const runtime = "nodejs";

export function POST(request: Request): Promise<Response> {
  return issueLicense(request);
}
