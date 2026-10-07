import { tether } from "@/lib/tether";

export const runtime = "nodejs";

export function POST(request: Request): Promise<Response> {
  return tether.refreshCookie(request);
}

export function DELETE(request: Request): Promise<Response> {
  return tether.clearCookie(request);
}
