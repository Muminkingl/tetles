import { tether } from "@/lib/tether";

export const runtime = "nodejs";

export function POST(request: Request): Promise<Response> {
  return tether.bind(request);
}
