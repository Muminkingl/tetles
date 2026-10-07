import { ingestTetherEvents } from "@/lib/server/event-ingestion";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  try {
    return await ingestTetherEvents(request);
  } catch {
    return Response.json({ error: "INGEST_UNAVAILABLE" }, {
      status: 503,
      headers: { "cache-control": "no-store" },
    });
  }
}
