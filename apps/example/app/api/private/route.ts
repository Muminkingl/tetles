import { tether } from "@/lib/tether";

export const runtime = "nodejs";

export const GET = tether.protect(async (_request, context) => !context.licensed
  ? Response.json({
    message: "This route ran without Tether protection because no acceptable production license is available.",
    protected: false,
    reasonCode: context.reasonCode,
  })
  : Response.json({
    message: "The Supabase session and ES256 proof both verified.",
    protected: true,
    userId: context.userId,
    proofId: context.proofId,
  }));
