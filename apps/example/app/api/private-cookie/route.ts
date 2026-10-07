import { tether } from "@/lib/tether";

export const runtime = "nodejs";

export const GET = tether.protectCookie(async (_request, session) => !session.licensed
  ? Response.json({
    message: "This route ran without Tether protection because no acceptable production license is available.",
    protected: false,
    reasonCode: session.reasonCode,
  })
  : Response.json({
    message: "The short-lived HttpOnly Tether cookie verified.",
    protected: true,
    userId: session.userId,
    expiresAt: session.expiresAt,
  }));
