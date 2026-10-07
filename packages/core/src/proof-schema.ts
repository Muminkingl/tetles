import { z } from "zod";

export const publicP256JwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().min(1),
    y: z.string().min(1),
  })
  .strip();

export const proofClaimsSchema = z.object({
  htm: z.string().min(1),
  htu: z.string().min(1),
  iat: z.number().int().nonnegative(),
  jti: z.string().min(16).max(128),
  ath: z.string().min(1),
  nonce: z.string().min(1).optional(),
});

export type PublicP256Jwk = z.infer<typeof publicP256JwkSchema>;
export type ProofClaims = z.infer<typeof proofClaimsSchema>;
