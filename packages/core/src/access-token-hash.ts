/** SHA-256 over the ASCII access-token value, encoded as unpadded base64url. */
export async function computeAccessTokenHash(accessToken: string): Promise<string> {
  if (!/^[\x00-\x7F]*$/u.test(accessToken)) {
    throw new TypeError("An access token must contain only ASCII characters");
  }
  const bytes = new TextEncoder().encode(accessToken);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return encodeBase64Url(new Uint8Array(digest));
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
