export const RELOGIN_REQUIRED_EVENT = "tether:relogin-required";

export type TetherClientErrorCode =
  | "AUTH_SESSION_REQUIRED"
  | "KEY_STORAGE_UNAVAILABLE"
  | "KEY_MISSING"
  | "KEY_INVALID"
  | "CRYPTO_UNAVAILABLE"
  | "INVALID_ACCESS_TOKEN"
  | "REQUEST_ORIGIN_REJECTED"
  | "LOCKS_UNAVAILABLE";

const MESSAGES: Record<TetherClientErrorCode, string> = {
  AUTH_SESSION_REQUIRED: "Sign in before using a Tether-protected request.",
  KEY_STORAGE_UNAVAILABLE: "Secure browser key storage is unavailable.",
  KEY_MISSING: "The device key is missing. Sign in again to restore this session.",
  KEY_INVALID: "The stored device key is invalid. Sign in again to restore this session.",
  CRYPTO_UNAVAILABLE: "This browser does not provide the required secure cryptography.",
  INVALID_ACCESS_TOKEN: "The access token cannot be used to create a proof.",
  REQUEST_ORIGIN_REJECTED: "The request origin is not configured for Tether protection.",
  LOCKS_UNAVAILABLE: "This browser does not support the Web Locks API required for safe session coordination.",
};

export class TetherClientError extends Error {
  readonly code: TetherClientErrorCode;

  constructor(code: TetherClientErrorCode) {
    super(MESSAGES[code]);
    this.name = "TetherClientError";
    this.code = code;
  }
}
