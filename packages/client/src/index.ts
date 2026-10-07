export { createTetherClient } from "./client.js";
export type { TetherClient, TetherClientOptions, TetherSession } from "./client.js";
export { createProof } from "./proof.js";
export type { CreateProofInput } from "./proof.js";
export { RELOGIN_REQUIRED_EVENT, TetherClientError } from "./errors.js";
export type { TetherClientErrorCode } from "./errors.js";
export { IndexedDbKeyStore } from "./key-store.js";
export type { DeviceKeyRecord, DeviceKeyStore } from "./key-store.js";
