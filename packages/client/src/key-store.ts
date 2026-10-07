import { TetherClientError } from "./errors.js";

export interface DeviceKeyRecord {
  readonly sessionId: string;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JsonWebKey;
}

export interface DeviceKeyStore {
  get(sessionId: string): Promise<DeviceKeyRecord | undefined>;
  put(record: DeviceKeyRecord): Promise<void>;
  putIfAbsent(record: DeviceKeyRecord): Promise<DeviceKeyRecord>;
  delete(sessionId: string): Promise<void>;
}

const DATABASE_NAME = "tether-device-keys";
const DATABASE_VERSION = 1;
const OBJECT_STORE = "sessions";

/** Stores non-extractable CryptoKey objects through IndexedDB structured cloning. */
export class IndexedDbKeyStore implements DeviceKeyStore {
  readonly #indexedDB: IDBFactory;
  #databasePromise: Promise<IDBDatabase> | undefined;

  constructor(indexedDBFactory: IDBFactory | undefined = globalThis.indexedDB) {
    if (indexedDBFactory === undefined) throw storageUnavailable();
    this.#indexedDB = indexedDBFactory;
  }

  async get(sessionId: string): Promise<DeviceKeyRecord | undefined> {
    const database = await this.#database();
    const transaction = database.transaction(OBJECT_STORE, "readonly");
    const completed = transactionDone(transaction);
    const request = requestResult<DeviceKeyRecord | undefined>(
      transaction.objectStore(OBJECT_STORE).get(sessionId),
    );
    try {
      const record = await request;
      await completed;
      return record;
    } catch {
      throw storageUnavailable();
    }
  }

  async put(record: DeviceKeyRecord): Promise<void> {
    const database = await this.#database();
    const transaction = database.transaction(OBJECT_STORE, "readwrite");
    const completed = transactionDone(transaction);
    try {
      await requestResult(transaction.objectStore(OBJECT_STORE).put(record));
      await completed;
    } catch {
      throw storageUnavailable();
    }
  }

  /** Atomically returns the existing session key or inserts this candidate. */
  async putIfAbsent(record: DeviceKeyRecord): Promise<DeviceKeyRecord> {
    const database = await this.#database();
    const transaction = database.transaction(OBJECT_STORE, "readwrite");
    const completed = transactionDone(transaction);
    let selected: DeviceKeyRecord | undefined;
    const selection = new Promise<void>((resolve, reject) => {
      const store = transaction.objectStore(OBJECT_STORE);
      const lookup = store.get(record.sessionId) as IDBRequest<DeviceKeyRecord | undefined>;
      lookup.onsuccess = () => {
        if (lookup.result !== undefined) {
          selected = lookup.result;
          resolve();
          return;
        }
        const insert = store.add(record);
        insert.onsuccess = () => {
          selected = record;
          resolve();
        };
        insert.onerror = () => reject(insert.error);
      };
      lookup.onerror = () => reject(lookup.error);
    });
    try {
      await selection;
      await completed;
      if (selected === undefined) throw storageUnavailable();
      return selected;
    } catch {
      await completed.catch(() => undefined);
      throw storageUnavailable();
    }
  }

  async delete(sessionId: string): Promise<void> {
    const database = await this.#database();
    const transaction = database.transaction(OBJECT_STORE, "readwrite");
    const completed = transactionDone(transaction);
    try {
      await requestResult(transaction.objectStore(OBJECT_STORE).delete(sessionId));
      await completed;
    } catch {
      throw storageUnavailable();
    }
  }

  #database(): Promise<IDBDatabase> {
    this.#databasePromise ??= new Promise<IDBDatabase>((resolve, reject) => {
      let request: IDBOpenDBRequest;
      try {
        request = this.#indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      } catch {
        reject(storageUnavailable());
        return;
      }

      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(OBJECT_STORE)) {
          database.createObjectStore(OBJECT_STORE, { keyPath: "sessionId" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(storageUnavailable());
      request.onblocked = () => reject(storageUnavailable());
    }).catch((error: unknown) => {
      this.#databasePromise = undefined;
      if (error instanceof TetherClientError) {
        throw error;
      }
      throw storageUnavailable();
    });
    return this.#databasePromise;
  }
}

function requestResult<T = undefined>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

function storageUnavailable(): TetherClientError {
  return new TetherClientError("KEY_STORAGE_UNAVAILABLE");
}
