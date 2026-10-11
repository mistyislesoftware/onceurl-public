import type {
  CapabilityObjectStorage,
  CapabilityObjectTransaction
} from "../capability-durable-object-core";

export type TransactionFault =
  | { readonly phase: "before_transaction" }
  | { readonly phase: "mutation"; readonly mutation: number }
  | { readonly phase: "after_commit" };

export interface CapabilityStorageSnapshot {
  readonly values: ReadonlyMap<string, unknown>;
  readonly alarm: number | null;
}

/**
 * A rollback-capable, serialized storage seam for deterministic fault campaigns.
 * It models transaction commit/rollback, not Cloudflare's SQLite implementation.
 * Runtime tests remain responsible for proving the platform-backed boundary.
 */
export class TransactionalCapabilityStorage implements CapabilityObjectStorage {
  private values = new Map<string, unknown>();
  private alarm: number | null = null;
  private lock: Promise<void> = Promise.resolve();
  private nextFault: TransactionFault | null = null;

  get<T = unknown>(key: string): Promise<T | undefined> {
    return Promise.resolve(clone(this.values.get(key) as T | undefined));
  }

  put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, clone(value));
    return Promise.resolve();
  }

  delete(key: string): Promise<boolean> {
    return Promise.resolve(this.values.delete(key));
  }

  getAlarm(): Promise<number | null> {
    return Promise.resolve(this.alarm);
  }

  setAlarm(scheduledTime: number): Promise<void> {
    this.alarm = scheduledTime;
    return Promise.resolve();
  }

  deleteAlarm(): Promise<void> {
    this.alarm = null;
    return Promise.resolve();
  }

  list<T = unknown>(options?: { readonly prefix?: string }): Promise<Map<string, T>> {
    return Promise.resolve(selectValues<T>(this.values, options?.prefix));
  }

  async transaction<T>(closure: (txn: CapabilityObjectTransaction) => Promise<T>): Promise<T> {
    const previous = this.lock;
    let release!: () => void;
    this.lock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;

    const fault = this.nextFault;
    this.nextFault = null;
    try {
      if (fault?.phase === "before_transaction") throw injectedFault(fault);

      const values = cloneMap(this.values);
      let alarm = this.alarm;
      let mutation = 0;
      const mutate = () => {
        mutation += 1;
        if (fault?.phase === "mutation" && fault.mutation === mutation) {
          throw injectedFault(fault);
        }
      };
      const transaction: CapabilityObjectTransaction = {
        get<Value = unknown>(key: string): Promise<Value | undefined> {
          return Promise.resolve(clone(values.get(key) as Value | undefined));
        },
        put<Value>(key: string, value: Value): Promise<void> {
          mutate();
          values.set(key, clone(value));
          return Promise.resolve();
        },
        delete(key: string): Promise<boolean> {
          mutate();
          return Promise.resolve(values.delete(key));
        },
        list<Value = unknown>(options?: { readonly prefix?: string }): Promise<Map<string, Value>> {
          return Promise.resolve(selectValues<Value>(values, options?.prefix));
        },
        getAlarm(): Promise<number | null> {
          return Promise.resolve(alarm);
        },
        setAlarm(scheduledTime: number): Promise<void> {
          mutate();
          alarm = scheduledTime;
          return Promise.resolve();
        },
        deleteAlarm(): Promise<void> {
          mutate();
          alarm = null;
          return Promise.resolve();
        }
      };

      const result = await closure(transaction);
      this.values = values;
      this.alarm = alarm;
      if (fault?.phase === "after_commit") throw injectedFault(fault);
      return result;
    } finally {
      release();
    }
  }

  failNextTransaction(fault: TransactionFault): void {
    if (
      fault.phase === "mutation" &&
      (!Number.isSafeInteger(fault.mutation) || fault.mutation < 1)
    ) {
      throw new Error("A mutation fault must identify a positive mutation number");
    }
    if (this.nextFault !== null) throw new Error("A transaction fault is already armed");
    this.nextFault = fault;
  }

  snapshot(): CapabilityStorageSnapshot {
    return { values: cloneMap(this.values), alarm: this.alarm };
  }

  restore(snapshot: CapabilityStorageSnapshot): void {
    this.values = cloneMap(snapshot.values);
    this.alarm = snapshot.alarm;
    this.nextFault = null;
  }

  entries(): Record<string, unknown> {
    return Object.fromEntries(cloneMap(this.values));
  }
}

function selectValues<T>(values: ReadonlyMap<string, unknown>, prefix?: string): Map<string, T> {
  return new Map(
    [...values.entries()]
      .filter(([key]) => prefix === undefined || key.startsWith(prefix))
      .map(([key, value]) => [key, clone(value) as T])
  );
}

function cloneMap(values: ReadonlyMap<string, unknown>): Map<string, unknown> {
  return new Map([...values.entries()].map(([key, value]) => [key, clone(value)]));
}

function clone<T>(value: T): T {
  return value === undefined ? value : structuredClone(value);
}

function injectedFault(fault: TransactionFault): Error {
  return new Error(
    fault.phase === "mutation"
      ? `injected transaction mutation ${fault.mutation}`
      : `injected ${fault.phase.replaceAll("_", " ")}`
  );
}
