export type Result<Value, Error> =
  { readonly ok: true; readonly value: Value } | { readonly ok: false; readonly error: Error };

export const ok = <Value>(value: Value): Result<Value, never> => ({ ok: true, value });

export const err = <Error>(error: Error): Result<never, Error> => ({ ok: false, error });
