export type Primitive = string | number | boolean | null | undefined;

export interface DeserializeOptions {
  readonly dateKeys?: readonly string[];
}

export interface OpenApiTransformOptions {
  readonly snakeCaseDateKeys?: readonly string[];
  readonly deep?: boolean;
}

type SnakeToCamelCase<S extends string> = S extends `${infer Head}_${infer Tail}`
  ? `${Head}${Capitalize<SnakeToCamelCase<Tail>>}`
  : S extends `${infer Head}-${infer Tail}`
    ? `${Head}${Capitalize<SnakeToCamelCase<Tail>>}`
    : S;

type CamelizeKey<K> = K extends string ? SnakeToCamelCase<K> : K;

type CamelizeArray<T> = T extends ReadonlyArray<infer U>
  ? ReadonlyArray<Camelize<U>>
  : T extends Array<infer U>
    ? Camelize<U>[]
    : T;

type CamelizeObject<T> = T extends Record<string, unknown>
  ? { [K in keyof T as CamelizeKey<K>]: Camelize<T[K]> }
  : T;

export type Camelize<T> = T extends Date
  ? T
  : T extends Function
    ? T
    : T extends Array<unknown> | ReadonlyArray<unknown>
      ? CamelizeArray<T>
      : T extends Record<string, unknown>
        ? CamelizeObject<T>
        : T;

/**
 * Parse an ISO-8601 timestamp into a {@link Date} instance while handling nullish values.
 */
export function parseDate(value: string | Date | null | undefined): Date | null {
  if (value == null) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/**
 * Parse an ISO-8601 timestamp into a {@link Date} or undefined.
 */
export function parseOptionalDate(value: string | Date | null | undefined): Date | undefined {
  const parsed = parseDate(value);
  return parsed === null ? undefined : parsed;
}

/**
 * Deserialize a payload into a rich object with dates converted from strings.
 * Only keys provided in {@link DeserializeOptions.dateKeys} will be coerced.
 */
export function deserialize<TRecord extends object>(
  payload: TRecord,
  options: DeserializeOptions = {},
): TRecord {
  if (!options.dateKeys || options.dateKeys.length === 0) {
    return payload;
  }

  const target = payload as Record<string, unknown>;

  for (const key of options.dateKeys) {
    if (Object.prototype.hasOwnProperty.call(target, key)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      target[key] = parseDate(target[key] as string | Date | null | undefined);
    }
  }

  return payload;
}

/**
 * Apply a mapper to every item in an array while preserving typing.
 */
export function mapArray<TInput, TOutput>(collection: readonly TInput[], mapper: (item: TInput) => TOutput): TOutput[] {
  return collection.map((item) => mapper(item));
}

/**
 * Convert a plain object with snake_case keys into camelCase keys recursively.
 * Only top-level keys are transformed by default; nested objects can be toggled.
 */
export function camelizeKeys<T extends object>(
  payload: T,
  options: { deep?: boolean } = {},
): Record<string, unknown> {
  const source = payload as Record<string, unknown>;
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(source)) {
    const targetKey = camelCase(key);
    if (options.deep && isPlainRecord(value)) {
      result[targetKey] = camelizeKeys(value, options);
    } else if (options.deep && Array.isArray(value)) {
      result[targetKey] = value.map((item) => (isPlainRecord(item) ? camelizeKeys(item, options) : item));
    } else {
      result[targetKey] = value;
    }
  }

  return result;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && (value.constructor === Object || Object.getPrototypeOf(value) === null);
}

function camelCase(input: string): string {
  return input.replace(/[_-](\w)/g, (_, char: string) => char.toUpperCase());
}

export function transformOpenApi<TPayload extends Record<string, unknown>, TResult>(
  payload: TPayload,
  projector: (record: Camelize<TPayload>) => TResult,
  options: OpenApiTransformOptions = {},
): TResult {
  const base = { ...(payload as Record<string, unknown>) };
  if (options.snakeCaseDateKeys?.length) {
    for (const key of options.snakeCaseDateKeys) {
      if (Object.prototype.hasOwnProperty.call(base, key)) {
        const value = base[key];
        base[key] = parseDate(value as string | Date | null | undefined);
      }
    }
  }

  const camel = camelizeKeys(base, { deep: options.deep }) as Camelize<TPayload>;
  return projector(camel);
}

export function transformOpenApiArray<TPayload extends Record<string, unknown>, TResult>(
  payload: readonly TPayload[],
  projector: (record: Camelize<TPayload>) => TResult,
  options: OpenApiTransformOptions = {},
): TResult[] {
  return payload.map((item) => transformOpenApi<TPayload, TResult>(item, projector, options));
}
