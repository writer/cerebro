export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

const levelOrder: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};

interface LoggingConfig {
  level: LogLevel;
  jsonOutput: boolean;
  sink?: LogSink;
}

export interface LogEntry {
  name: string;
  level: LogLevel;
  message: unknown[];
  timestamp: Date;
  jsonOutput: boolean;
}

export interface Logger {
  trace(...args: unknown[]): void;
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  fatal(...args: unknown[]): void;
}

const defaultSink = (entry: LogEntry): void => {
  const payload = entry.jsonOutput
    ? JSON.stringify({
        name: entry.name,
        level: entry.level,
        timestamp: entry.timestamp.toISOString(),
        message: entry.message,
      })
    : `${entry.timestamp.toISOString()} [${entry.level}] ${entry.name}: ${entry.message
        .map((item) => (typeof item === "string" ? item : JSON.stringify(item)))
        .join(" ")}`;

  switch (entry.level) {
    case "trace":
    case "debug":
      console.debug(payload);
      break;
    case "info":
      console.info(payload);
      break;
    case "warn":
      console.warn(payload);
      break;
    default:
      console.error(payload);
      break;
  }
};

let loggingConfig: LoggingConfig & { jsonOutput: boolean } = {
  level: "info",
  jsonOutput: false,
  sink: defaultSink,
};

export type LogSink = (entry: LogEntry) => void;

export function configureLogging(
  level?: LogLevel,
  options: { jsonOutput?: boolean; sink?: LogSink } = {},
): void {
  if (level) {
    loggingConfig.level = level;
  }
  if (typeof options.jsonOutput === "boolean") {
    loggingConfig.jsonOutput = options.jsonOutput;
  }
  if (options.sink) {
    loggingConfig.sink = options.sink;
  }
}

export function getLogger(name: string): Logger {
  const log = (level: LogLevel, values: unknown[]): void => {
    if (levelOrder[level] < levelOrder[loggingConfig.level]) {
      return;
    }

    const entry: LogEntry = {
      name,
      level,
      message: values,
      timestamp: new Date(),
      jsonOutput: loggingConfig.jsonOutput,
    };

    (loggingConfig.sink ?? defaultSink)(entry);
  };

  const logger: Logger = {
    trace: (...args: unknown[]) => log("trace", args),
    debug: (...args: unknown[]) => log("debug", args),
    info: (...args: unknown[]) => log("info", args),
    warn: (...args: unknown[]) => log("warn", args),
    error: (...args: unknown[]) => log("error", args),
    fatal: (...args: unknown[]) => log("fatal", args),
  };

  return logger;
}

type Labels = Record<string, string>;

function serialiseLabels(labels: Labels | undefined): string {
  if (!labels) {
    return "";
  }

  const entries = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
  return entries.map(([key, value]) => `${key}=${value}`).join("|");
}

export class Counter {
  private readonly labelNames: string[];
  private readonly values = new Map<string, number>();

  constructor(
    public readonly name: string,
    public readonly help: string,
    options: { labelNames?: string[] } = {},
  ) {
    this.labelNames = options.labelNames ?? [];
  }

  inc(labels?: Labels, value = 1): number {
    if (value < 0) {
      throw new Error("Counter cannot be decreased");
    }
    const key = serialiseLabels(labels);
    const current = this.values.get(key) ?? 0;
    const next = current + value;
    this.values.set(key, next);
    return next;
  }

  get(labels?: Labels): number {
    return this.values.get(serialiseLabels(labels)) ?? 0;
  }

  reset(labels?: Labels): void {
    if (labels) {
      this.values.delete(serialiseLabels(labels));
      return;
    }
    this.values.clear();
  }
}

export class Histogram {
  private readonly labelNames: string[];
  private readonly buckets: number[];
  private readonly samples = new Map<string, number[]>();

  constructor(
    public readonly name: string,
    public readonly help: string,
    options: { labelNames?: string[]; buckets?: number[] } = {},
  ) {
    this.labelNames = options.labelNames ?? [];
    this.buckets = options.buckets ?? [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
  }

  observe(value: number, labels?: Labels): void {
    const key = serialiseLabels(labels);
    const current = this.samples.get(key) ?? [];
    current.push(value);
    this.samples.set(key, current);
  }

  getBuckets(labels?: Labels): Array<{ upperBound: number; count: number }> {
    const key = serialiseLabels(labels);
    const values = this.samples.get(key) ?? [];
    return this.buckets.map((upperBound) => ({
      upperBound,
      count: values.filter((sample) => sample <= upperBound).length,
    }));
  }

  startTimer(labels?: Labels): () => number {
    const now = typeof performance !== "undefined" && typeof performance.now === "function"
      ? () => performance.now()
      : () => Date.now();
    const start = now();
    return () => {
      const delta = (now() - start) / 1000;
      this.observe(delta, labels);
      return delta;
    };
  }
}

export function createCounter(
  name: string,
  documentation: string,
  options: { labelNames?: string[] } = {},
): Counter {
  return new Counter(name, documentation, options);
}

export function createHistogram(
  name: string,
  documentation: string,
  options: { labelNames?: string[]; buckets?: number[] } = {},
): Histogram {
  return new Histogram(name, documentation, options);
}

export function timeOperation(histogram: Histogram, labels?: Labels): () => number {
  return histogram.startTimer(labels);
}
