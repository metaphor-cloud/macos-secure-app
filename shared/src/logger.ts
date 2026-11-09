/**
 * Structured logging for Cloudflare Workers. Workers Logs indexes the fields
 * of a logged object, not the text inside a stringified one, so every line is
 * a plain object with a top-level `level` and `message`, never a string.
 *
 *   const logger = createLogger({ worker: "api" });
 *   logger.info("import chunk done", { phase: "embed" });
 *   // console.log({ level: "info", message: "import chunk done", worker: "api", data: { phase: "embed" } })
 *
 * The console method matches the level, so the dashboard's level detection
 * agrees with the field. Bind ambient context (worker, environment, request
 * or job id) once with createLogger or logger.child.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogData = Record<string, unknown>;

export interface Logger {
  debug(message: string, data?: LogData): void;
  info(message: string, data?: LogData): void;
  warn(message: string, data?: LogData): void;
  error(message: string, data?: LogData): void;
  /** The same logger with more ambient context on every line. */
  child(context: Record<string, unknown>): Logger;
}

export type LogSink = Pick<Console, "debug" | "log" | "warn" | "error">;

export function createLogger(ambient: { worker: string } & Record<string, unknown>, sink?: LogSink): Logger {
  const emit = (level: LogLevel, message: string, data: LogData = {}) => {
    // The console is read at call time, so a test that spies on it sees the line.
    const out = sink ?? console;
    const line = { level, message, ...ambient, data };
    if (level === "error") out.error(line);
    else if (level === "warn") out.warn(line);
    else if (level === "debug") out.debug(line);
    else out.log(line);
  };
  return {
    debug: (message, data) => emit("debug", message, data),
    info: (message, data) => emit("info", message, data),
    warn: (message, data) => emit("warn", message, data),
    error: (message, data) => emit("error", message, data),
    child: (context) => createLogger({ ...ambient, ...context }, sink),
  };
}

/**
 * An unknown catch value, reduced to a JSON-safe shape. `Error.stack` does not
 * survive JSON encoding on its own, so log errors through this.
 */
export function serializeError(error: unknown): { name: string; message: string; stack?: string } | string {
  return error instanceof Error ? { name: error.name, message: error.message, stack: error.stack } : String(error);
}
