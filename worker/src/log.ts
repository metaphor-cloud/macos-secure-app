import { createLogger, serializeError, type LogData, type LogLevel } from "@secure-app/shared/logger";

export const WORKER_NAME = "secure-app";

export const logger = createLogger({ worker: WORKER_NAME });

/** One structured line: log("warn", "request refused", { reason }). */
export function log(level: LogLevel, message: string, data: LogData = {}): void {
  logger[level](message, data);
}

export { serializeError };
