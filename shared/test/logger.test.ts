import { describe, expect, it, vi } from "vitest";
import { createLogger, serializeError } from "../src/logger.ts";

function sink() {
  return { debug: vi.fn(), log: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

describe("createLogger", () => {
  it("logs one object with level, message and ambient context at the top and the payload under data", () => {
    const out = sink();
    createLogger({ worker: "api", environment: "test" }, out).info("import chunk done", { done: true, phase: "embed" });
    expect(out.log).toHaveBeenCalledWith({ level: "info", message: "import chunk done", worker: "api", environment: "test", data: { done: true, phase: "embed" } });
  });

  it("uses the console method that matches the level", () => {
    const out = sink();
    const logger = createLogger({ worker: "api" }, out);
    logger.debug("d");
    logger.info("i");
    logger.warn("w");
    logger.error("e");
    expect(out.debug.mock.calls[0][0]).toMatchObject({ level: "debug" });
    expect(out.log.mock.calls[0][0]).toMatchObject({ level: "info" });
    expect(out.warn.mock.calls[0][0]).toMatchObject({ level: "warn" });
    expect(out.error.mock.calls[0][0]).toMatchObject({ level: "error" });
  });

  it("passes an object, never a string", () => {
    const out = sink();
    createLogger({ worker: "api" }, out).warn("refused", { reason: "x" });
    expect(typeof out.warn.mock.calls[0][0]).toBe("object");
    expect(out.warn.mock.calls[0]).toHaveLength(1);
  });

  it("binds more context with child, without changing the parent", () => {
    const out = sink();
    const parent = createLogger({ worker: "api" }, out);
    parent.child({ requestId: "r1" }).info("a");
    parent.info("b");
    expect(out.log.mock.calls[0][0]).toMatchObject({ worker: "api", requestId: "r1" });
    expect(out.log.mock.calls[1][0]).not.toHaveProperty("requestId");
  });

  it("defaults data to an empty object", () => {
    const out = sink();
    createLogger({ worker: "api" }, out).info("started");
    expect(out.log.mock.calls[0][0].data).toEqual({});
  });
});

describe("serializeError", () => {
  it("keeps the name, message and stack of an Error, and stringifies anything else", () => {
    const error = new TypeError("boom");
    expect(serializeError(error)).toEqual({ name: "TypeError", message: "boom", stack: error.stack });
    expect(JSON.stringify(serializeError(error))).toContain("boom");
    expect(serializeError("plain")).toBe("plain");
  });
});
