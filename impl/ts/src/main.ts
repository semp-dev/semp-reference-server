/**
 * semp-server entry point. Mirrors impl/go/cmd/semp-server/main.go.
 *
 * @module
 */

import { parseArgs } from "node:util";

import pino from "pino";

import { loadConfig } from "./config/config.js";
import { newServer } from "./server/index.js";

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      config: { type: "string", default: "semp.toml" },
    },
    strict: false,
  });
  const configPath =
    typeof values.config === "string" ? values.config : "semp.toml";

  let cfg;
  try {
    cfg = loadConfig(configPath);
  } catch (err) {
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }

  const level = ["debug", "info", "warn", "error"].includes(cfg.logging.level)
    ? cfg.logging.level
    : "info";
  const logger =
    cfg.logging.format === "json"
      ? pino({ level }, pino.destination(2))
      : pino(
          {
            level,
            transport: {
              target: "pino-pretty",
              options: { destination: 2, colorize: true },
            },
          },
        );

  let server;
  try {
    server = await newServer(cfg, logger);
  } catch (err) {
    logger.error(
      { err: err instanceof Error ? err.message : String(err) },
      "failed to create server",
    );
    process.exit(1);
  }

  const shutdown = async (): Promise<void> => {
    logger.info("shutting down");
    try {
      await server.close();
    } catch (err) {
      logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        "error during shutdown",
      );
    }
    logger.info("server stopped");
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());

  try {
    await server.start();
  } catch (err) {
    logger.error(
      { err: err instanceof Error ? err.message : String(err) },
      "server exited with error",
    );
    process.exit(1);
  }
}

void main();
