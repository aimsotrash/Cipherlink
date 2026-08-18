/**
 * Server entry point.
 */
import { createLogger } from '@p2pchat/shared';
import { buildServer } from './app.js';
import { loadConfig } from './config.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger('server', { level: config.logLevel });
  const { app } = await buildServer(config, logger);

  await app.listen({ host: config.host, port: config.port });
  logger.info('signaling and relay server listening', {
    host: config.host,
    port: config.port,
    databasePath: config.databasePath,
  });

  const shutdown = (signal: string): void => {
    logger.info('shutting down', { signal });
    void app.close().then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((error: unknown) => {
  // Startup failures print a name and message only; never a full object that
  // might carry configuration secrets.
  const name = error instanceof Error ? error.name : 'Error';
  const message = error instanceof Error ? error.message : 'failed to start';
  console.error(JSON.stringify({ level: 'error', msg: 'server failed to start', name, message }));
  process.exit(1);
});
