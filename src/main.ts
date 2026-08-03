/**
 * MCP Server - Main Entry Point
 *
 * This file serves as the entry point for the MCP Server Actor.
 * It sets up a proxy server that forwards requests to the locally running
 * MCP server, which provides a Model Context Protocol (MCP) interface.
 */

// Apify SDK - toolkit for building Apify Actors (Read more at https://docs.apify.com/sdk/js/)
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Actor, log } from 'apify';

import { startServer } from './server.js';

// This is an ESM project, and as such, it requires you to specify extensions in your relative imports
// Read more about this here: https://nodejs.org/docs/latest-v18.x/api/esm.html#mandatory-file-extensions
// Note that we need to use `.js` even when inside TS files
// import { router } from './routes.js';

// Configuration constants for the MCP server
// Command to run our existing pkg-health-actor stdio MCP server (checkPackageHealth.js wrapped as-is).
// The files live under ./pkg-health (copied unchanged, see pkg-health/package.json for why).
const currentDirname = path.dirname(fileURLToPath(import.meta.url));
const MCP_SERVER_ENTRYPOINT = path.join(currentDirname, '..', 'pkg-health', 'mcpServer.js');
const MCP_COMMAND = [process.execPath, MCP_SERVER_ENTRYPOINT];

// Check if the Actor is running in standby mode
const STANDBY_MODE = process.env.APIFY_META_ORIGIN === 'STANDBY';
const SERVER_PORT = parseInt(process.env.ACTOR_WEB_SERVER_PORT || '3001', 10);

// Initialize the Apify Actor environment
// The init() call configures the Actor to correctly work with the Apify-provided environment - mainly the storage infrastructure. It is necessary that every Actor performs an init() call.
await Actor.init();

// Billing is per-tool (check-package-health / check-vulnerabilities / check-dependency-tree),
// charged from inside the proxied MCP server (see pkg-health/mcpServer.js). No flat actor-start fee.

if (!STANDBY_MODE) {
    // If the Actor is not in standby mode, we should not run the MCP server
    const msg = 'This Actor is not meant to be run directly. It should be run in standby mode.';
    log.error(msg);
    await Actor.exit({ statusMessage: msg });
}

await startServer({
    serverPort: SERVER_PORT,
    command: MCP_COMMAND,
});
