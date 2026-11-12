// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Whether this server installs the Nano payment lifecycle runner.
 *
 * The lifecycle code ships in this release so it can be reviewed and attacked. Real publishing is
 * not activated. While this is false the server never starts the runner, whatever the environment
 * says. A valid POST /api/v1/wallets/send is then refused before anything is reserved: 403 while
 * the operator send switch is off or the pause is on, 503 otherwise. A request that fails
 * authentication or lacks its Idempotency-Key is refused earlier with 401 or 400. The one `process`
 * call in nano-publish.ts is never reached from this server.
 *
 * Activation is a reviewed source change here, not a configuration switch.
 */
export const NANO_LIFECYCLE_ACTIVATED: boolean = false
