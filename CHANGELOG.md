# Changelog

## Unreleased

**Nano payment lifecycle, not activated.** The source now contains a payment lifecycle for agent wallet sends. Each send is a durable operation that reserves budget on every delegation in its chain, signs one block and publishes it through a single call site. It counts as spent when the configured node reports that the operation's own block is confirmed, or when an operator resolves a conflict incident that way with evidence the operator supplies.

The server in this release does not activate it. `NANO_LIFECYCLE_ACTIVATED` in `src/payment-rails/nano-activation.ts` is false in source and is not read from the environment, so the server never installs the lifecycle runner. After authentication and the `Idempotency-Key` header check, `POST /api/v1/wallets/send` refuses every request with nothing reserved: 403 while the operator send switch is off or the pause is on, 503 otherwise. `GET /healthz/nano-lifecycle` reports `disabled`. The legacy publish paths stay closed. No environment or runtime configuration makes the server publish a Nano block. The lifecycle code itself can be run by the tests and by a standalone harness with a fake node, which is the point of shipping it.

What the lifecycle code does when a test or harness runs it:

- `POST /api/v1/wallets/send` requires an `Idempotency-Key` header. One key is one payment, and a retry returns the same operation. The answer is 202 with the operation, and `GET /api/v1/wallets/ops/:id` reports its state.
- A send is built only on an account state an operator recorded for that wallet. If the node reports a different frontier or balance, the send waits and nothing is signed.
- A payment that may have been published never releases its reservation automatically. A payment cancelled before any publish attempt releases its reservation.
- A different block on the same previous that carries a valid signature of the account is an incident. The wallet is frozen, the delegation chain is held, new sends stop, and only an operator resolution that matches the recorded incident ends it. A reported block that does not verify is a node fault and freezes nothing.
- Pilot caps (`NANO_PILOT_MAX_PAYMENT_RAW`, `NANO_PILOT_MAX_WALLET_RAW`, `NANO_PILOT_MAX_PAYMENTS`) must all be set, or every send is refused.

Known limits, stated on purpose:

- A confirmation is taken from the one configured node. If that node reports a false confirmation, the gateway can count the payment as spent, report it confirmed to the caller and stop publishing its block even when the recipient was not paid. The signed block still exists and the network can accept it if someone broadcasts it later. Later sends from that wallet stop until an operator acts.
- A reservation is never released by time. If a block is dropped or the node is unreachable, the amount stays held on every delegation in the chain until the block confirms or an operator resolves it.
- One faulty node stops new sends for every tenant.
- An operator resolution is checked against what the gateway recorded, but the gateway does not contact or authenticate the outside sources the operator names.
- None of this has had an independent security review.

**Upgrading.** Startup creates `wallet_ops`, `wallet_op_reservations`, `wallet_op_attempts` and `wallet_frontiers`, although the lifecycle is off. The refusal text for a send while `NANO_WALLET_SEND_ENABLED` is unset no longer says budgets are in USD. A new dependency, `@noble/hashes`, is pinned at 1.8.0.

## 0.5.0 (2026-11-11)

**BREAKING: Nano publishing is disabled.** Agent wallet sends, receives and settlement payouts now refuse to publish, even when their feature switches are enabled. These paths stop before deriving a private key or contacting a Nano node. If a send has already debited a delegation budget, the debit is reversed and the attempt is recorded as failed.

The previous opt-in send path had no durable payment record before publication. A crash or timeout could therefore leave a payment without a record the gateway could reconcile. Publishing remains disabled until a payment lifecycle with that record is available in the public gateway.

**Explicit spending units.** Delegations can now declare `spend_unit` as `iso4217:USD:minor` (cents) or `nano:XNO:raw`, with `spend_limit_minor` as a canonical decimal integer string. Amounts are calculated exactly, without currency conversion.

A child cannot take a different spending unit from its parent, exceed its parent's remaining budget or receive an unlimited budget from a limited parent. A unit-declared child is refused under a legacy parent with a bounded budget, because that budget's unit is unknown. A legacy grant is also refused under a unit-declared parent.

`spend_limit` and `spend_unit` cannot be supplied together. Existing grants are not assigned a unit automatically.

**BREAKING: wallet send request amounts.** `POST /api/v1/wallets/send` now accepts `amount_raw` as an exact integer string or `amount_xno` as an exact decimal string. JSON numbers are refused, because they cannot represent every raw XNO amount.

A send requires an XNO-denominated delegation, and every bounded ancestor must be declared in the same unit. Legacy budgets without a declared unit cannot authorize Nano spending. Publishing remains disabled regardless of these checks.

**Evaluation and reporting.** For a unit-declared delegation, `/evaluate` denies requests with a positive estimated cost and any `commerce` action. In a shadow mode, `effective_verdict` may still be `permit`. That result is not authorization to execute a payment.

The public trust profile now reports a delegation's declared unit and exact limit and usage, and a zero limit is reported as zero, not as unlimited. The signed governance attestation keeps the draft v0.1 schema:

- For a legacy delegation it no longer asserts a currency. 0.4.3 and earlier labelled every budget XNO, although the counters of a legacy budget may hold USD or XNO amounts.
- For a unit-declared delegation the attestation is refused with `422 attestation_unavailable`, because the v0.1 schema cannot state an exact unit budget.
- The attestation's `delegation_chain_hash` now matches the decision record's for the same chain. The attestation used to keep a `null` spend limit in the hashed chain and the decision record dropped it, so a chain with an unlimited link got two different hashes. Both now drop it, as the SDK canonicalization does. For such a chain the attestation's hash changes once, to the value decision records already carry. Other chains hash as before.

The FinOps delegation view still reads the legacy budget columns and does not show unit-declared limits.

**Upgrading.** Startup adds `spend_unit`, `spend_limit_minor` and `spend_used_minor` to existing databases, and a failure to add a required column prevents startup. Existing delegation rows are not backfilled. Grants without a declared unit keep their legacy accounting, except that Nano sending is unavailable.

Do not downgrade to an earlier version with the old Nano publishing path enabled.

## 0.4.3 (2026-11-11)

**Security: a delegation's budget did not cover spending below it (GHSA-w2v3-jgwx-8xjf).** In every earlier version, `POST /api/v1/evaluate` and `POST /api/v1/wallets/send` checked and debited only the acting agent's own delegation. Spending under a child delegation did not count against its parent's budget, so a grant that was split into sub-delegations could authorize more in total than the grant allowed.

- A spend now has to fit every bounded delegation on the acting delegation's chain, and a permit debits every delegation on that chain in the same transaction.
- `POST /api/v1/wallets/send` now checks the whole delegation chain for a revoked, suspended or frozen grantor, as `/evaluate` already did, and treats a `spend_limit` of 0 as a zero budget. Before, it read 0 as no limit.
- A Nano send that fails before its block is published releases its debit. A send that fails while or after publishing keeps the debit and is recorded as `pending` with the reason `outcome_unknown`, because the block may still be accepted.

**BREAKING: Nano wallet send is off by default.** Delegation spend limits are created in USD, and `POST /api/v1/wallets/send` debits XNO against the same counter, so a limit does not mean the same amount on that route. Sends are refused unless `NANO_WALLET_SEND_ENABLED=1` is set, and `NANO_WALLETS_PAUSED=1` still refuses them when it is. Leave the flag unset until budgets carry their own unit.

**Upgrading an existing installation.** Earlier versions recorded a child's spending without adding it to its ancestors' counters, and updating the code does not repair those values. On its first start, 0.4.3 holds every delegation whose counter cannot be trusted and refuses spending through it, even where no budget was exceeded:

- every ancestor of a delegation that had spent, through `parent_delegation_id`
- every sub-delegation from before 0.4.1, which has no `parent_delegation_id`, together with its grantor's inbound delegation and that delegation's ancestors

The holds are listed in the `chain_spend_holds` table, with each delegation's direct `spend_used` at upgrade time. To release a chain, either revoke it and grant new delegations, or reconcile each ancestor's counter from the direct spending of its whole subtree and then delete its hold rows. Delete a hold row only after that reconciliation or revocation is complete. Keep the record of any spending that exceeded a limit. Do not cap a counter to make it fit. A new database gets no holds.

**Do not downgrade a database upgraded to 0.4.3 to an earlier gateway version.** Earlier versions do not enforce the spending holds and restore the ancestor budget vulnerability.

**Remaining limitations, not changed by this release.** `/evaluate` accepts the cost the caller reports, so its budget accounting is only as accurate as those values, and it does not establish what an executed action cost. Nano wallet sending needs budgets that carry their own unit and a pending record written before a block is broadcast before it should be enabled.

## 0.4.2 (2026-11-04)

**Security: Nano master seed generation (GHSA-x746-727g-7gxp).** Before this release, when the Nano payment rail had no seed file, `getMasterSeed()` created one from a random source built on `Math.random`. A seed created that way may be predictable. Updating does not repair an existing seed: if your gateway created its own seed, follow the steps in the advisory to replace it.

- The gateway no longer creates a seed implicitly. A missing or malformed seed file is an error, and in production the server refuses to start while the Nano wallets are in use without a seed. A new seed comes only from `npm run nano:seed-init`, which uses `crypto.randomBytes`.
- `NANO_WALLETS_PAUSED=1` pauses every wallet operation, for example while a seed is rotated. `npm run nano:seed-addresses` prints the addresses a seed file derives, to check a backup.
- Agent wallets start at index 1. The first agent wallet used to share index 0 with the gateway's settlement wallet.
- nanocurrency-web 2.0.0 (no crypto-js), body-parser 2.4.0, proxy-addr 2.0.8.

## 0.4.1 (2026-10-05)

**BREAKING: scoped approvals refuse fields they cannot bind.** `POST /api/v1/approvals`,
`POST /api/v1/approvals/:id/sign` and `POST /api/v1/approvals/:id/decide` answer
`400 {code: "unbindable_field", fields: [...]}` when the body carries `amount`, `currency`,
`params` or `target`. Before, these fields were accepted and silently dropped: nothing
stored them, the approver signature did not cover them and the receipt did not carry
them, so a caller could believe an amount or a payee had been approved when only the
action class and `requested_scope` were. Encode limits in `requested_scope` instead.
`estimated_total` (the advisory value gate at open) is unchanged.

**BREAKING: `/sign` and `/decide` refuse request content.** `subject`, `action_class` and
`requested_scope` in a `POST /api/v1/approvals/:id/sign` or `/decide` body answer
`400 {code: "request_bound_field", fields: [...]}` and nothing is stored. Before, they
were accepted and ignored: the signed commitment and the receipt always came from the
request as opened, so they could not change what was approved, but a caller could
believe they had. Open a new request to change them. `POST /api/v1/approvals` still
takes all three.

**BREAKING: `/sign` takes `approver_id`, `reason` and `signature` only.**

- `approver_id` must name an approver the tenant admin registered (below). Its public
  key, authority, key class and office come from the registry.
- `signature` is required: an Ed25519 signature, under the registered key, over the
  request commitment that `GET /api/v1/approvals/:id` returns as `commitment.message`.
- `approver_public_key`, `authority`, `key_class`, `office_id`, `decision_latency_ms`
  and `batch_size` in the body answer `400 {code: "server_bound_field", fields: [...]}`.
  One `/sign` call is one signature over one request commitment, so the batch is not
  the caller's to state.
- Elapsed time between opening and signing is no longer a reason to refuse: the
  `latency_impossible` 429 is gone. The gateway stores the server-measured request age
  on the signature row (`elapsed_since_open_ms`) as telemetry. It is not a measure of
  review or reading time.
- The rubber-stamp check no longer runs on `/sign`, and the success body has no
  `fatigue_flag`. On this route its only discriminating input was the request age,
  which is not review time. The 429 it used to return is gone.
- For high-risk tiers the approver must not be registered as the agent owner, the
  agent itself, or the API key that opened the request, and must not hold the agent's
  key. The body `requested_by` label is no longer part of that check. The check
  compares registered identities and keys. It does not prove that a separate person
  holds the approver key.

**New: tenant admin credential and approver registry routes.**

- `POST /auth/tenant-admin/issue` with the account owner's `email` and `password`
  returns a `tenant_admin` API key that expires 15 minutes after issuance. It cannot be
  renewed with any API key. Issue a new one with the password. Ordinary login, signup,
  GitHub OAuth and key rotation still return runtime keys only.
- `POST /api/v1/approvers`, `GET /api/v1/approvers` and
  `POST /api/v1/approvers/:approver_id/revoke` accept only an unexpired `tenant_admin`
  key of the same tenant. A runtime key gets `403 {code: "tenant_admin_required"}`.
- A `tenant_admin` key works only on those three routes and on `GET /api/v1/account`.
  Every other route answers `403 {code: "tenant_admin_scope"}`. That includes approval
  open, sign, decide and receipt and `rotate-key` and `regenerate-key`, so an admin key
  cannot mint, rotate or renew a runtime key.
- A `tenant_admin` key whose stored expiry is missing or unparseable is refused with
  401. Runtime keys with no expiry are unaffected.
- Each successful issuance sends one security notice to the account email: account,
  time, action and expiry, and what to do if it was not the owner. It never contains
  the key.
- Approver `authority` is a list of 1 to 32 action-class entries (`payments:refund`,
  `payments`, `payments:*`). A bare `*` or any other wildcard answers
  `400 {code: "authority_wildcard"}`, more than 32 entries
  `400 {code: "authority_too_many"}`. There is no update route. Revoke and register a
  new approver id to change authority.
- `POST /api/v1/account/rotate-key` and `regenerate-key` now revoke runtime keys only.
  Password reset still revokes every key, tenant admin keys included.
  `GET /api/v1/account` lists `key_class` and `expires_at` per key.

**Fixed: approver revocation during decide.** `decide` now reads the signatures and the
approver registry inside the same database transaction that records the decision. A
revocation committed by another process while a decide was in flight could be missed
before, and the request approved on the revoked approver's signature.

**Migration notes.**

- Every existing API key is a runtime key with no expiry.
- A `tenant_admin` row with no expiry, which only an unreleased build of this branch
  could write, no longer authenticates.
- No approvers are registered for any tenant. Until a tenant admin registers one,
  `/sign` answers `403 approver_not_registered`.
- Pending requests signed before this change hold signatures that were never verified.
  Approving them answers `409 approver_evidence_invalid`. A new signature from a
  registered approver does not change that, because the unverified rows stay on the
  request. Reject such a request or let it expire, then open a new one. Pending
  requests with no signatures can be signed and approved normally.
- Approval receipts issued from now on use payload schema `1.1.0` with
  `request_commitment` and `approver_evidence_digest`. Both are in the full receipt on
  the authenticated `GET /api/v1/approvals/:id/receipt` and are not in the public
  receipt projection.
