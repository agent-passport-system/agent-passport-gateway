# Changelog

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
