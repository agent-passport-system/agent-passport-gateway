# Changelog

## Unreleased

**BREAKING: scoped approvals refuse fields they cannot bind.** `POST /api/v1/approvals`,
`POST /api/v1/approvals/:id/sign` and `POST /api/v1/approvals/:id/decide` answer
`400 {code: "unbindable_field", fields: [...]}` when the body carries `amount`, `currency`,
`params` or `target`. Before, these fields were accepted and silently dropped: nothing
stored them, the approver signature did not cover them and the receipt did not carry
them, so a caller could believe an amount or a payee had been approved when only the
action class and `requested_scope` were. Encode limits in `requested_scope` instead.
`estimated_total` (the advisory value gate at open) is unchanged.

**BREAKING: `/sign` takes `approver_id`, `reason` and `signature` only.**

- `approver_id` must name an approver the tenant admin registered (below). Its public
  key, authority, key class and office come from the registry.
- `signature` is required: an Ed25519 signature, under the registered key, over the
  request commitment that `GET /api/v1/approvals/:id` returns as `commitment.message`.
- `approver_public_key`, `authority`, `key_class`, `office_id` and `decision_latency_ms`
  in the body answer `400 {code: "server_bound_field", fields: [...]}`.
- `batch_size` is no longer read. One `/sign` call signs one request, so the gateway
  treats every signature as a batch of 1.
- Elapsed time between opening and signing is no longer a reason to refuse: the
  `latency_impossible` 429 is gone. The gateway stores the server-measured request age
  on the signature row (`elapsed_since_open_ms`) as telemetry. It is not a measure of
  review or reading time.
- The success body adds `fatigue_flag` (`null` or `"rubber_stamping"`). It reports the
  rubber-stamp pattern over the approver's accepted signatures and does not block.
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
- Approver `authority` is a list of 1 to 32 action-class entries (`payments:refund`,
  `payments`, `payments:*`). A bare `*` or any other wildcard answers
  `400 {code: "authority_wildcard"}`, more than 32 entries
  `400 {code: "authority_too_many"}`. There is no update route. Revoke and register a
  new approver id to change authority.
- `POST /api/v1/account/rotate-key` and `regenerate-key` now revoke runtime keys only.
  Password reset still revokes every key, tenant admin keys included.
  `GET /api/v1/account` lists `key_class` and `expires_at` per key.

**Migration notes.**

- Every existing API key is a runtime key with no expiry.
- No approvers are registered for any tenant. Until a tenant admin registers one,
  `/sign` answers `403 approver_not_registered`.
- Pending requests signed before this change hold signatures that were never verified.
  Approving them answers `409 approver_evidence_invalid`, and they need re-signing by a
  registered approver.
- Approval receipts issued from now on use payload schema `1.1.0` with
  `request_commitment` and `approver_evidence_digest`. Both are in the full receipt on
  the authenticated `GET /api/v1/approvals/:id/receipt` and are not in the public
  receipt projection.
