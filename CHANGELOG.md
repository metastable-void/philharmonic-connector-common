# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-22

**Breaking.** `ConnectorTokenClaims` gained an `iat: UnixMillis`
field (issued-at, in Unix milliseconds), placed between `exp`
and `kid`. The CBOR wire form now has ten map entries instead
of nine; wire-level consumers must regenerate any pinned test
vectors. Lands the Wave A Gate-2 follow-up decision (option
(A) from
`docs/notes-to-humans/2026-04-22-0011-phase-5-wave-a-claude-review.md`):
`ConnectorCallContext.issued_at` is now populated from
`claims.iat` on the service side instead of the verification
timestamp, so the field name's meaning finally matches its
value.

No other API changes. The rest of the crate surface
(`ConnectorCallContext`, `RealmId`, `RealmPublicKey`,
`RealmRegistry`, `ConnectorSignedToken`,
`ConnectorEncryptedPayload`, `ImplementationError`) is
unchanged from 0.1.0.

## [0.1.0] - 2026-04-22

- Added `ConnectorTokenClaims` with the connector authorization-token
  claim set (`iss`, `exp`, `kid`, `realm`, `tenant`, `inst`, `step`,
  `config_uuid`, `payload_hash`).
- Added `ConnectorCallContext` for verified framework metadata delivered
  to connector implementations.
- Added realm key model types: `RealmId`, `RealmPublicKey`, and
  `RealmRegistry` (`kid` lookup, duplicate-`kid` rejection, ML-KEM-768
  public-key length validation).
- Added thin COSE wrapper types: `ConnectorSignedToken` and
  `ConnectorEncryptedPayload`.
- Added `ImplementationError` as the shared connector implementation
  error taxonomy.
- Added unit tests for serde round-trips, realm-registry lookup
  semantics, ML-KEM key-length validation, and COSE wrapper smoke
  construction.
- Verified clean under `cargo +nightly miri test` for the full test
  suite prior to publish.

## [0.0.0]

Name reservation on crates.io. No functional content yet.
