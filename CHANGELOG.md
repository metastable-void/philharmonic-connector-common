# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.0.0]

Name reservation on crates.io. No functional content yet.
