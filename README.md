# philharmonic-connector-common

Shared vocabulary for the Philharmonic connector layer.

This crate is intentionally **types-only**. It defines the claim,
context, realm, wrapper, and error shapes used by
`philharmonic-connector-client` (mint + encrypt),
`philharmonic-connector-service` (verify + decrypt), and
`philharmonic-connector-router` (transport-only dispatch). It does
**not** perform any cryptographic operation — no signing, no
verifying, no KEM encapsulation, no AEAD. Those live on the client
and service sides.

Part of the Philharmonic workspace:
https://github.com/metastable-void/philharmonic-workspace

## What's in this crate

- `ConnectorTokenClaims` — the COSE_Sign1 payload carried by each
  connector authorization token. Ten fields: `iss`, `exp`, `iat`
  (issued-at; added in `0.2.0`), `kid`, `realm`, `tenant`, `inst`,
  `step`, `config_uuid`, `payload_hash`.
- `ConnectorCallContext` — verified metadata delivered to connector
  implementations after the service side has finished checking the
  token. Drops the `iss` / `kid` bookkeeping claims and exposes
  `issued_at` (sourced from `claims.iat`) + `expires_at`.
- `RealmId`, `RealmPublicKey`, `RealmRegistry` — per-realm KEM public
  key model with `kid` indexing, validity-window checks, duplicate-
  key protection, and a named ML-KEM-768 public-key length constant
  (`MLKEM768_PUBLIC_KEY_LEN = 1184`).
- `ConnectorSignedToken`, `ConnectorEncryptedPayload` — thin newtypes
  around `coset::CoseSign1` / `coset::CoseEncrypt0` so the token /
  payload types appear in public APIs without forcing every caller
  to pull `coset` directly.
- `ImplementationError` — shared error taxonomy that individual
  connector implementations use to report failures back through the
  service layer.

## What's out of scope

- COSE signing / verification.
- COSE encryption / decryption.
- ML-KEM / X25519 / HKDF / AES-GCM primitive calls.
- Payload-hash computation.

Those land in `philharmonic-connector-client` (lowerer-side) and
`philharmonic-connector-service` (realm-side). Splitting them out
keeps this crate a zero-crypto, cheap dependency for any workspace
member that only needs to name the shapes (e.g. the workflow engine
referring to `ConnectorCallContext`).

## Quick example

```rust
use philharmonic_connector_common::{
    ConnectorTokenClaims, MLKEM768_PUBLIC_KEY_LEN, RealmId, RealmPublicKey,
    RealmRegistry, Sha256, UnixMillis, Uuid,
};

let claims = ConnectorTokenClaims {
    iss: "lowerer.main".to_owned(),
    exp: UnixMillis(1_800_000_000_000),
    iat: UnixMillis(1_799_999_880_000),
    kid: "lowerer-signing-key-2026-04".to_owned(),
    realm: "llm".to_owned(),
    tenant: Uuid::new_v4(),
    inst: Uuid::new_v4(),
    step: 7,
    config_uuid: Uuid::new_v4(),
    payload_hash: Sha256::from_bytes_unchecked([0xAB; 32]),
};

let key = RealmPublicKey::new(
    "realm-kid-1",
    RealmId::from("llm"),
    vec![0x11; MLKEM768_PUBLIC_KEY_LEN],
    [0x22; 32],
    UnixMillis(1_700_000_000_000),
    UnixMillis(1_900_000_000_000),
)?;

let mut registry = RealmRegistry::new();
registry.insert(key)?;
let _selected = registry.lookup(&claims.kid);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Versioning notes

- `0.2.0` — adds the `iat: UnixMillis` claim to
  `ConnectorTokenClaims` (placed between `exp` and `kid`).
  **Breaking** at the CBOR wire level: the claims map now has ten
  entries instead of nine, so any pinned test vectors must be
  regenerated. `ConnectorCallContext.issued_at` is now populated
  from `claims.iat` (mint time) instead of the verification
  timestamp. See `CHANGELOG.md` for the full entry.
- `0.1.0` — initial publish (2026-04-22).

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MPL](LICENSE-MPL).

SPDX-License-Identifier: `Apache-2.0 OR MPL-2.0`

## Contributing

This crate is developed as a submodule of the Philharmonic
workspace. Workspace-wide development conventions — git workflow,
script wrappers, Rust code rules, versioning, terminology — live
in the workspace meta-repo at
[metastable-void/philharmonic-workspace](https://github.com/metastable-void/philharmonic-workspace),
authoritatively in its
[`CONTRIBUTING.md`](https://github.com/metastable-void/philharmonic-workspace/blob/main/CONTRIBUTING.md).
