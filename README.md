# philharmonic-connector-common

Shared connector-layer vocabulary for Philharmonic v1.

This crate is intentionally **types-only**. It defines the claim,
context, realm, wrapper, and error shapes used by connector client/
router/service crates. It does **not** perform cryptographic
operations.

Part of the Philharmonic crate family:
https://github.com/metastable-void/philharmonic-workspace

## What's in this crate

- `ConnectorTokenClaims` — COSE_Sign1 payload claims used to authorize
  connector calls.
- `ConnectorCallContext` — verified metadata passed to connector
  implementations.
- `RealmId`, `RealmPublicKey`, `RealmRegistry` — realm key model with
  `kid` lookup and duplicate-key protection.
- `ConnectorSignedToken`, `ConnectorEncryptedPayload` — thin wrappers
  around `coset::CoseSign1` and `coset::CoseEncrypt0`.
- `ImplementationError` — shared implementation-level error taxonomy.

## What's out of scope

- COSE signing / verification.
- COSE encryption / decryption.
- ML-KEM / X25519 / HKDF / AES primitive calls.
- Payload-hash computation.

Those are implemented in later roadmap phases (`connector-client` and
`connector-service`).

## Quick example

```rust
use philharmonic_connector_common::{
    ConnectorTokenClaims, MLKEM768_PUBLIC_KEY_LEN, RealmId, RealmPublicKey,
    RealmRegistry, Sha256, UnixMillis, Uuid,
};

let claims = ConnectorTokenClaims {
    iss: "lowerer.main".to_owned(),
    exp: UnixMillis(1_800_000_000_000),
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

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`.
See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MPL](LICENSE-MPL).

SPDX-License-Identifier: `Apache-2.0 OR MPL-2.0`
