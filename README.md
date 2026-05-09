# alani-ipc

Capability-aware message passing, ports, channels, event queues, shared-memory handles, and routing contracts.

| Field | Value |
|---|---|
| Tier | MVK required |
| Owner | Kernel and runtime teams |
| Aliases | None |
| Architectural dependencies | `alani-abi`, `alani-protocol`, `alani-policy`, `alani-observability` |

## Quick start

```bash
cargo fmt -- --check
cargo test --all-features
```

## Public skeleton

The crate is `no_std` by default and dependency-free. It currently exposes fixed-capacity Rust contracts for:

- `port`: named port descriptors, port open requests, lifecycle states, and duplicate-safe port tables.
- `channel`: channel descriptors, message headers, message envelopes, payload descriptors, and delivery modes.
- `shared_memory`: shared-memory handles, access modes, seal/revoke lifecycle, and grant validation.
- `queue`: IPC events, wait reasons, queue overflow policies, and bounded FIFO queues.
- `router`: route rules, route decisions, and capability-gated fixed-capacity route tables.

Security-sensitive operations fail closed for reserved rights, unauthorized opens or sends, oversized payloads, unsealed shared memory, revoked memory, malformed traces, sensitive unredacted payloads, closed endpoints, and invalid routes.

Keep public API changes synchronized with `docs/repositories/alani-ipc.md`, Doc 42, Doc 43, and Docs 06, 08, 09, and 12.
