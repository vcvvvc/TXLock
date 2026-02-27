# MDLOCK Plan (Retained)

## Status Snapshot
- Project state: core encryption/decryption workflow is complete and test-covered.
- Dependency baseline: `github.com/vcvvvc/go-wallet-sdk/crypto` (v0.1.0).
- Plan mode: historical milestones are closed; this file is retained as a stable project anchor.

## Completed Milestones
- [x] M0: CLI entry skeleton (`mdlock-enc`, `mdlock-dec`).
- [x] M1: Argument and exit-code baseline (`1` usage, `2` processing).
- [x] M2: Path/index rule module (`m/44'/60'/0'/0/<i>` validation).
- [x] M3: Mnemonic normalization pipeline.
- [x] M4: Key derivation (`DeriveSK`) with deterministic vectors.
- [x] M5: Encryption core (HKDF-SHA256 + AES-256-GCM + fixed AAD).
- [x] M6: Strict markdown envelope parser/builder.
- [x] M7: End-to-end CLI wiring with file/stdin/stdout flow.
- [x] M8: Round-trip/tamper/error-class tests closure.

## Contract Snapshot (Current CLI Behavior)
- `mdlock-enc`:
  - Requires `-mnemonic-env`.
  - `-index` optional, defaults to `777`.
  - Default output path: `./lockfile/lock/<input>.lock`.
- `mdlock-dec`:
  - Requires `-mnemonic-env` and `-index`.
  - Does not use `-path-override`.
  - Default output path: `./lockfile/unlock/<input-without-.lock>`.
- Error signaling:
  - Usage errors: exit `1` + stderr message.
  - Processing errors: exit `2` + stderr message.

## Validation Gate
- Primary check:
  - `go test ./...`
- Optional CLI sanity check:
  - `go run ./cmd/mdlock-enc -h`
  - `go run ./cmd/mdlock-dec -h`

## Maintenance Notes
- Keep `_PLAN.md` as the single retained progress/context anchor.
- For any new contract change, update:
  - CLI help text
  - tests
  - README
  - this plan snapshot
