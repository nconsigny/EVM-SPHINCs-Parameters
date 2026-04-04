# EVM-SPHINCs-Parameters

`EVM-SPHINCs-Parameters` is an EVM-oriented adaptation of the Blockstream Research repository [`SPHINCS-Parameters`](https://github.com/BlockstreamResearch/SPHINCS-Parameters).

The original repository is a SageMath toolbox for exploring SPHINCS+ parameter tradeoffs. This fork keeps that research base, but repurposes it for Keccak-only verification inside the Ethereum Virtual Machine, with emphasis on:

- `n = 16` / 128-bit truncated Keccak outputs
- EVM verification gas instead of generic hash-call counts
- live mainnet calldata pricing (`EIP-7623`) by default
- optional draft `EIP-7976` comparison mode
- search modes tuned for Ledger-style devices and EVM verification
- architecture variants beyond plain SPHINCS+, including `W+C`, `W+C_F+C`, `W+C_P+FP`, and `FORS_MERKLE`

## Provenance

This repository starts from:

- Blockstream Research: https://github.com/BlockstreamResearch/SPHINCS-Parameters
- Original SPHINCS+ search script: `original-sphincs-parameter-search.sage`

The EVM-oriented work in this repository keeps the original research spirit, but changes the objective function and the engineering assumptions.

## What Changed Relative to the BlockstreamResearch Repo

The adaptation was done in a few deliberate steps.

### 1. Keep the parameter-search core

The original repository already contains the useful parts:

- a SageMath search framework
- SPHINCS+ size and cost formulas
- a security model in `security.sage`
- an updated version of the original SPHINCS+ search script

Those are preserved as the base.

### 2. Reframe the hash-cost model around Keccak

This repository assumes that the hash function is always Keccak because the target verifier is the EVM, where `KECCAK256` is an opcode.

In practice this means:

- signing and verification times are estimated from Keccak-call counts
- verification gas uses EVM Keccak opcode pricing
- all comparisons are made under a Keccak-only verifier model

The main implementation lives in `costs.sage`.

### 3. Add EVM-specific calldata pricing

The original repository is not an Ethereum gas model. This adaptation adds one.

Current modes:

- default: `EIP-7623` live mainnet calldata floor
- optional: `EIP-7976` draft mode
- optional: legacy `60/15` what-if mode used during earlier exploration

Important point: for `EIP-7623` and `EIP-7976`, total verification gas is not modeled as `compute + calldata`. It is modeled as:

```text
total_verify_gas = max(standard_calldata + compute_gas, calldata_floor)
```

This matters because many SPHINCS-like signatures are floor-bound on mainnet.

### 4. Add SPHINCS architecture variants relevant to EVM constraints

The repository now explores more than plain SPHINCS+:

- `SPX`: plain SPHINCS+
- `W+C`: WOTS+C
- `W+C_F+C`: WOTS+C with FORS+C
- `W+C_P+FP`: WOTS+C with PORS+FP
- `FORS_MERKLE`: FORS-only in a single Merkle tree (`d=1`, no WOTS)

These variants are intended to explore the gas/size/security frontier under EVM constraints.

### 5. Add an EVM-focused research search mode

`costs.sage --research` is the main entry point for interactive exploration.

It supports:

- filtering by `d`, `h`, `a`, `k`, `w`, and scheme
- tuning security to a target signature budget such as `2^16` or `2^20`
- reporting overuse-security checkpoints such as `2^16`, `2^20`, `2^30`
- device-specific Keccak throughput assumptions via `KECCAKS_PER_SEC`
- gas limits, sign-time limits, and verify-time limits

### 6. Add on-device root-generation estimates

For `d = 1`, key generation already mattered because the whole single Merkle tree must be built.

For `d > 1`, this repository now estimates `rootgen` rather than returning zero:

- it models generating the top XMSS root from seed
- it does not model precomputing the full hypertree eagerly

This is the right approximation for secure-element feasibility studies.

## Repository Layout

- `costs.sage`: size, sign/verify cost, gas model, and search logic
- `security.sage`: security calculations for FORS and PORS+FP style parameter sets
- `original-sphincs-parameter-search.sage`: updated copy of the original SPHINCS+ parameter search
- `octopus_pmf.py`: PMF helper for Octopus/PORS+FP authentication-set sizing

## Setup

This repository expects SageMath.

Example if Sage is installed directly:

```bash
sage costs.sage --help
```

Example if Sage is installed in a conda environment named `sage`:

```bash
DOT_SAGE=/tmp/sage conda run -n sage sage costs.sage --help
```

## Main Commands

### Show the current built-in table

```bash
sage costs.sage --table
```

### Run the EVM-focused search

```bash
sage costs.sage --research 20
```

### Compare against draft `EIP-7976`

```bash
CALLDATA_MODEL=7976 sage costs.sage --research 20
```

### Reproduce the old `60/15` what-if model

```bash
CALLDATA_MODEL=60_15 sage costs.sage --research 20
```

## Important Environment Knobs

### Gas and device model

- `CALLDATA_MODEL=7623|7976|60_15`
- `KECCAKS_PER_SEC=<rate>`
- `CALLDATA_ZERO_FRACTION=<fraction>`

### Security target

- `RESEARCH_TUNED_LOG_QS=<log2 signatures>`  
  Example: `16` means the parameter set is tuned for `2^16` signatures.
- `RESEARCH_TARGET_SECURITY=<bits>`
- `RESEARCH_SECURITY_LOGS=16,20,30`

### Search ranges

- `RESEARCH_SCHEMES=...`
- `RESEARCH_D_VALUES=...`
- `RESEARCH_MIN_H_D1=...`
- `RESEARCH_MAX_H_D1=...`
- `RESEARCH_MIN_H_OTHER=...`
- `RESEARCH_MAX_H_OTHER=...`
- `RESEARCH_A_MIN=...`
- `RESEARCH_A_MAX=...`
- `RESEARCH_K_MIN=...`
- `RESEARCH_K_MAX=...`
- `RESEARCH_W_VALUES=...`

### Search constraints

- `RESEARCH_SIGN_TIME_LIMIT=<seconds>`
- `RESEARCH_VERIFY_TIME_LIMIT=<seconds>`
- `RESEARCH_GAS_LIMIT=<gas>`
- `RESEARCH_FORCE_SCHEMES=...`

## Example Research Commands

### Default live-mainnet search

```bash
KECCAKS_PER_SEC=1000000 sage costs.sage --research 20
```

### Search around the C2/C3/C4 neighborhood at `2^16`

```bash
KECCAKS_PER_SEC=1000000 RESEARCH_TUNED_LOG_QS=16 RESEARCH_TARGET_SECURITY=128 RESEARCH_SCHEMES=W+C_F+C,W+C_P+FP RESEARCH_D_VALUES=2,3 RESEARCH_MIN_H_OTHER=16 RESEARCH_MAX_H_OTHER=33 RESEARCH_A_MIN=11 RESEARCH_A_MAX=15 RESEARCH_K_MIN=8 RESEARCH_K_MAX=14 RESEARCH_W_VALUES=16,32 RESEARCH_FORCE_SCHEMES= sage costs.sage --research 20
```

### secure-element exploration with longer sign budget to assess keygen tractability 

```bash
KECCAKS_PER_SEC=5400 RESEARCH_SIGN_TIME_LIMIT=300 RESEARCH_VERIFY_TIME_LIMIT=300 RESEARCH_TUNED_LOG_QS=16 RESEARCH_TARGET_SECURITY=128 RESEARCH_SCHEMES=W+C_F+C,W+C_P+FP RESEARCH_D_VALUES=2,3 RESEARCH_MIN_H_OTHER=16 RESEARCH_MAX_H_OTHER=33 RESEARCH_A_MIN=11 RESEARCH_A_MAX=15 RESEARCH_K_MIN=8 RESEARCH_K_MAX=14 RESEARCH_W_VALUES=16,32 RESEARCH_FORCE_SCHEMES= sage costs.sage --research 20
```

## Reading the Research Table

Key columns:

- `Size`: signature size in bytes
- `Sign(s)`: estimated signing time from Keccak-call counts
- `Verify(s)`: estimated verification time from Keccak-call counts
- `Gas`: total verification gas excluding the `21,000` base transaction cost and memory expansion
- `Path`:
  - `floor`: total gas is dominated by the calldata floor
  - `exec`: total gas is dominated by standard calldata plus compute
  - `legacy`: old `60/15` additive model
- `Floor`: calldata floor under the active pricing model
- `StdData`: standard calldata charge at `4/16`
- `Compute`: Keccak opcode gas for verification
- `Sec@2^N`: effective security in bits after `2^N` signatures
- `Keygen(s)`: root-generation estimate

## Modeling Assumptions and Limits

This repository is a parameter-search tool, not a full contract-level gas simulator.

Modeled:

- signature size
- Keccak opcode gas
- calldata floor / standard calldata pricing
- tuning-security and overuse checkpoints
- root-generation feasibility

Not modeled:

- `21,000` base transaction cost
- EVM memory expansion
- calldata copy overhead
- ABI decoding overhead
- loop/control-flow overhead in a concrete verifier implementation
- storage/logging costs

That is intentional. The tool is meant to compare parameter sets cleanly before contract-level micro-optimization.

## Notes on Current Design Direction

The present work is aimed at the following setting:

- hash function fixed to Keccak
- EVM verification as the primary deployment target
- signature gas as the main on-chain objective
- Ledger-like devices as the main off-chain feasibility constraint

That is why the repository emphasizes:

- `n = 16`
- `d = 2` / `d = 3` / `d = 4` tradeoffs
- `w = 16` / `w = 32` as the likely sweet spot
- comparison between live-mainnet `EIP-7623` and draft `EIP-7976`

## License / Upstream Attribution

Please keep upstream attribution when publishing derivative work based on the Blockstream Research repository and on the bundled external helper code.
