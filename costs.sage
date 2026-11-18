#!/usr/bin/env sage
"""
SPHINCS+ Parameter Efficiency and Size Calculator

Computes signature sizes and signing/verification times for SPHINCS+ variants:
- SPX: Plain SPHINCS+ (WOTS-TW + FORS)
- W+C: SPHINCS+ with WOTS+C (counter-based WOTS, no checksum chains)
- W+C_F+C: SPHINCS+ with WOTS+C and FORS+C (grinding to remove last FORS tree)
- W+C_P+FP: SPHINCS+ with WOTS+C and PORS+FP (single tree with Octopus auth)
- FORS_MERKLE: FORS-only with a single Merkle tree (d=1, no WOTS)

Notation:
- h: hypertree height (total)
- d: number of layers in the hypertree
- h' = h/d: height of each XMSS tree layer
- n: hash output size in bits (fixed at 128 = hashbytes*8)
- a: log2 of leaves per FORS tree (t = 2^a leaves per tree)
- k: number of FORS trees (or leaf indices for PORS)
- w: Winternitz parameter
- l: number of WOTS chains
- S_{w,n} (swn): target chain sum for WOTS+C
- q_s: max number of signatures supported
"""

from sage.all import *
from scipy.stats import binom
import os

from octopus_pmf import interleave_cost_table

# Load security.sage from the same directory
_dir = os.path.dirname(os.path.abspath(__file__))
load(os.path.join(_dir, "security.sage"))

# =============================================================================
# Constants
# =============================================================================

hashbytes = 16  # 16 bytes = 128 bits
counter_size = 4  # 4 bytes = 32 bits
randomness_size = 32  # 32 bytes = 256 bits

# Fixed input component sizes (bytes)
tweak_size = 12  # 96-bit tweak
msg_size = 32  # Model a 256-bit message digest in Hmsg/PRFmsg

# EVM gas schedule (Shanghai/Cancun) for KECCAK256.
# Calldata defaults to live mainnet EIP-7623 pricing; EIP-7976 draft and a legacy 60/15
# what-if mode are available via CALLDATA_MODEL.
# Sources: evm.codes (opcode costs), EIP-7623, EIP-7976.
GAS_KECCAK_BASE = 30
GAS_KECCAK_PER_WORD = 6
TX_BASE_GAS = 21_000
GAS_CALLDATA_STANDARD_ZERO = 4
GAS_CALLDATA_STANDARD_NONZERO = 16
GAS_CALLDATA_7623_FLOOR_PER_TOKEN = 10
GAS_CALLDATA_7976_FLOOR_PER_BYTE = 64
GAS_CALLDATA_60_15_NONZERO = 60
GAS_CALLDATA_60_15_ZERO = 15
ASM_MODEL_INTERCEPT = 36117.58115183245
ASM_MODEL_PER_OP = 194.2041884816754
PORS_CORE_TREE_H_WEIGHT = 5
PORS_CORE_CONST = 27

# Hash throughput assumption for rough CPU-time estimates (keccak calls per second).
# Override via KECCAKS_PER_SEC env var.
DEFAULT_KECCAKS_PER_SEC = float(os.environ.get("KECCAKS_PER_SEC", 5_000_000))
DEFAULT_CALLDATA_ZERO_FRACTION = float(os.environ.get("CALLDATA_ZERO_FRACTION", 0.0))

def normalize_calldata_model(value):
    """Normalize calldata model aliases to a canonical identifier."""
    model = str(value).strip().lower()
    aliases = {
        "7623": "7623",
        "eip7623": "7623",
        "mainnet": "7623",
        "mainnet_7623": "7623",
        "live": "7623",
        "live_7623": "7623",
        "7976": "7976",
        "eip7976": "7976",
        "draft": "7976",
        "draft_7976": "7976",
        "60_15": "60_15",
        "legacy": "60_15",
        "legacy_60_15": "60_15",
    }
    if model not in aliases:
        raise ValueError(f"Unsupported CALLDATA_MODEL={value!r}; expected 7623, 7976, or 60_15")
    return aliases[model]

DEFAULT_CALLDATA_MODEL = normalize_calldata_model(os.environ.get("CALLDATA_MODEL", "7623"))

def evm_keccak_gas(byte_len):
    """Gas for KECCAK256 over byte_len bytes (excluding memory expansion)."""
    return GAS_KECCAK_BASE + GAS_KECCAK_PER_WORD * ceil(byte_len / 32)

def calldata_token_counts(size_bytes, zero_bytes=0):
    """Return zero bytes, non-zero bytes, and EIP-7623 tokens."""
    if size_bytes < 0:
        raise ValueError("size_bytes must be nonnegative")
    zero_bytes = max(0, min(int(zero_bytes), int(size_bytes)))
    nonzero = int(size_bytes) - zero_bytes
    tokens = zero_bytes + 4 * nonzero
    return zero_bytes, nonzero, tokens

def calldata_standard_gas(size_bytes, zero_bytes=0):
    """Standard calldata gas at 4/16 (equivalently 4 gas per EIP-7623 token)."""
    zero_bytes, nonzero, _ = calldata_token_counts(size_bytes, zero_bytes)
    return zero_bytes * GAS_CALLDATA_STANDARD_ZERO + nonzero * GAS_CALLDATA_STANDARD_NONZERO

def calldata_floor_gas(size_bytes, zero_bytes=0, calldata_model=DEFAULT_CALLDATA_MODEL):
    """Calldata floor/data gas for the selected pricing model."""
    zero_bytes, nonzero, tokens = calldata_token_counts(size_bytes, zero_bytes)
    model = normalize_calldata_model(calldata_model)
    if model == "7623":
        return tokens * GAS_CALLDATA_7623_FLOOR_PER_TOKEN
    if model == "7976":
        return int(size_bytes) * GAS_CALLDATA_7976_FLOOR_PER_BYTE
    return nonzero * GAS_CALLDATA_60_15_NONZERO + zero_bytes * GAS_CALLDATA_60_15_ZERO

def calldata_model_label(calldata_model=DEFAULT_CALLDATA_MODEL):
    """Short human-readable label for the active calldata pricing model."""
    model = normalize_calldata_model(calldata_model)
    if model == "7623":
        return "EIP-7623 mainnet calldata floor"
    if model == "7976":
        return "EIP-7976 draft calldata floor"
    return "legacy 60/15 calldata what-if"

def compute_total_verify_gas(size_bytes, verify_keccak_gas, zero_bytes=0, calldata_model=DEFAULT_CALLDATA_MODEL):
    """Compute total verification gas under the selected calldata model.

    Returned totals exclude the 21,000 base transaction cost and memory expansion.
    """
    model = normalize_calldata_model(calldata_model)
    zero_bytes, nonzero, tokens = calldata_token_counts(size_bytes, zero_bytes)
    standard_data_gas = calldata_standard_gas(size_bytes, zero_bytes)
    floor_gas = calldata_floor_gas(size_bytes, zero_bytes, model)

    if model == "60_15":
        total_gas = verify_keccak_gas + floor_gas
        return {
            'calldata_model': model,
            'gas_path': 'legacy',
            'zero_bytes': zero_bytes,
            'nonzero_bytes': nonzero,
            'tokens_in_calldata': tokens,
            'standard_calldata_gas': standard_data_gas,
            'calldata_floor_gas': floor_gas,
            'calldata_gas': floor_gas,
            'standard_plus_compute_gas': standard_data_gas + verify_keccak_gas,
            'total_verify_gas': total_gas,
        }

    standard_plus_compute_gas = standard_data_gas + verify_keccak_gas
    gas_path = 'floor' if floor_gas >= standard_plus_compute_gas else 'exec'
    total_gas = max(standard_plus_compute_gas, floor_gas)
    return {
        'calldata_model': model,
        'gas_path': gas_path,
        'zero_bytes': zero_bytes,
        'nonzero_bytes': nonzero,
        'tokens_in_calldata': tokens,
        'standard_calldata_gas': standard_data_gas,
        'calldata_floor_gas': floor_gas,
        'calldata_gas': floor_gas,
        'standard_plus_compute_gas': standard_plus_compute_gas,
        'total_verify_gas': total_gas,
    }

def gas_formula_legend(calldata_model=DEFAULT_CALLDATA_MODEL):
    """Legend line describing the active gas combination rule."""
    model = normalize_calldata_model(calldata_model)
    if model == "60_15":
        return "Total Gas = Compute + Calldata"
    return "Total Gas = max(StdData + Compute, Floor)"

def th_bytes(n_values):
    """Bytes hashed for tweakable hash of n values."""
    return hashbytes + tweak_size + n_values * hashbytes

def prf_bytes():
    """Bytes hashed for PRF: PKseed + SKseed + tweak."""
    return hashbytes + hashbytes + tweak_size

def hmsg_bytes():
    """Bytes hashed for Hmsg: PKseed + PKroot + R + m."""
    return 2 * hashbytes + randomness_size + msg_size

def prfmsg_bytes():
    """Bytes hashed for PRFmsg: SKprf + Opt + m + counter."""
    return hashbytes + randomness_size + msg_size + counter_size

def estimate_time_seconds(hash_calls, keccaks_per_sec=DEFAULT_KECCAKS_PER_SEC):
    """Rough CPU time estimate from keccak call counts."""
    if keccaks_per_sec <= 0:
        return float("inf")
    return float(hash_calls) / float(keccaks_per_sec)

def env_float(name, default):
    """Parse a float environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return float(value)

def env_int(name, default):
    """Parse an int environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return int(value)

def env_int_tuple(name, default):
    """Parse comma-separated ints from an environment variable."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return tuple(int(part.strip()) for part in value.split(",") if part.strip())

def env_str_tuple(name, default):
    """Parse comma-separated strings from an environment variable."""
    value = os.environ.get(name)
    if value is None:
        return default
    if value.strip() == "":
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())

def env_str(name, default):
    """Parse a string environment variable with fallback."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()

# =============================================================================
# Parameter Sets
# =============================================================================

# Single consolidated list in table output order
# Format: (scheme, q_s, h, d, a, k, w, l, swn, bold)
#   q_s: log2 of max signatures (e.g., 40 means 2^40 signatures)
#   swn: S_{w,n} target chain sum for WOTS+C
# bold=True for rows highlighted in the paper tables
PARAMETER_SETS = [
    # Table 1: 2^64 signatures (SPX)
    ("SPX", 64, 63, 7, 12, 14, 16, 35, 0, True),

    # Table 1: 2^40 signatures
    # W+C (5 rows)
    ("W+C", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C", 40, 44, 4, 16, 8, 16, 32, 304, False),
    ("W+C", 40, 44, 4, 16, 8, 256, 16, 2040, False),
    ("W+C", 40, 40, 5, 14, 11, 256, 16, 2040, False),
    ("W+C", 40, 40, 5, 14, 11, 256, 16, 2840, False),
    # W+C F+C (2 rows)
    ("W+C_F+C", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C_F+C", 40, 40, 5, 14, 11, 256, 16, 2040, True),
    # W+C P+FP (2 rows)
    ("W+C_P+FP", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C_P+FP", 40, 40, 5, 14, 11, 256, 16, 2040, True),

    # Table 1: 2^30 signatures
    # W+C (6 rows)
    ("W+C", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C", 30, 33, 3, 15, 9, 16, 32, 304, False),
    ("W+C", 30, 33, 3, 15, 9, 256, 16, 2040, False),
    ("W+C", 30, 32, 4, 14, 10, 256, 16, 2040, False),
    ("W+C", 30, 32, 4, 14, 10, 256, 16, 2840, False),
    # W+C F+C (4 rows)
    ("W+C_F+C", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C_F+C", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C_F+C", 30, 33, 3, 15, 9, 256, 16, 2040, False),
    ("W+C_F+C", 30, 32, 4, 14, 10, 256, 16, 2040, True),
    # W+C P+FP (3 rows)
    ("W+C_P+FP", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C_P+FP", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C_P+FP", 30, 32, 4, 14, 10, 256, 16, 2040, True),

    # Table 2: 2^20 signatures (grouped by h)
    # h=24
    ("W+C", 20, 24, 2, 16, 8, 16, 32, 240, False),
    ("W+C", 20, 24, 2, 16, 8, 256, 16, 2040, False),
    ("W+C_F+C", 20, 24, 2, 16, 8, 16, 32, 240, False),
    ("W+C_P+FP", 20, 24, 2, 16, 8, 16, 32, 240, False),
    # h=20
    ("W+C", 20, 20, 2, 15, 10, 256, 16, 2040, False),
    ("W+C_F+C", 20, 20, 2, 15, 10, 256, 16, 2040, False),
    ("W+C_P+FP", 20, 20, 2, 15, 10, 256, 16, 2040, False),
]

# =============================================================================
# Helper Functions
# =============================================================================

# High precision arithmetic
F = RealField(100)

# -----------------------------------------------------------------------------
# WOTS helpers
# -----------------------------------------------------------------------------

def compute_wots_l(scheme, w):
    """
    Compute WOTS chain count l based on scheme type.

    For WOTS-TW (plain): l = l1 + l2
        l1 = n / log2(w)           -- message chains
        l2 = ceil(log_w(l1*(w-1))) -- checksum chains

    For WOTS+C: l = l1 (no checksum chains, replaced by counter)
    """
    if scheme == "FORS_MERKLE":
        return 0
    if scheme == "SPX":
        l1 = hashbytes*8//log(w,2)
        l2 = ceil(log(l1*(w-1), 2)/log(w, 2))
        return l1 + l2
    else:
        return hashbytes*8//log(w,2)

def compute_nu(l: int, paramsum: int, w: int) -> int:
    """
    Compute ν (nu), the number of valid WOTS+C encodings for a given target sum.

    For WOTS+C, we need message digests whose base-w digits sum to exactly S_{w,n}.
    ν counts how many such encodings exist out of w^l total possibilities.

        ν = Σ_{j=0}^{l} (-1)^j * C(l,j) * C((S_{w,n} + l) - j*w - 1, l-1)

    Returns integer ν. Rejects parameters with no digit encoding instead of fabricating a count.
    """
    if l < 1 or w < 2 or not 0 <= paramsum <= l * (w - 1):
        raise ValueError("No digit encoding exists for these parameters")
    nu = 0
    for j in range(l + 1):
        sign = (-1) ** j
        binom1 = binomial(l, j)
        n = (paramsum + l) - j * w - 1
        binom2 = binomial(n, l - 1) if n >= l - 1 and l - 1 >= 0 else 0
        nu += sign * binom1 * binom2
    if nu == 0:
        raise ValueError("Digit encoding count is zero")
    return nu

# -----------------------------------------------------------------------------
# PORS helpers
# -----------------------------------------------------------------------------

def compute_pors_tree_geometry(k, a):
    """
    Compute PORS tree geometry.

    Returns (t, subtree_height, extra_leaves) where:
    - t: total number of PORS leaves (k * 2^a)
    - subtree_height: height of the largest power-of-2 subtree
    - extra_leaves: leaves beyond the power-of-2 subtree
    """
    t = k * (2**a)
    subtree_height = floor(log(t, 2))
    extra_leaves = t - 2**subtree_height
    return t, subtree_height, extra_leaves

def ceil_log2_int(x):
    """Ceiling of log2 for positive integers."""
    x = int(x)
    if x <= 1:
        return 0
    return int(ceil(log(x, 2)))

def log2_exp_work_from_mmax(t, k, mmax):
    """Look up log2 of expected work for PORS+FP grinding given mmax."""
    table = dict(interleave_cost_table(t, k))
    if mmax in table:
        return table[mmax]
    lowers = [m for m in table if m <= mmax]
    if not lowers:
        raise ValueError("mmax below supported range for these (t,k).")
    return table[max(lowers)]

def exp_work_from_mmax(t, k, mmax):
    """Compute expected work (attempts) for PORS+FP grinding given mmax."""
    return 2.0 ** log2_exp_work_from_mmax(t, k, mmax)

# -----------------------------------------------------------------------------
# Search/Grinding helpers
# -----------------------------------------------------------------------------

def worst_case(p, q, d, max_k=10**11):
    """
    Find minimum trials k such that P(fewer than d successes in k trials) < q.

    Used to compute worst-case search time: how many attempts until we're
    confident (with probability 1-q) that we've found d valid encodings.

    P(X < d) = Σ_{i=0}^{d-1} C(k,i) * p^i * (1-p)^(k-i), where X ~ Binomial(k, p)

    Returns smallest k where P(X < d) < q.
    """
    # Convert Sage types to Python native types
    p_float = float(p)
    q_float = float(q)
    d_int = int(d)

    def tail_prob(k):
        if k < d_int:
            return 1.0
        # binom.cdf(d-1, k, p) = P(X <= d-1) = P(X < d)
        return binom.cdf(d_int - 1, int(k), p_float)
    # Find an upper bound for k
    k_low = d_int - 1
    k_high = max(d_int, 1)
    while tail_prob(k_high) >= q_float:
        k_high *= 2
        if k_high > max_k:
            raise RuntimeError("Could not find k below given max_k; try increasing max_k.")
    # Binary search between k_low and k_high
    while k_low + 1 < k_high:
        k_mid = (k_low + k_high) // 2
        if tail_prob(k_mid) < q_float:
            k_high = k_mid
        else:
            k_low = k_mid
    return k_high

# =============================================================================
# Core Computation Functions
# =============================================================================

def compute_size(h, d, a, k, w, scheme, mmax=0):
    """
    Compute signature size in bytes.

    Signature structure:
    - Randomness R (randomness_size bytes)
    - d XMSS layers, each containing:
        - WOTS signature: l hash values
        - Auth path: h' = h/d hash values
        - Counter (for W+C variants): counter_size bytes
    - Few-time signature (FTS):
        - FORS: k leaves + k*a auth path nodes
        - FORS+C: (k-1) leaves + (k-1)*a auth path nodes (last tree omitted)
        - PORS+FP: k leaves + mmax auth set nodes

    mmax: for PORS+FP, max size of the authentication set
    """
    if scheme == "FORS_MERKLE":
        assert d == 1, "FORS_MERKLE assumes d=1"
        # Merkle auth path (h) + FORS signature + randomness
        fts_size = k*hashbytes + k*a*hashbytes
        return randomness_size + fts_size + h*hashbytes

    assert h % d == 0, "h must be divisible by d"
    has_wc = (scheme != "SPX")
    l = compute_wots_l(scheme, w)
    h_prime = h // d
    # Each XMSS layer: auth path (h') + WOTS sig (l) + optional counter
    hyper_tree_size = d*(h_prime*hashbytes + l*hashbytes + counter_size*int(has_wc))
    # fts = few-time signature (FORS, FORS+C, or PORS+FP)
    if scheme == "W+C_P+FP":
        # k revealed leaves + mmax authentication nodes
        fts_size = (k + mmax)*hashbytes
    elif scheme == "W+C_F+C":
        # k-1 trees (last tree omitted via grinding)
        fts_size = (k-1)*hashbytes + (k-1)*a*hashbytes
    else:  # Plain FORS (SPX or W+C)
        # k trees, each with 1 leaf + a auth path nodes
        fts_size = k*hashbytes + k*a*hashbytes
    return hyper_tree_size + fts_size + randomness_size


def compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a):
    """Compute mmax for PORS+FP such that signing time is close to FORS+C.

    mmax is the max size of the authentication set.
    """
    gas_th1 = evm_keccak_gas(th_bytes(1))
    gas_th1c = evm_keccak_gas(th_bytes(1) + counter_size)
    gas_th2 = evm_keccak_gas(th_bytes(2))
    gas_prf = evm_keccak_gas(prf_bytes())
    gas_hmsg = evm_keccak_gas(hmsg_bytes())
    gas_prfmsg = evm_keccak_gas(prfmsg_bytes())
    gas_thl = evm_keccak_gas(th_bytes(l))
    gas_thk1 = evm_keccak_gas(th_bytes(k-1))  # FORS+C has k-1 roots

    merkle_tree_fixed_part_time = (2**h_prime * (l*gas_prf + l*(w-1)*gas_th1 + gas_thl)) + (2**h_prime-1)*gas_th2
    hyper_tree_expected_time = d*merkle_tree_fixed_part_time + d_wots_expected_search*gas_th1c
    # Compute FORS+C time to relate PORS time in keccak gas
    fors_c_fixed_part_time = (k-1)*(2**a)*gas_prf + (k-1)*(2**a)*gas_th1 + (k-1)*(2**a-1)*gas_th2 + gas_thk1
    fors_c_expected_search_time = 2**a*(gas_hmsg + gas_prfmsg)
    fors_c_expected_total_time = fors_c_fixed_part_time + fors_c_expected_search_time
    spx_fc_expected_total_time = hyper_tree_expected_time + fors_c_expected_total_time
    # Search for mmax such that PORS time is close to FORS+C time
    t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
    pors_fixed_part_time = t*gas_prf + t*gas_th1 + ((2**subtree_height-1) + extra_leaves)*gas_th2
    mmax = (k-1)*a - ceil(350/hashbytes)
    for i in range(20):
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        pors_expected_search_time = pors_search_attempts*(gas_hmsg + gas_prfmsg)
        pors_expected_total_time = pors_fixed_part_time + pors_expected_search_time
        spx_pors_expected_total_time = hyper_tree_expected_time + pors_expected_total_time
        ratio = spx_pors_expected_total_time/spx_fc_expected_total_time
        if (ratio < 1.11 or i == 19):
            return mmax
        mmax += 1
    return mmax


def compute_signing_time(h, d, a, k, w, swn, scheme, include_worst=True):
    """
    Compute signing time in both hash calls and keccak gas.

    Returns a dict with keys:
    - 'hashes': expected signing time in keccak calls
    - 'keccak_gas': expected signing time in keccak gas (excluding calldata)
    - 'exp_search': expected search attempts
    - 'worst_search': worst-case search attempts
    - 'mmax': mmax value for PORS+FP (max authentication set size)
    """
    if scheme == "FORS_MERKLE":
        assert d == 1, "FORS_MERKLE assumes d=1"
    else:
        assert h % d == 0, "h must be divisible by d"

    has_wots = (scheme != "FORS_MERKLE")
    has_wc = (scheme not in ("SPX", "FORS_MERKLE"))

    h_prime = h // d if has_wots else h
    l = compute_wots_l(scheme, w)

    gas_th1 = evm_keccak_gas(th_bytes(1))
    gas_th1c = evm_keccak_gas(th_bytes(1) + counter_size)
    gas_th2 = evm_keccak_gas(th_bytes(2))
    gas_prf = evm_keccak_gas(prf_bytes())
    gas_hmsg = evm_keccak_gas(hmsg_bytes())
    gas_prfmsg = evm_keccak_gas(prfmsg_bytes())
    gas_thl = evm_keccak_gas(th_bytes(l)) if l > 0 else 0
    gas_thk = evm_keccak_gas(th_bytes(k))

    if has_wc:
        # WOTS+C search: find counter such that digest sums to S_{w,n}
        # Success probability p_ν = ν / w^l
        # By geometric distribution, expected attempts until success = 1/p_ν = w^l / ν
        # We need d successful searches (one per hypertree layer)
        nu = compute_nu(l, swn, w)
        d_wots_expected_search = d*ceil((w**l) / nu)
        d_wots_worst_search = worst_case(nu/(w**l), F(2)**(-30), d) if include_worst else 0
    else:
        d_wots_expected_search = 0
        d_wots_worst_search = 0

    # Message hash cost (2 hash calls: Hmsg + PRFmsg)
    h_msg = 2
    gas_msg = gas_hmsg + gas_prfmsg

    # Merkle/hypertree component
    if has_wots:
        # One XMSS tree layer with 2^h' leaves:
        #   - 2^h' WOTS keypairs, each requiring:
        #       - l PRF calls to generate secret keys
        #       - l*(w-1) chain hashes (Th1)
        #       - 1 hash to compress l public key values (Thl)
        #   - 2^h' - 1 internal Merkle tree nodes (Th2, hashing 2 children)
        h_merkle = 2**h_prime * (l + l*(w-1) + 1) + (2**h_prime - 1)
        gas_merkle = 2**h_prime * (l*gas_prf + l*(w-1)*gas_th1 + gas_thl) + (2**h_prime - 1)*gas_th2

        # Full hypertree: d layers + WOTS+C counter search overhead
        h_hyper_exp = d*h_merkle + d_wots_expected_search
        gas_hyper_exp = d*gas_merkle + d_wots_expected_search*gas_th1c
    else:
        # Single Merkle tree over FORS public keys
        h_fors_pk = k*(2**a) + k*(2**a) + k*(2**a - 1) + 1
        gas_fors_pk = k*(2**a)*gas_prf + k*(2**a)*gas_th1 + k*(2**a - 1)*gas_th2 + gas_thk
        h_hyper_exp = 2**h * h_fors_pk + (2**h - 1)
        gas_hyper_exp = 2**h * gas_fors_pk + (2**h - 1)*gas_th2

    mmax = 0
    if scheme == "FORS_MERKLE":
        return {
            'hashes': h_hyper_exp + h_msg,
            'keccak_gas': gas_hyper_exp + gas_msg,
            'exp_search': 0,
            'worst_search': 0,
            'mmax': mmax,
        }
    elif scheme == "W+C_F+C":
        # FORS+C: k-1 trees (last tree omitted, grinding ensures first leaf is selected)
        # Each tree has 2^a leaves:
        #   - 2^a PRF calls to generate leaves
        #   - 2^a hashes to compute leaf nodes (Th1)
        #   - 2^a - 1 internal nodes (Th2)
        # Plus 1 hash to compress k-1 roots
        # Grinding: search for message hash with last a bits = 0, expected 2^a attempts
        gas_thk1 = evm_keccak_gas(th_bytes(k-1))
        h_fors_fixed = (k-1)*(2**a) + (k-1)*(2**a) + (k-1)*(2**a - 1) + 1
        gas_fors_fixed = (k-1)*(2**a)*gas_prf + (k-1)*(2**a)*gas_th1 + (k-1)*(2**a - 1)*gas_th2 + gas_thk1
        fors_exp_search = 2**a
        fors_worst_search = worst_case(F(1)/F(2**a), F(2)**(-30), 1) if include_worst else 0
        h_fors_search = fors_exp_search * h_msg
        gas_fors_search = fors_exp_search * gas_msg
        return {
            'hashes': h_hyper_exp + h_fors_fixed + h_fors_search,
            'keccak_gas': gas_hyper_exp + gas_fors_fixed + gas_fors_search,
            'exp_search': d_wots_expected_search + h_fors_search,
            'worst_search': d_wots_worst_search + fors_worst_search * h_msg,
            'mmax': mmax,
        }
    elif scheme == "W+C_P+FP":
        # PORS+FP: single tree with t = k * 2^a leaves
        # Tree structure: largest power-of-2 subtree + extra leaves
        # Grinding: search for message hash where Octopus auth set size <= mmax
        t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
        # t PRF calls + t leaf hashes + internal nodes
        h_pors_fixed = 2*t + (2**subtree_height - 1) + extra_leaves
        gas_pors_fixed = t*gas_prf + t*gas_th1 + ((2**subtree_height - 1) + extra_leaves)*gas_th2
        mmax = compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a)
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        h_pors_search = pors_search_attempts * h_msg
        gas_pors_search = pors_search_attempts * gas_msg
        pors_worst_search = worst_case(F(1)/pors_search_attempts, F(2)**(-30), 1) if include_worst else 0
        return {
            'hashes': h_hyper_exp + h_pors_fixed + h_pors_search,
            'keccak_gas': gas_hyper_exp + gas_pors_fixed + gas_pors_search,
            'exp_search': d_wots_expected_search + h_pors_search,
            'worst_search': d_wots_worst_search + pors_worst_search * h_msg,
            'mmax': mmax,
        }
    else:
        # Plain FORS (SPX or W+C): k trees, each with 2^a leaves
        # No grinding, message hash directly selects k leaf indices
        h_fors_fixed = k*(2**a) + k*(2**a) + k*(2**a - 1) + 1
        gas_fors_fixed = k*(2**a)*gas_prf + k*(2**a)*gas_th1 + k*(2**a - 1)*gas_th2 + gas_thk
        return {
            'hashes': h_fors_fixed + h_msg + h_hyper_exp,
            'keccak_gas': gas_fors_fixed + gas_msg + gas_hyper_exp,
            'exp_search': d_wots_expected_search,
            'worst_search': d_wots_worst_search,
            'mmax': mmax,
        }

def compute_verification_time(h, d, a, k, w, swn, scheme, mmax=0):
    """
    Compute verification time in both hash calls and keccak gas.

    Verification involves:
    1. Hash the message (Hmsg)
    2. Verify FTS (FORS/FORS+C/PORS+FP)
    3. For each of d hypertree layers: verify WOTS signature
    4. Verify h auth path nodes up the hypertree

    mmax: for PORS+FP, max size of the authentication set
    """
    if scheme == "FORS_MERKLE":
        assert d == 1, "FORS_MERKLE assumes d=1"
    has_wots = (scheme != "FORS_MERKLE")
    has_wc = (scheme not in ("SPX", "FORS_MERKLE"))
    l = compute_wots_l(scheme, w)

    gas_th1 = evm_keccak_gas(th_bytes(1))
    gas_th1c = evm_keccak_gas(th_bytes(1) + counter_size)
    gas_th2 = evm_keccak_gas(th_bytes(2))
    gas_hmsg = evm_keccak_gas(hmsg_bytes())
    gas_prfmsg = evm_keccak_gas(prfmsg_bytes())
    gas_thl = evm_keccak_gas(th_bytes(l)) if l > 0 else 0
    gas_thk = evm_keccak_gas(th_bytes(k))

    # WOTS verification: complete each chain from signature value to public key
    if has_wots and has_wc:
        # WOTS+C: chain positions sum to S_{w,n}, so remaining steps = (w-1)*l - S_{w,n}
        # Plus: verify counter hash (Th1c) and compress public key (Thl)
        h_wots = (w-1)*l - swn + 2
        gas_wots = ((w-1)*l - swn)*gas_th1 + gas_th1c + gas_thl
    elif has_wots:  # Plain WOTS
        # Expected chain position is (w-1)/2, so expected remaining steps = (w-1)*l/2
        h_wots = (w-1)*l//2 + 1
        gas_wots = (w-1)*l//2*gas_th1 + gas_thl
    else:
        h_wots = 0
        gas_wots = 0

    # FTS verification
    if scheme == "W+C_F+C":
        # FORS+C: k-1 leaves to hash, (k-1)*a auth path nodes, 1 root compression
        gas_thk1 = evm_keccak_gas(th_bytes(k-1))
        h_fts = (k-1) + (k-1)*a + 1
        gas_fts = (k-1)*gas_th1 + (k-1)*a*gas_th2 + gas_thk1
    elif scheme == "W+C_P+FP":
        # PORS+FP: k leaves to hash, mmax auth set nodes
        h_fts = k + mmax
        gas_fts = k*gas_th1 + mmax*gas_th2
    else:  # Plain FORS (SPX or W+C, or FORS_MERKLE)
        # FORS: k leaves, k*a auth path nodes, 1 root compression
        h_fts = k + k*a + 1
        gas_fts = k*gas_th1 + k*a*gas_th2 + gas_thk

    # Total: Hmsg + FTS + d*WOTS + h auth path nodes
    return {
        'hashes': 1 + h_fts + d*h_wots + h,
        'keccak_gas': gas_hmsg + gas_fts + d*gas_wots + h*gas_th2,
    }

def estimate_contract_verify_gas(h, d, a, k, w, swn, scheme, mmax=0):
    """
    Calibrated verifier execution-gas estimate for the Solidity/Yul implementation.

    This augments the raw keccak-opcode model with loop/control/memory overhead by
    fitting a coarse operation proxy to measured verifier gas. The calibration is
    strongest for W+C_F+C and W+C_P+FP, and is used as a pragmatic whole-cost model
    for nearby schemes.
    """
    if scheme == "FORS_MERKLE":
        core = k * (a + 1) + 3 + h
        ops = core
    else:
        assert h % d == 0, "h must be divisible by d"
        l = compute_wots_l(scheme, w)
        subtree_h = h // d
        if scheme == "SPX":
            wots_verify_ops = (w - 1) * l // 2 + 1
        else:
            wots_verify_ops = (w - 1) * l - swn + 2
        hypertree_term = d * (wots_verify_ops + subtree_h)

        if scheme == "W+C_F+C":
            core = (k - 1) * (a + 1) + 3
        elif scheme == "W+C_P+FP":
            tree_height = ceil_log2_int(k * (2**a))
            core = 2 * mmax + k + PORS_CORE_TREE_H_WEIGHT * tree_height + PORS_CORE_CONST
        else:
            core = k * (a + 1) + 3
        ops = core + hypertree_term

    g = ASM_MODEL_INTERCEPT + ASM_MODEL_PER_OP * ops
    return max(0, int(round(g)))

def compute_keygen_cost(h, d, a, k, w, scheme):
    """
    Estimate keygen cost in keccak calls and keccak gas.

    This models on-device public-root generation from the secret seed.

    - For WOTS-based schemes with d=1, this is the single XMSS tree root.
    - For WOTS-based schemes with d>1, this is the top-layer XMSS root only.
      Lower-layer material is assumed to be derived lazily during signing.
    - FORS_MERKLE is only defined for d=1 and models the full Merkle root.
    """
    if scheme == "FORS_MERKLE":
        assert d == 1, "FORS_MERKLE assumes d=1"
        gas_th1 = evm_keccak_gas(th_bytes(1))
        gas_th2 = evm_keccak_gas(th_bytes(2))
        gas_prf = evm_keccak_gas(prf_bytes())
        gas_thk = evm_keccak_gas(th_bytes(k))

        h_fors_pk = k*(2**a) + k*(2**a) + k*(2**a - 1) + 1
        gas_fors_pk = k*(2**a)*gas_prf + k*(2**a)*gas_th1 + k*(2**a - 1)*gas_th2 + gas_thk
        h_merkle = 2**h * h_fors_pk + (2**h - 1)
        gas_merkle = 2**h * gas_fors_pk + (2**h - 1) * gas_th2
        return {'hashes': h_merkle, 'keccak_gas': gas_merkle}

    l = compute_wots_l(scheme, w)
    gas_th1 = evm_keccak_gas(th_bytes(1))
    gas_th2 = evm_keccak_gas(th_bytes(2))
    gas_prf = evm_keccak_gas(prf_bytes())
    gas_thl = evm_keccak_gas(th_bytes(l)) if l > 0 else 0

    h_tree = h if d == 1 else h // d
    leaves = 2**h_tree
    h_merkle = leaves * (l + l*(w-1) + 1) + (leaves - 1)
    gas_merkle = leaves * (l*gas_prf + l*(w-1)*gas_th1 + gas_thl) + (leaves - 1)*gas_th2
    return {'hashes': h_merkle, 'keccak_gas': gas_merkle}

# =============================================================================
# CSV Output
# =============================================================================

def compute_all_results():
    """Compute results for all parameter sets. Returns list of dicts."""
    results = []
    for scheme, q_s, h, d, a, k, w, _, swn, bold in PARAMETER_SETS:
        # Compute l dynamically based on scheme
        l = compute_wots_l(scheme, w)

        # Verify security level is at least 128 bits
        scheme_type = "PORS+FP" if scheme == "W+C_P+FP" else "FORS"
        security = compute_security(2**q_s, h, k, a, scheme_type)
        assert security >= 128, f"Security {security:.1f} < 128 for {scheme} q_s=2^{q_s} h={h} a={a} k={k}"

        sign = compute_signing_time(h, d, a, k, w, swn, scheme, include_worst=True)
        verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
        size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
        calldata_zero_bytes = int(size * DEFAULT_CALLDATA_ZERO_FRACTION)
        gas_model = compute_total_verify_gas(size, verify['keccak_gas'], zero_bytes=calldata_zero_bytes)
        contract_verify_gas = estimate_contract_verify_gas(h, d, a, k, w, swn, scheme, sign['mmax'])
        contract_gas_model = compute_total_verify_gas(size, contract_verify_gas, zero_bytes=calldata_zero_bytes)
        keccak_gas_per_byte = float(verify['keccak_gas']) / float(size)
        keygen = compute_keygen_cost(h, d, a, k, w, scheme)

        results.append({
            'scheme': scheme,
            'q_s': q_s,
            'h': h,
            'd': d,
            'a': a,
            'k': k,
            'w': w,
            'l': l,
            'swn': swn,
            'size': size,
            'sign_hashes': sign['hashes'],
            'sign_keccak_gas': sign['keccak_gas'],
            'exp_search': sign['exp_search'],
            'worst_search': sign['worst_search'],
            'verify_hashes': verify['hashes'],
            'verify_keccak_gas': verify['keccak_gas'],
            'verify_contract_gas': contract_verify_gas,
            'keccak_gas_per_byte': keccak_gas_per_byte,
            **gas_model,
            'total_verify_contract_gas': contract_gas_model['total_verify_gas'],
            'contract_gas_path': contract_gas_model['gas_path'],
            'contract_standard_plus_compute_gas': contract_gas_model['standard_plus_compute_gas'],
            'tx_total_keccak_gas': gas_model['total_verify_gas'] + TX_BASE_GAS,
            'tx_total_contract_gas': contract_gas_model['total_verify_gas'] + TX_BASE_GAS,
            'sign_seconds': estimate_time_seconds(sign['hashes']),
            'verify_seconds': estimate_time_seconds(verify['hashes']),
            'keygen_seconds': estimate_time_seconds(keygen['hashes']) if keygen['hashes'] else 0.0,
            'bold': bold,
        })
    return results


# =============================================================================
# EVM-focused search helpers
# =============================================================================

_SECURITY_CACHE = {}

def security_cached(q_s, h, k, a, scheme_type):
    key = (q_s, h, k, a, scheme_type)
    if key not in _SECURITY_CACHE:
        _SECURITY_CACHE[key] = compute_security(q_s, h, k, a, scheme_type)
    return _SECURITY_CACHE[key]

def scheme_security_type(scheme):
    """Map table scheme name to the security model used by security.sage."""
    return "PORS+FP" if scheme == "W+C_P+FP" else "FORS"

def add_security_report(rows, report_log_qs, tuned_log_qs):
    """Annotate already-selected rows with security at the requested signature counts."""
    for row in rows:
        scheme_type = scheme_security_type(row['scheme'])
        for q in report_log_qs:
            if q == tuned_log_qs and 'sec_tuned' in row:
                row[f'sec_{q}'] = row['sec_tuned']
            else:
                row[f'sec_{q}'] = security_cached(2**q, row['h'], row['k'], row['a'], scheme_type)
    return rows

def search_evm_candidates(
    target_security_bits=128,
    tuned_log_qs=20,
    report_log_qs=(16, 20, 30),
    gas_limit=350_000,
    sign_time_limit=2.0,
    verify_time_limit=2.0,
    min_h_d1=12,
    max_h_d1=21,
    min_h_other=12,
    max_h_other=40,
    d_values=(1, 2, 3, 4, 5, 6),
    a_values=tuple(range(8, 21)),
    k_values=tuple(range(4, 25)),
    w_values=(16, 32, 256),
    max_rows=20,
    scheme_names=("W+C", "W+C_F+C", "W+C_P+FP", "SPX", "FORS_MERKLE"),
    force_schemes=("W+C_P+FP", "W+C", "FORS_MERKLE"),
    keccaks_per_sec=DEFAULT_KECCAKS_PER_SEC,
    gas_metric="contract",
):
    """
    Search for candidate parameter sets under EVM constraints.
    Returns a list of dicts sorted by total gas then size.
    """
    tuned_qs = 2**tuned_log_qs

    wots_swn = {
        16: [240],
        32: [403],
        256: [2040, 2840],
    }

    # Include size-focused variants (WOTS+C, FORS+C, PORS+FP) alongside SPX and FORS-only.
    schemes = [
        ("W+C", True),
        ("W+C_F+C", True),
        ("W+C_P+FP", True),
        ("SPX", True),
        ("FORS_MERKLE", False),
    ]
    schemes = [entry for entry in schemes if entry[0] in set(scheme_names)]

    results = []

    for scheme, has_wots in schemes:
        for d in d_values:
            if d == 1:
                h_values = range(min_h_d1, max_h_d1 + 1)
            else:
                h_values = range(min_h_other, max_h_other + 1)
            for h in h_values:
                if has_wots and h % d != 0:
                    continue
                for a in a_values:
                    for k in k_values:
                        if has_wots:
                            for w in w_values:
                                swn_list = wots_swn[w] if scheme != "SPX" else [0]
                                for swn in swn_list:
                                    scheme_type = scheme_security_type(scheme)
                                    try:
                                        sign = compute_signing_time(h, d, a, k, w, swn, scheme, include_worst=False)
                                        verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
                                        size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
                                    except (ValueError, RuntimeError):
                                        continue

                                    calldata_zero_bytes = int(size * DEFAULT_CALLDATA_ZERO_FRACTION)
                                    gas_model = compute_total_verify_gas(size, verify['keccak_gas'], zero_bytes=calldata_zero_bytes)
                                    contract_verify_gas = estimate_contract_verify_gas(h, d, a, k, w, swn, scheme, sign['mmax'])
                                    contract_gas_model = compute_total_verify_gas(size, contract_verify_gas, zero_bytes=calldata_zero_bytes)
                                    if gas_metric == "contract":
                                        selected_total_gas = contract_gas_model['total_verify_gas']
                                        selected_tx_gas = contract_gas_model['total_verify_gas'] + TX_BASE_GAS
                                        selected_gas_path = contract_gas_model['gas_path']
                                    else:
                                        selected_total_gas = gas_model['total_verify_gas']
                                        selected_tx_gas = gas_model['total_verify_gas'] + TX_BASE_GAS
                                        selected_gas_path = gas_model['gas_path']

                                    sign_s = estimate_time_seconds(sign['hashes'], keccaks_per_sec)
                                    verify_s = estimate_time_seconds(verify['hashes'], keccaks_per_sec)
                                    if sign_s > sign_time_limit or verify_s > verify_time_limit:
                                        continue
                                    if selected_total_gas > gas_limit:
                                        continue
                                    sec_tuned = security_cached(tuned_qs, h, k, a, scheme_type)
                                    if sec_tuned < target_security_bits:
                                        continue

                                    keygen = compute_keygen_cost(h, d, a, k, w, scheme)
                                    keygen_s = estimate_time_seconds(keygen['hashes'], keccaks_per_sec) if keygen['hashes'] else 0.0

                                    results.append({
                                        'scheme': scheme,
                                        'h': h,
                                        'd': d,
                                        'a': a,
                                        'k': k,
                                        'w': w,
                                        'l': compute_wots_l(scheme, w),
                                        'swn': swn,
                                        'size': size,
                                        'sign_seconds': sign_s,
                                        'verify_seconds': verify_s,
                                        'verify_keccak_gas': verify['keccak_gas'],
                                        'verify_contract_gas': contract_verify_gas,
                                        **gas_model,
                                        'total_verify_contract_gas': contract_gas_model['total_verify_gas'],
                                        'contract_gas_path': contract_gas_model['gas_path'],
                                        'tx_total_keccak_gas': gas_model['total_verify_gas'] + TX_BASE_GAS,
                                        'tx_total_contract_gas': contract_gas_model['total_verify_gas'] + TX_BASE_GAS,
                                        'selected_total_gas': selected_total_gas,
                                        'selected_tx_gas': selected_tx_gas,
                                        'selected_gas_path': selected_gas_path,
                                        'sec_tuned': sec_tuned,
                                        'keygen_seconds': keygen_s,
                                        'mmax': sign['mmax'],
                                    })
                        else:
                            if scheme == "FORS_MERKLE" and d != 1:
                                continue
                            scheme_type = scheme_security_type(scheme)

                            w = 0
                            swn = 0
                            try:
                                sign = compute_signing_time(h, d, a, k, w, swn, scheme, include_worst=False)
                                verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
                                size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
                            except (ValueError, RuntimeError):
                                continue

                            calldata_zero_bytes = int(size * DEFAULT_CALLDATA_ZERO_FRACTION)
                            gas_model = compute_total_verify_gas(size, verify['keccak_gas'], zero_bytes=calldata_zero_bytes)
                            contract_verify_gas = estimate_contract_verify_gas(h, d, a, k, w, swn, scheme, sign['mmax'])
                            contract_gas_model = compute_total_verify_gas(size, contract_verify_gas, zero_bytes=calldata_zero_bytes)
                            if gas_metric == "contract":
                                selected_total_gas = contract_gas_model['total_verify_gas']
                                selected_tx_gas = contract_gas_model['total_verify_gas'] + TX_BASE_GAS
                                selected_gas_path = contract_gas_model['gas_path']
                            else:
                                selected_total_gas = gas_model['total_verify_gas']
                                selected_tx_gas = gas_model['total_verify_gas'] + TX_BASE_GAS
                                selected_gas_path = gas_model['gas_path']

                            sign_s = estimate_time_seconds(sign['hashes'], keccaks_per_sec)
                            verify_s = estimate_time_seconds(verify['hashes'], keccaks_per_sec)
                            if sign_s > sign_time_limit or verify_s > verify_time_limit:
                                continue
                            if selected_total_gas > gas_limit:
                                continue
                            sec_tuned = security_cached(tuned_qs, h, k, a, scheme_type)
                            if sec_tuned < target_security_bits:
                                continue

                            keygen = compute_keygen_cost(h, d, a, k, w, scheme)
                            keygen_s = estimate_time_seconds(keygen['hashes'], keccaks_per_sec) if keygen['hashes'] else 0.0

                            results.append({
                                'scheme': scheme,
                                'h': h,
                                'd': d,
                                'a': a,
                                'k': k,
                                'w': w,
                                'l': 0,
                                'swn': 0,
                                'size': size,
                                'sign_seconds': sign_s,
                                'verify_seconds': verify_s,
                                'verify_keccak_gas': verify['keccak_gas'],
                                'verify_contract_gas': contract_verify_gas,
                                **gas_model,
                                'total_verify_contract_gas': contract_gas_model['total_verify_gas'],
                                'contract_gas_path': contract_gas_model['gas_path'],
                                'tx_total_keccak_gas': gas_model['total_verify_gas'] + TX_BASE_GAS,
                                'tx_total_contract_gas': contract_gas_model['total_verify_gas'] + TX_BASE_GAS,
                                'selected_total_gas': selected_total_gas,
                                'selected_tx_gas': selected_tx_gas,
                                'selected_gas_path': selected_gas_path,
                                'sec_tuned': sec_tuned,
                                'keygen_seconds': keygen_s,
                                'mmax': sign['mmax'],
                            })

    results.sort(key=lambda r: (r['selected_total_gas'], r['size'], r['verify_seconds']))

    if not force_schemes:
        return results[:max_rows]

    forced = []
    forced_keys = set()
    for scheme in force_schemes:
        for r in results:
            if r['scheme'] == scheme:
                key = (r['scheme'], r['h'], r['d'], r['a'], r['k'], r['w'], r['swn'])
                if key not in forced_keys:
                    forced.append(r)
                    forced_keys.add(key)
                break

    remaining = []
    for r in results:
        key = (r['scheme'], r['h'], r['d'], r['a'], r['k'], r['w'], r['swn'])
        if key in forced_keys:
            continue
        remaining.append(r)

    combined = forced + remaining
    return combined[:max_rows]

def generate_research_table(max_rows=20, force_schemes=("W+C_P+FP", "W+C", "FORS_MERKLE")):
    """Generate a table of EVM-oriented candidate parameter sets."""
    tuned_log_qs = env_int("RESEARCH_TUNED_LOG_QS", 20)
    report_log_qs = env_int_tuple("RESEARCH_SECURITY_LOGS", (16, 20, 30))
    search_kwargs = {
        'max_rows': env_int("RESEARCH_MAX_ROWS", max_rows),
        'force_schemes': env_str_tuple("RESEARCH_FORCE_SCHEMES", force_schemes),
        'sign_time_limit': env_float("RESEARCH_SIGN_TIME_LIMIT", 2.0),
        'verify_time_limit': env_float("RESEARCH_VERIFY_TIME_LIMIT", 2.0),
        'gas_limit': env_int("RESEARCH_GAS_LIMIT", 350_000),
        'min_h_d1': env_int("RESEARCH_MIN_H_D1", 12),
        'max_h_d1': env_int("RESEARCH_MAX_H_D1", 21),
        'min_h_other': env_int("RESEARCH_MIN_H_OTHER", 12),
        'max_h_other': env_int("RESEARCH_MAX_H_OTHER", 40),
        'd_values': env_int_tuple("RESEARCH_D_VALUES", (1, 2, 3, 4, 5, 6)),
        'a_values': tuple(range(env_int("RESEARCH_A_MIN", 8), env_int("RESEARCH_A_MAX", 20) + 1)),
        'k_values': tuple(range(env_int("RESEARCH_K_MIN", 4), env_int("RESEARCH_K_MAX", 24) + 1)),
        'w_values': env_int_tuple("RESEARCH_W_VALUES", (16, 32, 256)),
        'scheme_names': env_str_tuple("RESEARCH_SCHEMES", ("W+C", "W+C_F+C", "W+C_P+FP", "SPX", "FORS_MERKLE")),
        'tuned_log_qs': tuned_log_qs,
        'report_log_qs': report_log_qs,
        'target_security_bits': env_float("RESEARCH_TARGET_SECURITY", 128),
        'gas_metric': env_str("RESEARCH_GAS_METRIC", "contract"),
    }
    rows = search_evm_candidates(**search_kwargs)
    if not rows:
        print("No candidates found under current constraints.")
        return
    rows = add_security_report(rows, report_log_qs, tuned_log_qs)

    print()
    print(f"EVM constraints: {calldata_model_label(DEFAULT_CALLDATA_MODEL)}, Keccak-only hash model, n=16")
    print(f"Assumptions: KECCAKS_PER_SEC={DEFAULT_KECCAKS_PER_SEC:,.0f}, CALLDATA_ZERO_FRACTION={DEFAULT_CALLDATA_ZERO_FRACTION:.2f}")
    print(f"Search: schemes={search_kwargs['scheme_names']}, d={search_kwargs['d_values']}, sign<= {search_kwargs['sign_time_limit']:.2f}s, verify<= {search_kwargs['verify_time_limit']:.2f}s, gas<= {search_kwargs['gas_limit']}, gas_metric={search_kwargs['gas_metric']}")
    print(f"Ranges: h_d1=[{search_kwargs['min_h_d1']},{search_kwargs['max_h_d1']}], h_other=[{search_kwargs['min_h_other']},{search_kwargs['max_h_other']}], a={search_kwargs['a_values']}, k={search_kwargs['k_values']}, w={search_kwargs['w_values']}")
    print(f"Security columns: {tuple(f'2^{q}' for q in report_log_qs)}")
    print()

    columns = [
        ("Scheme", 'scheme', 12, str),
        ("h", 'h', 3, str),
        ("d", 'd', 3, str),
        ("a", 'a', 3, str),
        ("k", 'k', 3, str),
        ("w", 'w', 4, str),
        ("Size", 'size', 6, str),
        ("Sign(s)", 'sign_seconds', 7, lambda x: f"{x:.2f}"),
        ("Verify(s)", 'verify_seconds', 9, lambda x: f"{x:.2f}"),
        ("Gas", 'selected_total_gas', 8, format_num),
        ("TxGas", 'selected_tx_gas', 8, format_num),
        ("Path", 'selected_gas_path', 6, str),
        ("Floor", 'calldata_floor_gas', 8, format_num),
        ("StdData", 'standard_calldata_gas', 8, format_num),
        ("ExecGas", 'verify_contract_gas', 8, format_num),
        ("Keccak", 'verify_keccak_gas', 8, format_num),
        ("Keygen(s)", 'keygen_seconds', 9, lambda x: f"{x:.2f}"),
    ]
    sec_columns = [(f"Sec@2^{q}", f"sec_{q}", 9, lambda x: f"{x:.1f}") for q in report_log_qs]
    columns = columns[:12] + sec_columns + columns[12:]

    total_width = sum(w for _, _, w, _ in columns) + len(columns) - 1
    header_line = " ".join(h.center(w) for h, _, w, _ in columns)
    print("=" * total_width)
    print(header_line)
    print("-" * total_width)

    for r in rows:
        row_parts = []
        for _, key, width, fmt in columns:
            val = fmt(r[key])
            row_parts.append(val.rjust(width) if key != 'scheme' else val.ljust(width))
        print(" ".join(row_parts))

    print()
    print(f"Legend: Gas excludes 21k base tx cost and memory expansion; TxGas = Gas + 21k; {gas_formula_legend(DEFAULT_CALLDATA_MODEL)}")
    if search_kwargs['force_schemes']:
        present = {r['scheme'] for r in rows}
        missing = [s for s in search_kwargs['force_schemes'] if s not in present]
        if missing:
            print(f"Note: No candidates found for forced schemes under current constraints: {', '.join(missing)}")
def generate_csv():
    """Generate CSV output for all parameter sets."""
    print("scheme,q_s,h,d,a,k,w,l,paramsum,size,sign_hashes,sign_keccak_gas,exp_search,worst_search,verify_hashes,verify_keccak_gas,keccak_gas_per_byte,calldata_model,gas_path,standard_calldata_gas,calldata_floor_gas,calldata_gas,total_verify_gas,sign_seconds,verify_seconds,keygen_seconds,bold")

    for r in compute_all_results():
        bold_str = "True" if r['bold'] else "False"
        print(f"{r['scheme']},2^{r['q_s']},{r['h']},{r['d']},{r['a']},{r['k']},{r['w']},{r['l']},{r['swn']},{r['size']},{r['sign_hashes']},{r['sign_keccak_gas']},{r['exp_search']},{r['worst_search']},{r['verify_hashes']},{r['verify_keccak_gas']},{r['keccak_gas_per_byte']:.2f},{r['calldata_model']},{r['gas_path']},{r['standard_calldata_gas']},{r['calldata_floor_gas']},{r['calldata_gas']},{r['total_verify_gas']},{r['sign_seconds']:.4f},{r['verify_seconds']:.4f},{r['keygen_seconds']:.4f},{bold_str}")


def format_num(n):
    """Format large numbers with K/M suffixes for readability."""
    n = float(n)  # Convert Sage types to Python float
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n/1_000:.1f}K"
    else:
        return str(int(n))


def generate_table(q_s_filter=None):
    """Generate pretty ASCII table output for parameter sets.

    Args:
        q_s_filter: If specified, only show rows with this q_s value (e.g., 40 for 2^40 sigs)
    """
    results = compute_all_results()

    if q_s_filter is not None:
        results = [r for r in results if r['q_s'] == q_s_filter]

    if not results:
        print(f"No parameter sets found for q_s=2^{q_s_filter}")
        return

    # Group results by q_s for section headers
    q_s_groups = {}
    for r in results:
        q_s_groups.setdefault(r['q_s'], []).append(r)

    # Column definitions: (header, key, width, format_func)
    columns = [
        ("Scheme", 'scheme', 12, str),
        ("h", 'h', 4, str),
        ("d", 'd', 3, str),
        ("a", 'a', 3, str),
        ("k", 'k', 3, str),
        ("w", 'w', 4, str),
        ("l", 'l', 3, str),
        ("S_wn", 'swn', 5, str),
        ("Size", 'size', 6, str),
        ("SignGas", 'sign_keccak_gas', 9, format_num),
        ("VerifyGas", 'verify_keccak_gas', 10, format_num),
        ("Path", 'gas_path', 6, str),
        ("Floor", 'calldata_floor_gas', 9, format_num),
        ("StdData", 'standard_calldata_gas', 9, format_num),
        ("TotalGas", 'total_verify_gas', 9, format_num),
        ("Gas/byte", 'keccak_gas_per_byte', 8, lambda x: f"{x:.2f}"),
    ]

    # Calculate total width
    total_width = sum(w for _, _, w, _ in columns) + len(columns) - 1

    for q_s in sorted(q_s_groups.keys(), reverse=True):
        group = q_s_groups[q_s]

        # Section header
        print()
        print("=" * total_width)
        print(f" 2^{q_s} signatures ".center(total_width, "="))
        print("=" * total_width)

        # Column headers
        header_line = " ".join(h.center(w) for h, _, w, _ in columns)
        print(header_line)
        print("-" * total_width)

        # Data rows
        for r in group:
            row_parts = []
            for _, key, width, fmt in columns:
                val = fmt(r[key])
                row_parts.append(val.rjust(width) if key != 'scheme' else val.ljust(width))
            print(" ".join(row_parts))

    print()
    print(f"Legend: Size=bytes. Gas columns exclude 21k base tx cost and memory expansion; {gas_formula_legend(DEFAULT_CALLDATA_MODEL)}")


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--table":
        # Optional: --table 40 to filter by q_s
        q_s_filter = int(sys.argv[2]) if len(sys.argv) > 2 else None
        generate_table(q_s_filter)
    elif len(sys.argv) > 1 and sys.argv[1] == "--research":
        # Optional: --research N to limit rows
        max_rows = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        generate_research_table(max_rows)
    elif len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: sage costs.sage [--table [q_s]] [--research [N]]")
        print()
        print("Options:")
        print("  (no args)      Output CSV format")
        print("  --table        Output pretty ASCII table")
        print("  --table N      Output table filtered to 2^N signatures (e.g., --table 40)")
        print("  --research     Search EVM-oriented candidates")
        print("  --research N   Limit research table to N rows")
        print("  --help         Show this help message")
    else:
        generate_csv()
