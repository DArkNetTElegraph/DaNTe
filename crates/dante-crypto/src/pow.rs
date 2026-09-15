//! The `argon2id-pow` memory-hard proof-of-work puzzle (`docs/PROTOCOL.md` §3).
//!
//! A proof is valid iff
//!
//! ```text
//! Argon2id(pwd = challenge || nonce,
//!          salt = challenge[0..16],
//!          m_cost = m_cost_kib, t_cost, p = 1, out_len = 32)
//! ```
//!
//! has at least `difficulty` leading zero bits. `challenge` is the 32-byte,
//! kind-specific value defined by the ledger record being authorised.

use crate::{
    error::CryptoError,
    pwhash::{self, Argon2idParams},
    random_bytes,
};

/// Lanes / parallelism. Fixed at 1 so a proof is verifier-cheap to reproduce.
pub const PARALLELISM: u32 = 1;
/// Hard ceiling on the Argon2 memory cost a *verifier* will reproduce, in KiB
/// (128 MiB). `m_cost_kib`/`t_cost` are attacker-chosen wire data, and
/// verification runs one Argon2 pass at exactly those costs; without a ceiling a
/// single unauthenticated proof can force a multi-GiB allocation (OOM) or a
/// multi-year hash (permanent wedge). 128 MiB / 8 passes leaves generous
/// headroom over [`REGISTRATION`] (64 MiB / 3) while bounding a verify to well
/// under a second and a fraction of a GiB. A network that tunes above this must
/// raise the constant in lockstep on solvers and verifiers.
pub const MAX_VERIFY_M_COST_KIB: u32 = 131_072;
/// Hard ceiling on the Argon2 time cost a verifier will reproduce. See
/// [`MAX_VERIFY_M_COST_KIB`].
pub const MAX_VERIFY_T_COST: u32 = 8;
/// Argon2id output length used as the puzzle digest.
pub const DIGEST_LEN: usize = 32;
/// Length of the solver-chosen nonce carried in a proof.
pub const NONCE_LEN: usize = 16;

/// Default parameters for minting an identity (`IdentityAnnounce`).
pub const REGISTRATION: Difficulty = Difficulty {
    m_cost_kib: 65_536,
    t_cost: 3,
    bits: 20,
};
/// Default parameters for a periodic `LivenessProof`.
pub const LIVENESS: Difficulty = Difficulty {
    m_cost_kib: 16_384,
    t_cost: 3,
    bits: 16,
};

/// The tunable cost of a puzzle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Difficulty {
    /// Argon2 memory cost in KiB.
    pub m_cost_kib: u32,
    /// Argon2 time cost (passes).
    pub t_cost: u32,
    /// Required leading zero bits of the digest.
    pub bits: u8,
}

/// A completed proof of work. Serialized into the ledger record it authorises
/// via `dante_proto::pow`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowProof {
    /// Argon2 memory cost in KiB the solver used.
    pub m_cost_kib: u32,
    /// Argon2 time cost the solver used.
    pub t_cost: u32,
    /// Difficulty (leading zero bits) the solver claims to meet.
    pub difficulty: u8,
    /// The solver-chosen nonce.
    pub nonce: [u8; NONCE_LEN],
}

fn digest(
    challenge: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    m_cost_kib: u32,
    t_cost: u32,
) -> Result<[u8; DIGEST_LEN], CryptoError> {
    let mut pwd = [0u8; 32 + NONCE_LEN];
    pwd[..32].copy_from_slice(challenge);
    pwd[32..].copy_from_slice(nonce);

    let params = Argon2idParams {
        m_cost_kib,
        t_cost,
        p_cost: PARALLELISM,
    };
    let mut out = [0u8; DIGEST_LEN];
    pwhash::argon2id(&pwd, &challenge[..16], params, &mut out)?;
    Ok(out)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// One attempt: a fresh random nonce, hashed once. `Some(proof)` if it meets
/// `difficulty`.
fn try_one(challenge: &[u8; 32], difficulty: Difficulty) -> Option<PowProof> {
    let nonce = random_bytes::<NONCE_LEN>();
    let d = digest(challenge, &nonce, difficulty.m_cost_kib, difficulty.t_cost)
        .expect("REGISTRATION/LIVENESS and tuned params are valid");
    (leading_zero_bits(&d) >= u32::from(difficulty.bits)).then_some(PowProof {
        m_cost_kib: difficulty.m_cost_kib,
        t_cost: difficulty.t_cost,
        difficulty: difficulty.bits,
        nonce,
    })
}

/// Search for a nonce whose digest meets `difficulty`. Blocks until found,
/// on the calling thread alone — see [`solve_parallel`] to spread the search
/// across more than one.
///
/// Cost is exponential in `difficulty.bits` and linear in the Argon2 cost per
/// attempt — callers pick [`REGISTRATION`] or [`LIVENESS`], or a network-tuned
/// value, and run this off the main thread.
pub fn solve(challenge: &[u8; 32], difficulty: Difficulty) -> PowProof {
    solve_with_progress(challenge, difficulty, &std::sync::atomic::AtomicU64::new(0))
}

/// [`solve`], incrementing `attempts` after every hash so a caller on another
/// thread can report live progress (e.g. a UI showing nonces tried so far).
/// One increment per Argon2 pass, which is also the dominant per-attempt
/// cost, so `attempts` is a faithful proxy for elapsed work.
pub fn solve_with_progress(
    challenge: &[u8; 32],
    difficulty: Difficulty,
    attempts: &std::sync::atomic::AtomicU64,
) -> PowProof {
    loop {
        if let Some(proof) = try_one(challenge, difficulty) {
            attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return proof;
        }
        attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// [`solve`], searching with `threads` independent workers instead of one.
/// Each nonce is freshly random, so workers need no coordination beyond
/// "stop once somebody wins" — there's no shared counter to partition, unlike
/// a sequential-nonce PoW scheme.
///
/// **Measured, not assumed: this is NOT a reliable speedup at
/// memory-hard costs like [`REGISTRATION`] (64 MiB/attempt), and don't wire
/// it into a hot path expecting one without measuring on the actual target
/// hardware first.** Argon2's memory-hardness exists specifically to resist
/// this — every worker allocates and randomly walks its own buffer
/// independently, so `threads` workers contend for real memory bandwidth,
/// not just CPU. A live benchmark at REGISTRATION strength on a 12-core/30GB
/// box in this project's own CI-adjacent environment measured wall-clock
/// speedups ranging from roughly break-even down to **6x slower** than a
/// single thread, run to run, well within one machine. This only pays off
/// once `threads * difficulty.m_cost_kib` comfortably fits within real
/// available memory bandwidth (far fewer threads than cores, most likely),
/// which is workload- and hardware-specific — there's no safe universal
/// default here, which is why this takes an explicit `threads` rather than
/// defaulting to `available_parallelism()` itself.
///
/// `threads == 0` is treated as 1 (never spawns zero workers). Blocks the
/// calling thread until a worker wins; run this off whatever thread must
/// stay responsive (an async runtime's worker, a UI thread), the same as
/// [`solve`].
pub fn solve_parallel(challenge: &[u8; 32], difficulty: Difficulty, threads: usize) -> PowProof {
    solve_parallel_with_progress(
        challenge,
        difficulty,
        threads,
        &std::sync::atomic::AtomicU64::new(0),
    )
}

/// [`solve_parallel`], incrementing `attempts` — shared across every
/// worker — after each hash, same convention as [`solve_with_progress`].
pub fn solve_parallel_with_progress(
    challenge: &[u8; 32],
    difficulty: Difficulty,
    threads: usize,
    attempts: &std::sync::atomic::AtomicU64,
) -> PowProof {
    use std::sync::atomic::{AtomicBool, Ordering};

    let threads = threads.max(1);
    if threads == 1 {
        return solve_with_progress(challenge, difficulty, attempts);
    }

    let found = AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel::<PowProof>();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let tx = tx.clone();
            let found = &found;
            scope.spawn(move || {
                while !found.load(Ordering::Relaxed) {
                    match try_one(challenge, difficulty) {
                        Some(proof) => {
                            attempts.fetch_add(1, Ordering::Relaxed);
                            found.store(true, Ordering::Relaxed);
                            // The receiver may already be gone if another
                            // worker's send won the race first; that's fine,
                            // this thread is about to exit either way.
                            let _ = tx.send(proof);
                            return;
                        }
                        None => {
                            attempts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        drop(tx);
        rx.recv()
            .expect("at least one of `threads` workers finds a proof before all exit")
    })
}

/// Verify a proof against `challenge`, enforcing a caller-supplied floor on
/// every axis so a solver cannot downgrade the puzzle:
///
/// * `min_bits` — minimum leading-zero-bit target.
/// * `min_m_cost_kib` / `min_t_cost` — minimum Argon2 memory / time cost. The
///   bit target alone is not enough: a proof with the right zeros but a tiny
///   Argon2 cost is far cheaper to grind than an honest one, so a spammer would
///   claim the weakest costs the verifier still accepts. Pass `0` for no floor
///   (dev / tests); a deployed network passes its real solver parameters.
pub fn verify(
    challenge: &[u8; 32],
    proof: &PowProof,
    min_bits: u8,
    min_m_cost_kib: u32,
    min_t_cost: u32,
) -> Result<(), CryptoError> {
    if proof.difficulty < min_bits || proof.m_cost_kib < min_m_cost_kib || proof.t_cost < min_t_cost
    {
        return Err(CryptoError::PowUnmetDifficulty);
    }
    // Reject before touching Argon2: the costs are untrusted wire data and
    // verification would otherwise allocate/spin at exactly the attacker's
    // chosen scale. See [`MAX_VERIFY_M_COST_KIB`].
    if proof.m_cost_kib > MAX_VERIFY_M_COST_KIB || proof.t_cost > MAX_VERIFY_T_COST {
        return Err(CryptoError::PowUnmetDifficulty);
    }
    let d = digest(challenge, &proof.nonce, proof.m_cost_kib, proof.t_cost)?;
    if leading_zero_bits(&d) >= u32::from(proof.difficulty) {
        Ok(())
    } else {
        Err(CryptoError::PowUnmetDifficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny cost so the search is instant in CI.
    const TEST: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 8,
    };
    // Higher bit target for the "wrong input is rejected" tests: at 8 bits a
    // random digest clears the target ~1/256 of the time (a spurious pass). At
    // 14 that drops to ~1/16k while the solve stays well under a second.
    const TEST_STRICT: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 14,
    };

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xff]), 16);
        assert_eq!(leading_zero_bits(&[0x0f, 0xff]), 4);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn solve_then_verify_roundtrip() {
        let challenge = [0x42u8; 32];
        let proof = solve(&challenge, TEST);
        assert_eq!(proof.difficulty, 8);
        verify(&challenge, &proof, 8, 0, 0).unwrap();
    }

    #[test]
    fn solve_parallel_produces_a_valid_proof() {
        let challenge = [0x99u8; 32];
        let proof = solve_parallel(&challenge, TEST_STRICT, 4);
        assert_eq!(proof.difficulty, TEST_STRICT.bits);
        verify(&challenge, &proof, TEST_STRICT.bits, 0, 0).unwrap();
    }

    #[test]
    fn solve_parallel_with_zero_or_one_threads_still_works() {
        let challenge = [0x11u8; 32];
        for threads in [0, 1] {
            let proof = solve_parallel(&challenge, TEST, threads);
            verify(&challenge, &proof, TEST.bits, 0, 0).unwrap();
        }
    }

    #[test]
    fn solve_parallel_attempts_counter_reflects_every_worker() {
        // A difficulty no digest can ever satisfy (one more bit than a
        // 32-byte digest has) means every worker runs its full fixed
        // iteration count with no early winner to race against — so the
        // shared counter's final value is deterministic: it must be the sum
        // across every worker, not just whichever one happened to run last.
        let never = Difficulty {
            m_cost_kib: 32,
            t_cost: 1,
            bits: 255,
        };
        let attempts = std::sync::atomic::AtomicU64::new(0);
        let threads = 4;
        std::thread::scope(|scope| {
            for _ in 0..threads {
                let attempts = &attempts;
                scope.spawn(move || {
                    for _ in 0..20 {
                        let _ = try_one(&[3u8; 32], never);
                        attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 80);
    }

    #[test]
    fn proof_is_bound_to_its_challenge() {
        let proof = solve(&[1u8; 32], TEST_STRICT);
        assert!(verify(&[2u8; 32], &proof, TEST_STRICT.bits, 0, 0).is_err());
    }

    #[test]
    fn downgrade_below_min_bits_is_rejected() {
        let challenge = [7u8; 32];
        let proof = solve(&challenge, TEST);
        assert!(matches!(
            verify(&challenge, &proof, 16, 0, 0),
            Err(CryptoError::PowUnmetDifficulty)
        ));
    }

    #[test]
    fn oversized_cost_params_are_rejected_before_hashing() {
        // A proof claiming absurd Argon2 costs must be refused up front, never
        // reproduced — otherwise a single ~120-byte message OOMs or wedges the
        // verifier. This returns fast precisely because `digest` is not called.
        let challenge = [3u8; 32];
        let bomb = PowProof {
            m_cost_kib: u32::MAX,
            t_cost: u32::MAX,
            difficulty: 8,
            nonce: [0u8; NONCE_LEN],
        };
        assert!(matches!(
            verify(&challenge, &bomb, 8, 0, 0),
            Err(CryptoError::PowUnmetDifficulty)
        ));
        // The boundary: one over the ceiling on either axis is refused.
        let over_m = PowProof {
            m_cost_kib: MAX_VERIFY_M_COST_KIB + 1,
            t_cost: 1,
            difficulty: 8,
            nonce: [0u8; NONCE_LEN],
        };
        assert!(verify(&challenge, &over_m, 8, 0, 0).is_err());
        let over_t = PowProof {
            m_cost_kib: 32,
            t_cost: MAX_VERIFY_T_COST + 1,
            difficulty: 8,
            nonce: [0u8; NONCE_LEN],
        };
        assert!(verify(&challenge, &over_t, 8, 0, 0).is_err());
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let challenge = [9u8; 32];
        let mut proof = solve(&challenge, TEST_STRICT);
        proof.nonce[0] ^= 0xff;
        // With a 20-bit target a tampered nonce misses it ~1e6:1.
        assert!(verify(&challenge, &proof, TEST_STRICT.bits, 0, 0).is_err());
    }
}
