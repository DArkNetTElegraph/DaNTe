//! Wire encoding for [`dante_crypto::pow::PowProof`].
//!
//! `dante-crypto` is a leaf crate and does not know about [`crate::enc`], so the
//! codec for its `PowProof` lives here, where both are in scope. Layout:
//! `u32 m_cost_kib | u32 t_cost | u8 difficulty | [u8; 16] nonce`.

use dante_crypto::pow::{PowProof, NONCE_LEN};

use crate::enc::{Reader, WireError, Writer};

/// Append a `PowProof` to `w`.
pub fn write(w: &mut Writer, proof: &PowProof) {
    w.u32(proof.m_cost_kib)
        .u32(proof.t_cost)
        .u8(proof.difficulty)
        .fixed(&proof.nonce);
}

/// Read a `PowProof` from `r`.
pub fn read(r: &mut Reader<'_>) -> Result<PowProof, WireError> {
    let m_cost_kib = r.u32()?;
    let t_cost = r.u32()?;
    let difficulty = r.u8()?;
    let nonce = r.fixed::<NONCE_LEN>()?;
    Ok(PowProof {
        m_cost_kib,
        t_cost,
        difficulty,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let proof = PowProof {
            m_cost_kib: 65_536,
            t_cost: 3,
            difficulty: 20,
            nonce: [0xA5; 16],
        };
        let mut w = Writer::new();
        write(&mut w, &proof);
        let bytes = w.into_vec();
        assert_eq!(bytes.len(), 4 + 4 + 1 + 16);

        let mut r = Reader::new(&bytes);
        assert_eq!(read(&mut r).unwrap(), proof);
        r.finish().unwrap();
    }

    #[test]
    fn truncated_input_errors() {
        let mut r = Reader::new(&[0, 0, 0, 1]);
        assert!(read(&mut r).is_err());
    }
}
