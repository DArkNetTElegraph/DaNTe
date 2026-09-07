//! [`Content`] — the application payload carried *inside* the ratchet (i.e. the
//! plaintext that [`crate::Session::encrypt`] seals). Distinct from
//! [`crate::Packet`], which is the transport framing (first contact vs. a
//! subsequent message).

use dante_proto::enc::{Reader, WireError, Writer};

use crate::file::FileManifest;

/// A decrypted direct-message payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// A UTF-8 text message.
    Text(String),
    /// A file offer: the manifest travels here; the ciphertext chunks are
    /// fetched separately from the relay blob store.
    File(FileManifest),
    /// A channel-control message (invite, sender-key exchange). The bytes are
    /// opaque to `dante-dm`; `dante-core` defines their shape.
    Channel(Vec<u8>),
}

impl Content {
    /// Encode with a 1-byte discriminant.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Content::Text(s) => {
                w.u8(1).string(s);
            }
            Content::File(m) => {
                w.u8(2).bytes(&m.encode());
            }
            Content::Channel(b) => {
                w.u8(3).bytes(b);
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let out = match r.u8()? {
            1 => Content::Text(r.string()?),
            2 => Content::File(FileManifest::decode(r.bytes()?)?),
            3 => Content::Channel(r.bytes()?.to_vec()),
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "dm::Content",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use dante_identity::Identity;

    use super::*;

    #[test]
    fn text_roundtrip() {
        let c = Content::Text("hello".into());
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn file_roundtrip() {
        let id = Identity::generate(0);
        let (m, _) = FileManifest::build(&id, "a.bin", &[1u8; 1000]);
        let c = Content::File(m);
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn bad_tag_rejected() {
        assert!(Content::decode(&[9]).is_err());
    }
}
