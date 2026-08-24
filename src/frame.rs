//! Length-prefixed message framing.
//!
//! The wire format is deliberately minimal: a 4-byte big-endian unsigned
//! length prefix followed by exactly that many opaque payload bytes.
//!
//! ```text
//! +---------------+--------------------+
//! | len: u32 (BE) | payload (`len` B)  |
//! +---------------+--------------------+
//! ```
//!
//! Design rules (see `THREAT_MODEL.md`, goals G2/G5):
//!
//! - A maximum frame length is enforced on **both** sides. A hostile length
//!   prefix is rejected *before* any allocation for that frame takes place;
//!   legitimate frames grow their buffers incrementally as bytes arrive, so
//!   memory use never exceeds bytes actually received.
//! - Errors are fatal for the session. Callers must not continue feeding a
//!   decoder after it returns [`FrameError`].

use core::fmt;

/// Default maximum payload length per frame: 64 KiB.
pub const DEFAULT_MAX_FRAME_LEN: u32 = 64 * 1024;

/// Size in bytes of the length prefix.
pub const HEADER_LEN: usize = 4;

/// Framing failures. Every variant is fatal for the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Encoding was attempted with a payload larger than the allowed maximum.
    PayloadTooLarge {
        /// The offending payload length in bytes.
        len: usize,
        /// The configured maximum frame length in bytes.
        max: u32,
    },
    /// The peer announced a frame longer than the allowed maximum.
    ///
    /// Raised as soon as the full header is seen and before allocating any
    /// buffer for the announced payload.
    FrameTooLong {
        /// The announced frame length in bytes.
        len: u32,
        /// The configured maximum frame length in bytes.
        max: u32,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::PayloadTooLarge { len, max } => {
                write!(
                    f,
                    "payload of {len} bytes exceeds maximum frame length of {max} bytes"
                )
            }
            FrameError::FrameTooLong { len, max } => {
                write!(
                    f,
                    "peer announced frame of {len} bytes exceeds maximum of {max} bytes"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Appends one framed message to `out`: a [`HEADER_LEN`]-byte big-endian
/// length prefix followed by `payload`.
///
/// Fails without writing anything if `payload` is empty-eligible but larger
/// than `max_frame_len`, or does not fit in a `u32`.
pub fn encode_into(
    payload: &[u8],
    out: &mut Vec<u8>,
    max_frame_len: u32,
) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge {
        len: payload.len(),
        max: max_frame_len,
    })?;
    if len > max_frame_len {
        return Err(FrameError::PayloadTooLarge {
            len: payload.len(),
            max: max_frame_len,
        });
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes one framed message into a fresh buffer using
/// [`DEFAULT_MAX_FRAME_LEN`].
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    encode_into(payload, &mut out, DEFAULT_MAX_FRAME_LEN)?;
    Ok(out)
}

/// Incremental decoder for the framed stream format.
///
/// Feed it arbitrary chunks via [`Decoder::feed`]; every call returns all
/// frames completed by that chunk, so frames may arrive split across any
/// number of writes and multiple frames may share one write.
#[derive(Debug)]
pub struct Decoder {
    max_frame_len: u32,
    state: State,
}

#[derive(Debug)]
enum State {
    Header {
        buf: [u8; HEADER_LEN],
        filled: usize,
    },
    Payload {
        total: u32,
        buf: Vec<u8>,
    },
}

impl Decoder {
    /// Creates a decoder that rejects frames longer than `max_frame_len`.
    pub fn new(max_frame_len: u32) -> Self {
        Decoder {
            max_frame_len,
            state: State::Header {
                buf: [0; HEADER_LEN],
                filled: 0,
            },
        }
    }

    /// Creates a decoder using [`DEFAULT_MAX_FRAME_LEN`].
    pub fn new_default() -> Self {
        Decoder::new(DEFAULT_MAX_FRAME_LEN)
    }

    /// The configured maximum frame length in bytes.
    pub fn max_frame_len(&self) -> u32 {
        self.max_frame_len
    }

    /// Consumes stream bytes and returns every frame completed by this chunk.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] if the peer violates the framing rules. The
    /// decoder must then be discarded; the session is unrecoverable.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut frames = Vec::new();
        for byte in data.iter().copied() {
            match &mut self.state {
                State::Header { buf, filled } => {
                    buf[*filled] = byte;
                    *filled += 1;
                    if *filled == HEADER_LEN {
                        let total = u32::from_be_bytes(*buf);
                        if total > self.max_frame_len {
                            return Err(FrameError::FrameTooLong {
                                len: total,
                                max: self.max_frame_len,
                            });
                        }
                        self.state = if total == 0 {
                            frames.push(Vec::new());
                            State::Header {
                                buf: [0; HEADER_LEN],
                                filled: 0,
                            }
                        } else {
                            State::Payload {
                                total,
                                buf: Vec::new(),
                            }
                        };
                    }
                }
                State::Payload { total, buf } => {
                    buf.push(byte);
                    // Compare through u64: safe on targets where usize < u32.
                    if buf.len() as u64 == u64::from(*total) {
                        frames.push(core::mem::take(buf));
                        self.state = State::Header {
                            buf: [0; HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
            }
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small deterministic PRNG so chunked-delivery tests need no dependency.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn roundtrip_single_frame() {
        let payloads: [&[u8]; 4] = [
            b"",
            b"a",
            b"hello, world",
            &[0xff; DEFAULT_MAX_FRAME_LEN as usize],
        ];
        for payload in payloads {
            let encoded = encode(payload).expect("within default limit");
            let got = Decoder::new_default().feed(&encoded).expect("valid stream");
            assert_eq!(got, vec![payload]);
        }
    }

    #[test]
    fn concatenated_frames_decode_in_order() {
        let payloads: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8; i * 137 % 1000]).collect();
        let mut stream = Vec::new();
        for p in &payloads {
            encode_into(p, &mut stream, DEFAULT_MAX_FRAME_LEN).unwrap();
        }
        assert_eq!(Decoder::new_default().feed(&stream).unwrap(), payloads);
    }

    #[test]
    fn arbitrary_chunk_splits_deliver_identical_frames() {
        let payloads: Vec<Vec<u8>> = (0..32)
            .map(|i| vec![(i * 31) as u8; (i * 61) % 512])
            .collect();
        let mut stream = Vec::new();
        for p in &payloads {
            encode_into(p, &mut stream, DEFAULT_MAX_FRAME_LEN).unwrap();
        }

        let mut rng = Xorshift(0x0b5c_u64);
        let mut decoder = Decoder::new_default();
        let mut decoded = Vec::new();
        let mut rest = &stream[..];
        while !rest.is_empty() {
            let take = 1 + rng.below(rest.len());
            decoded.append(&mut decoder.feed(&rest[..take]).unwrap());
            rest = &rest[take..];
        }
        assert_eq!(decoded, payloads);
    }

    #[test]
    fn zero_length_frames_are_allowed() {
        let encoded = encode(b"").unwrap();
        assert_eq!(&encoded, &[0, 0, 0, 0]);
        assert_eq!(
            Decoder::new_default().feed(&encoded).unwrap(),
            vec![Vec::<u8>::new()]
        );
    }

    #[test]
    fn encode_rejects_oversize_payload() {
        let err = encode_into(&[0; 65], &mut Vec::new(), 64).unwrap_err();
        assert_eq!(err, FrameError::PayloadTooLarge { len: 65, max: 64 });
    }

    #[test]
    fn decode_rejects_oversize_announcement_before_allocation() {
        let mut decoder = Decoder::new(64);
        // Announce ~4 GiB; only the header has arrived.
        let err = decoder.feed(&[0xff, 0xff, 0xff, 0xf0]).unwrap_err();
        assert_eq!(
            err,
            FrameError::FrameTooLong {
                len: 0xffff_fff0,
                max: 64
            }
        );
    }

    #[test]
    fn oversize_announcement_is_rejected_only_once_header_is_complete() {
        let mut decoder = Decoder::new(64);
        assert!(decoder.feed(&[0xff, 0xff]).unwrap().is_empty());
        assert!(matches!(
            decoder.feed(&[0xff, 0x01]),
            Err(FrameError::FrameTooLong { .. })
        ));
    }

    #[test]
    fn max_frame_len_zero_accepts_only_empty_frames() {
        let mut decoder = Decoder::new(0);
        assert_eq!(decoder.max_frame_len(), 0);
        assert_eq!(
            decoder.feed(&encode(b"").unwrap()).unwrap(),
            vec![Vec::<u8>::new()]
        );
        assert!(decoder.feed(&[0, 0, 0, 1, b'x']).is_err());
    }

    #[test]
    fn error_display_mentions_lengths() {
        let err = FrameError::FrameTooLong { len: 5, max: 4 };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("4"));
    }
}
