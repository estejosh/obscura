//! # obscura
//!
//! Safe secure transport protocol for communications, platform agnostic.
//!
//! **Pre-alpha:** the protocol is not specified yet and nothing here should be
//! relied on for security. See `DESIGN.md` and `THREAT_MODEL.md` in the
//! repository root for direction and constraints.
//!
//! Implemented so far:
//!
//! - [`frame`]: length-prefixed message framing with hard bounds and
//!   fail-closed semantics.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod frame;

pub use frame::{Decoder, FrameError};
