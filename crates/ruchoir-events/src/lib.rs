//! The format of Ruchoir's server-to-server events, and of the frame the hub pushes to clients.
//!
//! Two kinds of messages leave a Ruchoir service and are read by code that did not write them:
//!
//! - [`event`]: an [`Event`] one service tells others about (a file deleted in the drive, an
//!   account deleted in Propolis). It carries an identifier, so handling it twice changes nothing,
//!   and it is signed by its emitter ([`signature`], ADR 0006 of `Ruchoir/.github`).
//! - [`frame`]: a [`ClientFrame`] the hub pushes to connected pages and apps, and the
//!   [`Publication`] a product hands the hub to get it delivered to the audience it computed
//!   (ADR 0003 of `Ruchoir/.github`).
//! - [`grant`]: a product's short grant over a file another product keeps for it, signed with its
//!   event key, checked without calling it.
//!
//! Nothing here knows a product: the event kinds, their payloads, the frame types and what a scope
//! means all belong to the product that emits them. Events travel through the hub (ADR 0015); this crate
//! only fixes what travels.

pub mod event;
pub mod frame;
pub mod grant;
pub mod signature;

pub use event::{Event, Kind, KindError};
pub use frame::{ClientFrame, Publication, FRAME_VERSION};
pub use signature::{
    sign, verify, verify_and_parse, HeaderError, KeyError, PublicKeys, SignatureHeader,
    SignedEvent, SigningKey, VerifyError, SIGNATURE_HEADER,
};
