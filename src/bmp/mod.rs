//! BMP export: focl forwards what its sessions see to a monitoring station.
//!
//! focl is a speaker, not a router, so the exporter here answers one question: what does a
//! station such as `bgpviews` need in order to archive this daemon's sessions? The answer is a
//! BMP (RFC 7854) stream in which focl plays the exporter's role and dials the station.
//!
//! The encoder is in [`wire`] and is pure; [`export`] owns the socket, the reconnect and the
//! liveness timer. Two properties of BMP shape the design and are easy to get wrong:
//!
//! - **BMP has no keepalive and no hold timer.** The exporter dials, and after that only data
//!   frames flow. A station therefore cannot tell an idle peer from a dead exporter, which is
//!   why [`export`] sends a Statistics Report on a timer: it is the only liveness signal the
//!   protocol offers.
//! - **The station replays nothing.** Every frame is written to its archive as it arrives, so
//!   the exporter owns ordering: a Peer Up must precede that peer's Route Monitoring on the same
//!   connection, and a session that ends must be closed with a Peer Down rather than left to look
//!   quiet.

pub mod export;
pub mod wire;

pub use export::{BmpExporter, ExportHandle};
pub use wire::{now_micros, PeerHeader};
