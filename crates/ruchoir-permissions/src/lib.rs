//! The permission model shared by every Ruchoir product (ADR 0001 of this repository).
//!
//! - [`catalogue`]: the named permissions, as a `u64` set. A name is never renamed or removed and
//!   its position never moves (`the_permission_catalogue_only_grows`).
//! - [`engine`]: the pure resolution, with an explain trace: owner standing, base role and roles,
//!   guest ceiling, rules level by level, private lock, author, archived.
//! - [`system_roles`]: what the system roles hold, and the guest ceiling.
//!
//! Nothing here reads a database: the products load people, roles and rules and hand them to the
//! engine.

pub mod catalogue;
pub mod engine;
pub mod system_roles;
