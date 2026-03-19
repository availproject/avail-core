#[cfg(feature = "runtime")]
pub mod extended_header;
#[cfg(feature = "runtime")]
pub use extended_header::ExtendedHeader;

#[cfg(feature = "runtime")]
pub mod extended_block;
#[cfg(feature = "runtime")]
pub use extended_block::ExtendedBlock;
