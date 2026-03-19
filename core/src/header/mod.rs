#[cfg(feature = "runtime")]
pub mod extension;
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "runtime")]
pub use extension::HeaderExtension;
#[cfg(feature = "runtime")]
pub use runtime::ExtendedHeader;

#[derive(Debug, Clone, Copy, Eq, PartialEq, codec::Encode, codec::Decode, scale_info::TypeInfo)]
pub enum HeaderVersion {
	V3 = 2, // Current one
	V4 = 3, // Next version
}
