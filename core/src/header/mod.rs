#[cfg(feature = "runtime")]
pub mod extension;
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "runtime")]
pub use extension::HeaderExtension;

use codec::{Decode, Encode};
use scale_info::TypeInfo;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub enum HeaderVersion {
	V3 = 2, // Current one
	V4 = 3, // Next version
}
