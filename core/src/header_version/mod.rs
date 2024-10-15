use codec::{Decode, Encode};
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_runtime_interface::pass_by::PassByCodec};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode)]
#[cfg_attr(feature = "runtime", derive(PassByCodec, TypeInfo))]
pub enum HeaderVersion {
	V3 = 2, // Current one
}
