use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use crate::from_substrate::HexDisplay;
#[cfg(feature = "serde")]
use scale_info::prelude::format;

/// Simple blob to hold an extrinsic without committing to its format and ensure it is serialized
/// correctly.
///
/// **NOTE**: It a customized version of `sp_runtime::Opaque` where inner `Vec` is public.
#[derive(PartialEq, Eq, Clone, Default, Encode, Decode, TypeInfo)]
pub struct OpaqueExtrinsic(pub Vec<u8>);

impl OpaqueExtrinsic {
	/// Convert an encoded extrinsic to an `OpaqueExtrinsic`.
	/// # Errors
	/// A decodification error if `bytes` does not follow the `Vec<u8>` encoded schema.
	pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, codec::Error> {
		Self::decode(&mut bytes)
	}
}

impl sp_std::fmt::Debug for OpaqueExtrinsic {
	#[cfg(feature = "std")]
	fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(fmt, "{}", HexDisplay(&self.0))
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for OpaqueExtrinsic {
	fn serialize<S>(&self, seq: S) -> Result<S::Ok, S::Error>
	where
		S: ::serde::Serializer,
	{
		codec::Encode::using_encoded(&self.0, |bytes| {
			::impl_serde::serialize::serialize(bytes, seq)
		})
	}
}

#[cfg(feature = "serde")]
impl<'a> ::serde::Deserialize<'a> for OpaqueExtrinsic {
	fn deserialize<D>(de: D) -> Result<Self, D::Error>
	where
		D: ::serde::Deserializer<'a>,
	{
		let r = ::impl_serde::serialize::deserialize(de)?;
		Decode::decode(&mut &r[..])
			.map_err(|e| ::serde::de::Error::custom(format!("Decode error: {e}")))
	}
}

#[cfg(feature = "runtime")]
impl sp_runtime::traits::Extrinsic for OpaqueExtrinsic {
	type Call = ();
	type SignaturePayload = ();
}

impl AsRef<[u8]> for OpaqueExtrinsic {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}
