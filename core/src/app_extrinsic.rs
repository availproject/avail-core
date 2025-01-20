use crate::traits::{GetAppId, GetDaCommitments};
#[cfg(feature = "runtime")]
use codec::Codec;
use codec::{Decode, Encode};
use derive_more::Constructor;
use scale_info::prelude::string::String;
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

use crate::{AppId, DaCommitments};

/// Raw Extrinsic with application id.
#[derive(Clone, TypeInfo, Default, Encode, Decode, RuntimeDebug, Constructor)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AppExtrinsic {
	pub app_id: AppId,
	#[cfg_attr(
		feature = "serde",
		serde(
			serialize_with = "serialize_da_commitments",
			deserialize_with = "deserialize_da_commitments"
		)
	)]
	pub da_commitments: DaCommitments,
	#[cfg_attr(feature = "serde", serde(with = "hex"))]
	pub data: Vec<u8>,
}

#[cfg(feature = "serde")]
fn serialize_da_commitments<S>(
	da_commitments: &DaCommitments,
	serializer: S,
) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let hex_strings: Vec<String> = da_commitments
		.iter()
		.map(|commitment| hex::encode(commitment))
		.collect();
	hex_strings.serialize(serializer)
}

#[cfg(feature = "serde")]
fn deserialize_da_commitments<'de, D>(deserializer: D) -> Result<DaCommitments, D::Error>
where
	D: Deserializer<'de>,
{
	let hex_strings: Vec<String> = Vec::deserialize(deserializer)?;
	hex_strings
		.iter()
		.map(|hex_str| {
			let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
			let mut array = [0u8; 48];
			array.copy_from_slice(&bytes);
			Ok(array)
		})
		.collect()
}

#[cfg(feature = "runtime")]
use crate::asdr::AppUncheckedExtrinsic;
#[cfg(feature = "runtime")]
use sp_runtime::{generic::UncheckedExtrinsic, traits::SignedExtension};

#[cfg(feature = "runtime")]
impl<A, C, S, E> From<UncheckedExtrinsic<A, C, S, E>> for AppExtrinsic
where
	A: Encode,
	C: Encode,
	S: Encode,
	E: SignedExtension + GetAppId + GetDaCommitments,
{
	fn from(ue: sp_runtime::generic::UncheckedExtrinsic<A, C, S, E>) -> Self {
		let app_id = ue
			.signature
			.as_ref()
			.map(|(_, _, extra)| extra.app_id())
			.unwrap_or_default();
		let da_commitments = ue
			.signature
			.as_ref()
			.map(|(_, _, extra)| extra.da_commitments())
			.unwrap_or_default();
		let data = ue.encode();

		Self {
			app_id,
			da_commitments,
			data,
		}
	}
}

impl GetAppId for AppExtrinsic {
	fn app_id(&self) -> AppId {
		self.app_id
	}
}

impl GetDaCommitments for AppExtrinsic {
	fn da_commitments(&self) -> DaCommitments {
		self.da_commitments.clone()
	}
}

impl From<Vec<u8>> for AppExtrinsic {
	#[inline]
	fn from(data: Vec<u8>) -> Self {
		Self {
			data,
			app_id: <_>::default(),
			da_commitments: <_>::default(),
		}
	}
}

#[cfg(feature = "runtime")]
impl<A, C, S, E> From<&AppUncheckedExtrinsic<A, C, S, E>> for AppExtrinsic
where
	A: Codec,
	C: Codec,
	S: Codec,
	E: SignedExtension + GetAppId + GetDaCommitments,
{
	fn from(app_ext: &AppUncheckedExtrinsic<A, C, S, E>) -> Self {
		Self {
			app_id: app_ext.app_id(),
			da_commitments: app_ext.da_commitments(),
			data: app_ext.encode(),
		}
	}
}

#[cfg(feature = "runtime")]
impl<A, C, S, E> From<AppUncheckedExtrinsic<A, C, S, E>> for AppExtrinsic
where
	A: Codec,
	C: Codec,
	S: Codec,
	E: SignedExtension + GetAppId + GetDaCommitments,
{
	fn from(app_ext: AppUncheckedExtrinsic<A, C, S, E>) -> Self {
		Self {
			app_id: app_ext.app_id(),
			da_commitments: app_ext.da_commitments(),
			data: app_ext.encode(),
		}
	}
}
