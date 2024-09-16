use crate::sp_std::vec::Vec;
use crate::traits::GetAppId;
use codec::Codec;
use codec::{Decode, Encode};
use derive_more::Constructor;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "runtime")]
use {scale_info::TypeInfo, sp_core::RuntimeDebug};

use crate::AppId;

/// Raw Extrinsic with application id.
#[derive(Clone, Default, Encode, Decode, Constructor)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(TypeInfo, RuntimeDebug))]
pub struct AppExtrinsic {
	pub app_id: AppId,
	#[cfg_attr(feature = "serde", serde(with = "hex"))]
	pub data: Vec<u8>,
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
	E: SignedExtension + GetAppId,
{
	fn from(ue: sp_runtime::generic::UncheckedExtrinsic<A, C, S, E>) -> Self {
		let app_id = ue
			.signature
			.as_ref()
			.map(|(_, _, extra)| extra.app_id())
			.unwrap_or_default();
		let data = ue.encode();

		Self { app_id, data }
	}
}

impl GetAppId for AppExtrinsic {
	fn app_id(&self) -> AppId {
		self.app_id
	}
}

impl From<Vec<u8>> for AppExtrinsic {
	#[inline]
	fn from(data: Vec<u8>) -> Self {
		Self {
			data,
			app_id: <_>::default(),
		}
	}
}

#[cfg(feature = "runtime")]
impl<A, C, S, E> From<&AppUncheckedExtrinsic<A, C, S, E>> for AppExtrinsic
where
	A: Codec,
	C: Codec,
	S: Codec,
	E: SignedExtension + GetAppId,
{
	fn from(app_ext: &AppUncheckedExtrinsic<A, C, S, E>) -> Self {
		Self {
			app_id: app_ext.app_id(),
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
	E: SignedExtension + GetAppId,
{
	fn from(app_ext: AppUncheckedExtrinsic<A, C, S, E>) -> Self {
		Self {
			app_id: app_ext.app_id(),
			data: app_ext.encode(),
		}
	}
}
