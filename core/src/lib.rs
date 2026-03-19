#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::arithmetic_side_effects)]

use core::fmt::Debug;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use derive_more::{Add, Constructor, Deref, Into, Mul};
use num_traits::Zero;
use scale_info::TypeInfo;

#[cfg(feature = "runtime")]
use sp_debug_derive::RuntimeDebug;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod from_substrate;

/// DA Block
pub mod block;

/// Customized headers.
pub mod header;
pub use header::HeaderVersion;

/// Kate Commitment on Headers.
pub mod kate_commitment;
pub use kate_commitment::*;

pub mod traits;

pub mod keccak256;
pub use keccak256::Keccak256;

pub mod fri_config;
pub use fri_config::*;

pub mod data_proof;
pub use data_proof::DataProof;

pub mod data_lookup;
pub use data_lookup::v3 as V3DataLookup;
pub use data_lookup::v4::*;
pub use data_lookup::{v3_compact, v4_compact};
pub mod constants;
pub use constants::*;

pub mod const_generic_asserts;

#[repr(u8)]
pub enum InvalidTransactionCustomId {
	/// The AppId is not registered.
	InvalidAppId = 137,
	/// Extrinsic is not allowed for the given `AppId`.
	ForbiddenAppId = 138,
	/// Max recursion was reached for a call with AppId != 0.
	MaxRecursionExceeded = 139,
	/// DA::submit_data calls are forbidden to be in Batch calls
	UnexpectedSubmitDataCall = 140,
	/// Vector::send_message calls are forbidden to be in Batch calls
	UnexpectedSendMessageCall = 141,
}

#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Add,
	Deref,
	TypeInfo,
	Encode,
	Decode,
	DecodeWithMemTracking,
	Default,
	Into,
	MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "runtime", derive(RuntimeDebug))]
#[cfg_attr(not(feature = "runtime"), derive(Debug))]
pub struct AppId(#[codec(compact)] pub u32);

impl core::fmt::Display for AppId {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Zero for AppId {
	fn zero() -> Self {
		AppId(Zero::zero())
	}

	fn is_zero(&self) -> bool {
		self.0.is_zero()
	}
}

/// Strong type for `BlockLength::cols`
#[derive(
	Clone,
	Copy,
	Add,
	Mul,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	PartialOrd,
	Ord,
	Into,
	Constructor,
	MaxEncodedLen,
	Default,
	Debug,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[mul(forward)]
pub struct BlockLengthColumns(#[codec(compact)] pub u32);

/// Strong type for `BlockLength::rows`
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Clone,
	Copy,
	Add,
	Mul,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Into,
	Constructor,
	Default,
	Debug,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[mul(forward)]
pub struct BlockLengthRows(#[codec(compact)] pub u32);

/// Return Err of the expression: `return Err($expression);`.
///
/// Used as `fail!(expression)`.
#[macro_export]
macro_rules! fail {
	( $y:expr ) => {{
		return Err($y.into());
	}};
}

/// Evaluate `$x:expr` and if not true return `Err($y:expr)`.
///
/// Used as `ensure!(expression_to_ensure, expression_to_return_on_false)`.
#[macro_export]
macro_rules! ensure {
	( $x:expr, $y:expr $(,)? ) => {{
		if !$x {
			$crate::fail!($y);
		}
	}};
}

/// Variadic macro used by `keccak256_concat` internally.
#[macro_export]
macro_rules! keccak256_concat_update {
	($hasher:ident, $e:expr) => {{
		$hasher.update($e.as_ref());
	}};

	($hasher:ident, $e:expr, $($es:expr),+) => {{
		$hasher.update($e.as_ref());
		$crate::keccak256_concat_update!($hasher, $($es),+);
	}};
}

/// Calculates the Keccak 256 of arguments with NO extra allocations to join inputs.
#[macro_export]
macro_rules! keccak256_concat{
	($($arg:tt)*) => {{
		{
			use tiny_keccak::Hasher as _;
			let mut output = [0u8; 32];
			let mut hasher = tiny_keccak::Keccak::v256();
			$crate::keccak256_concat_update!(hasher, $($arg)*);
			hasher.finalize(&mut output);
			primitive_types::H256::from(output)
		}
	}}
}
