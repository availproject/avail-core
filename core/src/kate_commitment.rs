use crate::from_substrate::HexDisplay;
use codec::{Decode, Encode};
use primitive_types::H256;
use scale_info::TypeInfo;
use sp_std::{fmt, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod v3 {
	use super::*;

	/// Customized extrinsics root to save the commitment.
	#[derive(PartialEq, Eq, Clone, Default, Encode, Decode, TypeInfo)]
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
	#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
	pub struct KateCommitment {
		/// Rows
		#[codec(compact)]
		pub rows: u16,
		/// Cols
		#[codec(compact)]
		pub cols: u16,
		/// Plonk commitment.
		pub commitment: Vec<u8>,
		/// The merkle root of the data submitted
		pub data_root: H256,
	}

	impl KateCommitment {
		pub fn new(rows: u16, cols: u16, data_root: H256, commitment: Vec<u8>) -> Self {
			Self {
				rows,
				cols,
				commitment,
				data_root,
			}
		}
	}

	impl fmt::Debug for KateCommitment {
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			let commitment: &[u8] = self.commitment.as_slice();
			let data_root: &[u8] = self.data_root.as_ref();

			f.debug_struct("KateCommitment(v3)")
				.field("rows", &self.rows)
				.field("cols", &self.cols)
				.field("commitment", &HexDisplay(commitment))
				.field("data_root", &HexDisplay(data_root))
				.finish()
		}
	}
}
