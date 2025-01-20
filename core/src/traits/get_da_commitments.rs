use crate::{constants::kate::COMMITMENT_SIZE, DaCommitments};
use scale_info::prelude::vec::Vec;

/// Get DA Commitments trait
pub trait GetDaCommitments {
	fn da_commitments(&self) -> DaCommitments {
		Vec::new()
	}
}

impl<A, B, C, D, E, F, G, H, I: GetDaCommitments> GetDaCommitments for (A, B, C, D, E, F, G, H, I) {
	fn da_commitments(&self) -> DaCommitments {
		self.8.da_commitments()
	}
}

impl<A, B, C, D, E, F, G, H, I, J: GetDaCommitments> GetDaCommitments
	for (A, B, C, D, E, F, G, H, I, J)
{
	fn da_commitments(&self) -> DaCommitments {
		self.9.da_commitments()
	}
}

impl<A, B, C, D, E, F, G, H, I, J: GetDaCommitments, K> GetDaCommitments
	for (A, B, C, D, E, F, G, H, I, J, K)
{
	fn da_commitments(&self) -> DaCommitments {
		self.9.da_commitments()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::kate::COMMITMENT_SIZE;

	struct CustomDaCommitments {}

	impl GetDaCommitments for CustomDaCommitments {
		fn da_commitments(&self) -> DaCommitments {
			vec![[0u8; COMMITMENT_SIZE]]
		}
	}

	struct DefaultGetDaCommitments {}
	impl GetDaCommitments for DefaultGetDaCommitments {}

	#[test]
	fn da_commitments_trait_on_tuples() {
		let custom_da_commitments = (0, 1, 2, 3, 4, 5, 6, CustomDaCommitments {});
		let default_da_commitments = (0, 1, 2, 3, 4, 5, 6, DefaultGetDaCommitments {});

		assert_eq!(
			custom_da_commitments.da_commitments(),
			vec![[0u8; COMMITMENT_SIZE]]
		);
		assert_eq!(
			default_da_commitments.da_commitments(),
			DaCommitments::new()
		);
	}
}
