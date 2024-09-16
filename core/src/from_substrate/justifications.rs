use super::digest::ConsensusEngineId;
use codec::{Decode, Encode};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An abstraction over justification for a block's validity under a consensus algorithm.
///
/// Essentially a finality proof. The exact formulation will vary between consensus
/// algorithms. In the case where there are multiple valid proofs, inclusion within
/// the block itself would allow swapping justifications to change the block's hash
/// (and thus fork the chain). Sending a `Justification` alongside a block instead
/// bypasses this problem.
///
/// Each justification is provided as an encoded blob, and is tagged with an ID
/// to identify the consensus engine that generated the proof (we might have
/// multiple justifications from different engines for the same block).
pub type Justification = (ConsensusEngineId, EncodedJustification);

/// The encoded justification specific to a consensus engine.
pub type EncodedJustification = Vec<u8>;

/// Collection of justifications for a given block, multiple justifications may
/// be provided by different consensus engines for the same block.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct Justifications(Vec<Justification>);

impl Justifications {
	/// Return an iterator over the justifications.
	pub fn iter(&self) -> impl Iterator<Item = &Justification> {
		self.0.iter()
	}

	/// Append a justification. Returns false if a justification with the same
	/// `ConsensusEngineId` already exists, in which case the justification is
	/// not inserted.
	pub fn append(&mut self, justification: Justification) -> bool {
		if self.get(justification.0).is_some() {
			return false;
		}
		self.0.push(justification);
		true
	}

	/// Return the encoded justification for the given consensus engine, if it
	/// exists.
	pub fn get(&self, engine_id: ConsensusEngineId) -> Option<&EncodedJustification> {
		self.iter().find(|j| j.0 == engine_id).map(|j| &j.1)
	}

	/// Remove the encoded justification for the given consensus engine, if it exists.
	pub fn remove(&mut self, engine_id: ConsensusEngineId) {
		self.0.retain(|j| j.0 != engine_id)
	}

	/// Return a copy of the encoded justification for the given consensus
	/// engine, if it exists.
	pub fn into_justification(self, engine_id: ConsensusEngineId) -> Option<EncodedJustification> {
		self.into_iter().find(|j| j.0 == engine_id).map(|j| j.1)
	}
}

impl IntoIterator for Justifications {
	type Item = Justification;
	type IntoIter = crate::sp_std::vec::IntoIter<Self::Item>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl From<Justification> for Justifications {
	fn from(justification: Justification) -> Self {
		Self(vec![justification])
	}
}
