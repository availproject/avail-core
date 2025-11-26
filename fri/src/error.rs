use core::fmt;

#[derive(Debug)]
pub enum FriBiniusError {
	ReedSolomonInit(String),
	FriParamsInit(String),
	DomainInit(String),
	Commitment(String),
	Proof(String),
	Verification(String),
	Merkle(String),
	Encoding(String),
	Transcript(String),
	Reconstruction(String),
	InvalidInput(&'static str),
}

impl fmt::Display for FriBiniusError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use FriBiniusError::*;
		match self {
			ReedSolomonInit(e) => write!(f, "Reed-Solomon init error: {e}"),
			FriParamsInit(e) => write!(f, "FRI params init error: {e}"),
			DomainInit(e) => write!(f, "Domain init error: {e}"),
			Commitment(e) => write!(f, "Commitment error: {e}"),
			Proof(e) => write!(f, "Proof error: {e}"),
			Verification(e) => write!(f, "Verification error: {e}"),
			Merkle(e) => write!(f, "Merkle error: {e}"),
			Encoding(e) => write!(f, "Encoding error: {e}"),
			Transcript(e) => write!(f, "Transcript error: {e}"),
			Reconstruction(e) => write!(f, "Reconstruction error: {e}"),
			InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
		}
	}
}
