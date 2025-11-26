use crate::error::FriBiniusError;
use binius_transcript::Buf;
use binius_transcript::VerifierTranscript;
use binius_verifier::config::StdChallenger;

pub type Challenger = StdChallenger;
pub type VerifierTr = VerifierTranscript<Challenger>;

pub fn transcript_to_bytes(transcript: &VerifierTr) -> Vec<u8> {
	// NOTE: this is inherently stateful / consumptive;
	// cloning is fine on verifier side.
	let mut cloned = transcript.clone();
	let mut message_reader = cloned.message();
	let buffer = message_reader.buffer();
	let remaining = buffer.remaining();

	if remaining == 0 {
		return Vec::new();
	}

	let mut bytes = vec![0u8; remaining];
	buffer.copy_to_slice(&mut bytes);
	bytes
}

pub fn transcript_from_bytes(bytes: Vec<u8>) -> VerifierTr {
	VerifierTr::new(Challenger::default(), bytes)
}

#[allow(dead_code)]
pub fn extract_commitment_from_transcript(
	transcript: &mut VerifierTr,
) -> Result<Vec<u8>, FriBiniusError> {
	transcript
		.message()
		.read()
		.map_err(|e| FriBiniusError::Transcript(e.to_string()))
}
