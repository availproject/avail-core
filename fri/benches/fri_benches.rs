#![allow(clippy::needless_pass_by_value)]

use avail_core::FriParamsVersion;
use avail_fri::{
	core::FriCommitOutput, e2e_helpers::commit_bytes, FriBiniusPCS, FriCommitment, FriContext,
	PackedMLE,
};
use binius_verifier::config::B128;
use divan::{black_box, Bencher};
use rand::{rngs::StdRng, SeedableRng};

fn patterned_data(size: usize) -> Vec<u8> {
	(0..size).map(|i| (i % 251) as u8).collect()
}

/// Helper: setup PCS, context, packed MLE, commit_output, commitment for a given byte size.
fn setup_for_size(
	size_bytes: usize,
) -> (
	FriBiniusPCS,
	FriContext,
	PackedMLE<B128>,
	FriCommitOutput<B128>,
	FriCommitment,
) {
	let data = patterned_data(size_bytes);

	let params_version = FriParamsVersion(0);
	let cfg = params_version.to_config(0);

	commit_bytes(cfg, &data).expect("commit_bytes must succeed")
}

// commitment generation
fn fri_commit_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	bencher.bench_local(|| {
		let data = patterned_data(size_bytes);

		let params_version = FriParamsVersion(0);
		let cfg = params_version.to_config(0);

		let _ = commit_bytes(cfg, &data).expect("commit_bytes must succeed");
		black_box(());
	});
}

#[divan::bench(max_time = 10)]
fn fri_commit_2_mib(bencher: Bencher) {
	fri_commit_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_commit_4_mib(bencher: Bencher) {
	fri_commit_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_commit_8_mib(bencher: Bencher) {
	fri_commit_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_commit_16_mib(bencher: Bencher) {
	fri_commit_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_commit_32_mib(bencher: Bencher) {
	fri_commit_for_size(bencher, 32);
}

// sampling prrof generation

fn fri_sampling_proof_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, _packed, commit_output, _commitment) = setup_for_size(size_bytes);
	let log_batch_size = ctx.fri_params.log_batch_size();
	let leaf_count = 1usize
		<< (ctx
			.fri_params
			.rs_code()
			.log_len()
			.saturating_sub(log_batch_size));
	let idx = leaf_count / 2; // middle leaf

	bencher.bench_local(|| {
		let mut transcript = pcs
			.inclusion_proof::<B128>(&commit_output.committed, idx)
			.expect("inclusion_proof must succeed");

		black_box(&mut transcript);
		black_box(&ctx);
	});
}

#[divan::bench(name = "fri_sampling_proof_2_mib")]
fn fri_sampling_proof_2_mib(bencher: Bencher) {
	fri_sampling_proof_for_size(bencher, 2);
}

#[divan::bench(name = "fri_sampling_proof_4_mib")]
fn fri_sampling_proof_4_mib(bencher: Bencher) {
	fri_sampling_proof_for_size(bencher, 4);
}

#[divan::bench(name = "fri_sampling_proof_8_mib")]
fn fri_sampling_proof_8_mib(bencher: Bencher) {
	fri_sampling_proof_for_size(bencher, 8);
}

#[divan::bench(name = "fri_sampling_proof_16_mib")]
fn fri_sampling_proof_16_mib(bencher: Bencher) {
	fri_sampling_proof_for_size(bencher, 16);
}

#[divan::bench(name = "fri_sampling_proof_32_mib")]
fn fri_sampling_proof_32_mib(bencher: Bencher) {
	fri_sampling_proof_for_size(bencher, 32);
}

// sampling proof verification

fn fri_sampling_verify_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, _packed, commit_output, commitment) = setup_for_size(size_bytes);
	let log_batch_size = ctx.fri_params.log_batch_size();
	let leaf_count = 1usize
		<< (ctx
			.fri_params
			.rs_code()
			.log_len()
			.saturating_sub(log_batch_size));
	let idx = leaf_count / 2;
	let values = commit_output
		.codeword
		.to_ref()
		.chunk(log_batch_size, idx)
		.iter_scalars()
		.collect::<Vec<_>>();

	let base_transcript = pcs
		.inclusion_proof::<B128>(&commit_output.committed, idx)
		.expect("proof");

	bencher.bench_local(|| {
		// clone transcript to avoid re-proving inside loop
		let mut tr = base_transcript.clone();
		pcs.verify_inclusion_proof(&mut tr, &values, idx, &ctx, &commitment)
			.expect("verify");
		black_box(tr);
	});
}

#[divan::bench(max_time = 10)]
fn fri_sampling_verify_2_mib(bencher: Bencher) {
	fri_sampling_verify_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_sampling_verify_4_mib(bencher: Bencher) {
	fri_sampling_verify_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_sampling_verify_8_mib(bencher: Bencher) {
	fri_sampling_verify_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_sampling_verify_16_mib(bencher: Bencher) {
	fri_sampling_verify_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_sampling_verify_32_mib(bencher: Bencher) {
	fri_sampling_verify_for_size(bencher, 32);
}

// evealuation proof generation

fn fri_eval_prove_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, packed, commit_output, _commitment) = setup_for_size(size_bytes);
	let mut rng = StdRng::from_seed([7u8; 32]);
	let eval_point = pcs.sample_evaluation_point(&mut rng);

	bencher.bench_local(|| {
		let proof = pcs
			.prove::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)
			.expect("prove");
		black_box(proof);
	});
}

#[divan::bench(max_time = 10)]
fn fri_eval_prove_2_mib(bencher: Bencher) {
	fri_eval_prove_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_eval_prove_4_mib(bencher: Bencher) {
	fri_eval_prove_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_eval_prove_8_mib(bencher: Bencher) {
	fri_eval_prove_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_eval_prove_16_mib(bencher: Bencher) {
	fri_eval_prove_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_eval_prove_32_mib(bencher: Bencher) {
	fri_eval_prove_for_size(bencher, 32);
}

// evaluation proof verification

fn fri_eval_verify_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, packed, commit_output, _commitment) = setup_for_size(size_bytes);
	let mut rng = StdRng::from_seed([8u8; 32]);
	let eval_point = pcs.sample_evaluation_point(&mut rng);

	// Heavy part done once: claim + proof
	let eval_claim = pcs
		.calculate_evaluation_claim(&packed.packed_values, &eval_point)
		.expect("claim");

	let proof = pcs
		.prove::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)
		.expect("prove");

	// Approximate proof size "over the wire":
	// - commitment: 32 bytes (already in header)
	// - eval_point: n_vars * sizeof(B128)
	// - eval_claim: sizeof(B128)
	// - transcript: proof.transcript_bytes.len()
	let fp_size = core::mem::size_of::<B128>();
	let eval_point_bytes = eval_point.len() * fp_size;
	let eval_claim_bytes = fp_size;
	let commitment_bytes = 32;
	let transcript_bytes = proof.transcript_bytes.len();
	let total_bytes = commitment_bytes + eval_point_bytes + eval_claim_bytes + transcript_bytes;

	println!(
		"FRI eval proof size for {:>2} MiB blob ≈ {} bytes \
         (commitment={}, eval_point={}, claim={}, transcript={})",
		mb, total_bytes, commitment_bytes, eval_point_bytes, eval_claim_bytes, transcript_bytes
	);

	bencher.bench_local(|| {
		pcs.verify(&proof, eval_claim, &eval_point, &ctx)
			.expect("verify");
		black_box(&proof);
	});
}

#[divan::bench(max_time = 10)]
fn fri_eval_verify_2_mib(bencher: Bencher) {
	fri_eval_verify_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_eval_verify_4_mib(bencher: Bencher) {
	fri_eval_verify_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_eval_verify_8_mib(bencher: Bencher) {
	fri_eval_verify_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_eval_verify_16_mib(bencher: Bencher) {
	fri_eval_verify_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_eval_verify_32_mib(bencher: Bencher) {
	fri_eval_verify_for_size(bencher, 32);
}

// evaluation claim (p(z)) computation
fn fri_eval_claim_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, _ctx, packed, _commit_output, _commitment) = setup_for_size(size_bytes);

	// Deterministic evaluation point.
	let mut rng = StdRng::from_seed([42u8; 32]);
	let eval_point = pcs.sample_evaluation_point(&mut rng);

	bencher.bench_local(|| {
		let claim = pcs
			.calculate_evaluation_claim(&packed.packed_values, &eval_point)
			.expect("evaluation_claim must succeed");

		// Prevent the optimizer from throwing this away.
		black_box(claim);
	});
}

#[divan::bench(max_time = 20)]
fn fri_eval_claim_2_mib(bencher: Bencher) {
	fri_eval_claim_for_size(bencher, 2);
}

#[divan::bench(max_time = 20)]
fn fri_eval_claim_4_mib(bencher: Bencher) {
	fri_eval_claim_for_size(bencher, 4);
}

#[divan::bench(max_time = 20)]
fn fri_eval_claim_8_mib(bencher: Bencher) {
	fri_eval_claim_for_size(bencher, 8);
}

#[divan::bench(max_time = 20)]
fn fri_eval_claim_16_mib(bencher: Bencher) {
	fri_eval_claim_for_size(bencher, 16);
}

#[divan::bench(max_time = 30)]
fn fri_eval_claim_32_mib(bencher: Bencher) {
	fri_eval_claim_for_size(bencher, 32);
}

fn main() {
	divan::main();
}
