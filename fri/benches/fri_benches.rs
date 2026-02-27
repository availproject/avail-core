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

	let params_version = FriParamsVersion::V0;
	let cfg = params_version.to_config(0);

	commit_bytes(cfg, &data).expect("commit_bytes must succeed")
}

// commitment generation
fn fri_commit_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	bencher.bench_local(|| {
		let data = patterned_data(size_bytes);

		let params_version = FriParamsVersion::V0;
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

// evaluation proof bundle generation (prove_with_openings + extra-query payload)
fn fri_eval_bundle_build_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, packed, commit_output, _commitment) = setup_for_size(size_bytes);
	let mut rng = StdRng::from_seed([9u8; 32]);
	let eval_point = pcs.sample_evaluation_point(&mut rng);

	let log_batch_size = ctx.fri_params.log_batch_size();
	let leaf_count = 1usize
		<< (ctx
			.fri_params
			.rs_code()
			.log_len()
			.saturating_sub(log_batch_size));
	let extra_index = leaf_count / 2;

	bencher.bench_local(|| {
		let (_terminate_codeword, query_prover, proof) = pcs
			.prove_with_openings::<B128>(
				packed.packed_mle.clone(),
				&ctx,
				&commit_output,
				&eval_point,
			)
			.expect("prove_with_openings");
		let bundle = pcs
			.build_eval_proof_bundle(&proof, &_terminate_codeword, &query_prover, extra_index)
			.expect("build_eval_proof_bundle");
		black_box(bundle);
	});
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_build_2_mib(bencher: Bencher) {
	fri_eval_bundle_build_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_build_4_mib(bencher: Bencher) {
	fri_eval_bundle_build_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_build_8_mib(bencher: Bencher) {
	fri_eval_bundle_build_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_build_16_mib(bencher: Bencher) {
	fri_eval_bundle_build_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_build_32_mib(bencher: Bencher) {
	fri_eval_bundle_build_for_size(bencher, 32);
}

// evaluation proof bundle verification (verify_with_extra_query wrapper)
fn fri_eval_bundle_verify_for_size(bencher: Bencher, mb: usize) {
	let size_bytes = mb * 1024 * 1024;

	let (pcs, ctx, packed, commit_output, _commitment) = setup_for_size(size_bytes);
	let mut rng = StdRng::from_seed([10u8; 32]);
	let eval_point = pcs.sample_evaluation_point(&mut rng);
	let eval_claim = pcs
		.calculate_evaluation_claim(&packed.packed_values, &eval_point)
		.expect("evaluation_claim");

	let log_batch_size = ctx.fri_params.log_batch_size();
	let leaf_count = 1usize
		<< (ctx
			.fri_params
			.rs_code()
			.log_len()
			.saturating_sub(log_batch_size));
	let extra_index = leaf_count / 2;

	let (terminate_codeword, query_prover, proof) = pcs
		.prove_with_openings::<B128>(packed.packed_mle.clone(), &ctx, &commit_output, &eval_point)
		.expect("prove_with_openings");
	let bundle = pcs
		.build_eval_proof_bundle(&proof, &terminate_codeword, &query_prover, extra_index)
		.expect("build_eval_proof_bundle");

	bencher.bench_local(|| {
		pcs.verify_eval_proof_bundle(&bundle, eval_claim, &eval_point, &ctx)
			.expect("verify_eval_proof_bundle");
		black_box(&bundle);
	});
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_verify_2_mib(bencher: Bencher) {
	fri_eval_bundle_verify_for_size(bencher, 2);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_verify_4_mib(bencher: Bencher) {
	fri_eval_bundle_verify_for_size(bencher, 4);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_verify_8_mib(bencher: Bencher) {
	fri_eval_bundle_verify_for_size(bencher, 8);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_verify_16_mib(bencher: Bencher) {
	fri_eval_bundle_verify_for_size(bencher, 16);
}

#[divan::bench(max_time = 10)]
fn fri_eval_bundle_verify_32_mib(bencher: Bencher) {
	fri_eval_bundle_verify_for_size(bencher, 32);
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
