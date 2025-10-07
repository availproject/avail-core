use avail_core::{BlockLengthColumns, BlockLengthRows};
use divan::Bencher;
use kate::com::Cell;
use kate::{couscous, gridgen::core::*, Seed};
use kate_recovery::commons::ArkPublicParams;
use kate_recovery::matrix::Dimensions;
use kate_recovery::proof::domain_points;
use poly_multiproof::merlin::Transcript;
use poly_multiproof::traits::PolyMultiProofNoPrecomp;
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {
	divan::main();
}

// #[divan::bench(max_time = 5)]
// fn build_commitments_from_data(bencher: Bencher) {
// 	let pp = couscous::multiproof_params();
// 	let mut rng = rand::thread_rng();
// 	let blob_m: Vec<u8> = (0..32_505_656u32).map(|_| rng.gen()).collect();

// 	bencher.bench(|| {
// 		let grid = EvaluationGrid::from_data(&blob_m, 1024, 1024, 4096, Seed::default())
// 			.expect("failed to build evaluation grid");

// 		let poly_grid = grid
// 			.make_polynomial_grid()
// 			.expect("failed to build polynomial grid");

// 		let _commitments = poly_grid
// 			.commitments(&pp)
// 			.expect("failed to compute commitments");
// 	});
// }

fn random_cell(rng: &mut impl Rng, dims: Dimensions) -> Cell {
	let row = rng.gen_range(0..dims.rows().get());
	let col = rng.gen_range(0..dims.cols().get());
	Cell::new(BlockLengthRows(row as u32), BlockLengthColumns(col as u32))
}

fn run_proof_generate(pp: &ArkPublicParams, blob_m: &[u8], target_dims: Dimensions) {
	let grid = EvaluationGrid::from_data(blob_m, 1024, 1024, 1024, Seed::default())
		.expect("failed to build evaluation grid");

	let poly_grid = grid
		.make_polynomial_grid()
		.expect("failed to build polynomial grid");

	let mut rng = rand::thread_rng();
	let cell = random_cell(&mut rng, target_dims);

	let _multiproof = poly_grid
		.multiproof(pp, &cell, &grid, target_dims)
		.expect("failed to build multiproof");
}

fn generate_multiproof_and_commitments(
	pp: &ArkPublicParams,
	blob_m: &[u8],
	target_dims: Dimensions,
	cells: Vec<Cell>,
) -> (
	Vec<Multiproof<poly_multiproof::ark_bls12_381::Bls12_381>>,
	Vec<Commitment>,
) {
	let grid = EvaluationGrid::from_data(blob_m, 1024, 1024, 1024, Seed::default())
		.expect("failed to build evaluation grid");

	let poly_grid = grid
		.make_polynomial_grid()
		.expect("failed to build polynomial grid");
	let commitments = poly_grid
		.commitments(pp)
		.expect("failed to compute commitments");

	let mut multiproofs = Vec::with_capacity(cells.len());
	for cell in cells {
		let multiproof = poly_grid
			.multiproof(pp, &cell, &grid, target_dims)
			.expect("failed to build multiproof");
		multiproofs.push(multiproof);
	}
	(multiproofs, commitments)
}

fn blob() -> Vec<u8> {
	let mut rng = rand::thread_rng();
	(0..32_505_656u32).map(|_| rng.gen()).collect()
}

// ---------------- Proof Generation BENCHES ---------------- //

#[divan::bench(max_time = 10)]
fn multiproof_generate_1kib_subgrid_1024_32(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1024, 32).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

#[divan::bench(max_time = 10)]
fn multiproof_generate_1kib_subgrid_32_1024(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(32, 1024).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

#[divan::bench(max_time = 10)]
fn multiproof_generate_8kib_subgrid_1024_4(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1024, 4).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

#[divan::bench(max_time = 10)]
fn multiproof_generate_8kib_subgrid_4_1024(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(4, 1024).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

#[divan::bench(max_time = 10)]
fn multiproof_generate_32kib_subgrid_1_1024(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1, 1024).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

#[divan::bench(max_time = 10)]
fn multiproof_generate_32kib_subgrid_1024_1(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1024, 1).unwrap();

	bencher.bench(|| run_proof_generate(&pp, &blob_m, target_dims));
}

// ---------------- Proof Verification BENCHES ---------------- //

#[divan::bench(max_time = 10)]
fn multiproof_verify_1kib_subgrid_1024_32(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1024, 32).unwrap();

	// generate random cells to prove/verify
	let mut rng = rand::thread_rng();
	let cells: Vec<Cell> = (0..16)
		.map(|_| random_cell(&mut rng, target_dims))
		.collect();

	// precompute multiproofs + commitments for all cells
	let (multiproofs, commitments) =
		generate_multiproof_and_commitments(&pp, &blob_m, target_dims, cells);

	// domain points for verification
	let points = domain_points(1024).unwrap(); // adjust if your API differs

	// cycle through the precomputed multiproofs
	let idx = AtomicUsize::new(0);

	bencher.bench(|| {
		let i = idx.fetch_add(1, Ordering::Relaxed);
		let multiproof = &multiproofs[i % multiproofs.len()];

		let verified = PolyMultiProofNoPrecomp::verify(
			&pp,
			&mut Transcript::new(b"avail-mp"),
			&commitments[multiproof.block.start_y..multiproof.block.end_y],
			&points[multiproof.block.start_x..multiproof.block.end_x],
			&multiproof.evals,
			&multiproof.proof,
		)
		.unwrap();

		divan::black_box(verified);
	});
}

#[divan::bench(max_time = 10)]
fn multiproof_verify_1kib_subgrid_32_1024(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(32, 1024).unwrap();

	// generate random cells to prove/verify
	let mut rng = rand::thread_rng();
	let cells: Vec<Cell> = (0..16)
		.map(|_| random_cell(&mut rng, target_dims))
		.collect();

	// precompute multiproofs + commitments for all cells
	let (multiproofs, commitments) =
		generate_multiproof_and_commitments(&pp, &blob_m, target_dims, cells);

	// domain points for verification
	let points = domain_points(1024).unwrap(); // adjust if your API differs

	// cycle through the precomputed multiproofs
	let idx = AtomicUsize::new(0);

	bencher.bench(|| {
		let i = idx.fetch_add(1, Ordering::Relaxed);
		let multiproof = &multiproofs[i % multiproofs.len()];

		let verified = PolyMultiProofNoPrecomp::verify(
			&pp,
			&mut Transcript::new(b"avail-mp"),
			&commitments[multiproof.block.start_y..multiproof.block.end_y],
			&points[multiproof.block.start_x..multiproof.block.end_x],
			&multiproof.evals,
			&multiproof.proof,
		)
		.unwrap();

		divan::black_box(verified);
	});
}

#[divan::bench(max_time = 10)]
fn multiproof_verify_32kib_subgrid_1_1024(bencher: Bencher) {
	let pp = couscous::multiproof_params();
	let blob_m = blob();
	let target_dims = Dimensions::new_from(1, 1024).unwrap();

	// generate random cells to prove/verify
	let mut rng = rand::thread_rng();
	let cells: Vec<Cell> = (0..16)
		.map(|_| random_cell(&mut rng, target_dims))
		.collect();

	// precompute multiproofs + commitments for all cells
	let (multiproofs, commitments) =
		generate_multiproof_and_commitments(&pp, &blob_m, target_dims, cells);

	// domain points for verification
	let points = domain_points(1024).unwrap(); // adjust if your API differs

	// cycle through the precomputed multiproofs
	let idx = AtomicUsize::new(0);

	bencher.bench(|| {
		let i = idx.fetch_add(1, Ordering::Relaxed);
		let multiproof = &multiproofs[i % multiproofs.len()];

		let verified = PolyMultiProofNoPrecomp::verify(
			&pp,
			&mut Transcript::new(b"avail-mp"),
			&commitments[multiproof.block.start_y..multiproof.block.end_y],
			&points[multiproof.block.start_x..multiproof.block.end_x],
			&multiproof.evals,
			&multiproof.proof,
		)
		.unwrap();

		divan::black_box(verified);
	});
}

#[divan::bench(max_time = 10)]
// This benchmark requires larger g2's (1025) than currently available 513 in the pp
// fn multiproof_verify_32kib_subgrid_1024_1(bencher: Bencher) {
// 	let pp = couscous::multiproof_params();
// 	let blob_m = blob();
// 	let target_dims = Dimensions::new_from(1024, 1).unwrap();

// 	// generate random cells to prove/verify
// 	let mut rng = rand::thread_rng();
// 	let cells: Vec<Cell> = (0..16)
// 		.map(|_| random_cell(&mut rng, target_dims))
// 		.collect();

// 	// precompute multiproofs + commitments for all cells
// 	let (multiproofs, commitments) =
// 		generate_multiproof_and_commitments(&pp, &blob_m, target_dims, cells);

// 	// domain points for verification
// 	let points = domain_points(1024).unwrap(); // adjust if your API differs

// 	// cycle through the precomputed multiproofs
// 	let idx = AtomicUsize::new(0);

// 	bencher.bench(|| {
// 		let i = idx.fetch_add(1, Ordering::Relaxed);
// 		let multiproof = &multiproofs[i % multiproofs.len()];

// 		let verified = PolyMultiProofNoPrecomp::verify(
// 			&pp,
// 			&mut Transcript::new(b"avail-mp"),
// 			&commitments[multiproof.block.start_y..multiproof.block.end_y],
// 			&points[multiproof.block.start_x..multiproof.block.end_x],
// 			&multiproof.evals,
// 			&multiproof.proof,
// 		)
// 		.unwrap();

// 		divan::black_box(verified);
// 	});
// }
