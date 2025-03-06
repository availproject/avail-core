use avail_core::{
	app_extrinsic::AppExtrinsic, constants::kate::CHUNK_SIZE, BlockLengthColumns, BlockLengthRows,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kate::com::par_build_commitments;
use kate::couscous;
use kate::gridgen::{AsBytes, EvaluationGrid};
use kate::metrics::IgnoreMetrics;
use kate::Seed;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use std::time::Duration;

const ROWS: usize = 1024;
const COLUMNS: usize = 1024;

fn benchmark_commitments(c: &mut Criterion) {
	let mut group = c.benchmark_group("commitments");

	// Max tx size supported by the current setup
	let tx_size: usize = ROWS * COLUMNS * CHUNK_SIZE - (ROWS * COLUMNS) - 32;
	let mut rng = ChaChaRng::from_seed([0u8; 32]);
	let data: Vec<u8> = (0..tx_size).map(|_| rng.gen()).collect();
	let app_extrinsics = vec![AppExtrinsic::from(data)];
	let public_params = couscous::multiproof_params();

	group.bench_function("serial_commitments", |b| {
		b.iter(|| {
			let grid = EvaluationGrid::from_extrinsics(
				app_extrinsics.clone(),
				4,
				COLUMNS,
				ROWS,
				Seed::default(),
			)
			.unwrap_or_else(|e| panic!("Grid creation failed: {e:?}"));

			let poly_grid = grid
				.make_polynomial_grid()
				.unwrap_or_else(|e| panic!("Polynomial grid creation failed: {e:?}"));

			let commitments_poly_grid = poly_grid
				.extended_commitments(&public_params, 2)
				.unwrap_or_else(|e| panic!("Commitment generation failed: {e:?}"));

			let commitments: Vec<u8> = commitments_poly_grid
				.iter()
				.flat_map(|c| {
					c.to_bytes()
						.unwrap_or_else(|e| panic!("Failed to convert commitment: {e:?}"))
				})
				.collect();

			black_box(commitments);
		});
	});

	group.bench_function("parallel_commitments", |b| {
		b.iter(|| {
			let (_, commitments_bytes, _, _) = par_build_commitments::<CHUNK_SIZE, _>(
				BlockLengthRows(ROWS as u32),
				BlockLengthColumns(COLUMNS as u32),
				&app_extrinsics,
				Seed::default(),
				&IgnoreMetrics {},
			)
			.unwrap_or_else(|e| panic!("Parallel commitment generation failed: {e:?}"));

			black_box(commitments_bytes);
		});
	});

	group.finish();
}

fn criterion_config() -> Criterion {
	Criterion::default()
		.measurement_time(Duration::new(60, 0))
		.warm_up_time(Duration::new(5, 0))
		.sample_size(20)
}

criterion_group! {
	name = benches;
	config = criterion_config();
	targets = benchmark_commitments
}
criterion_main!(benches);
