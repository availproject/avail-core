/// Parameters that Avail config / node code will set.
#[derive(Clone, Copy, Debug)]
pub struct FriParamsConfig {
	/// log2(1 / Reed–Solomon code rate).
	pub log_inv_rate: usize,
	/// Number of FRI test queries (soundness parameter).
	pub num_test_queries: usize,
	/// log2(number of “shares” / repetitions).
	pub log_num_shares: usize,
	/// Number of multilinear variables (depends on data size).
	pub n_vars: usize,
}
