pub mod get_app_id;
pub use get_app_id::GetAppId;
pub trait MaybeCaller<A> {
	fn caller(&self) -> Option<&A>;
}
