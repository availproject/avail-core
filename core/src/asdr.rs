// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generic implementation of an unchecked (pre-verification) extrinsic.
use crate::{
	traits::{GetAppId, MaybeCaller},
	AppId, OpaqueExtrinsic,
};

use crate::from_substrate::blake2_256;
use codec::{Codec, Compact, Decode, Encode, EncodeLike, Error, Input};
use scale_info::{build::Fields, meta_type, Path, StaticTypeInfo, Type, TypeInfo, TypeParameter};
use sp_runtime::MultiAddress;
use sp_std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	vec,
	vec::Vec,
};

#[cfg(all(not(feature = "std"), feature = "serde"))]
use sp_std::alloc::format;
#[cfg(feature = "runtime")]
use {
	frame_support::{
		dispatch::{DispatchInfo, GetDispatchInfo},
		traits::ExtrinsicCall,
	},
	sp_runtime::{
		generic::CheckedExtrinsic,
		traits::{
			self, Checkable, Extrinsic, ExtrinsicMetadata, IdentifyAccount, MaybeDisplay, Member,
			SignedExtension,
		},
		transaction_validity::{InvalidTransaction, TransactionValidityError},
	},
};

/// Current version of the [`UncheckedExtrinsic`] encoded format.
///
/// This version needs to be bumped if the encoded representation changes.
/// It ensures that if the representation is changed and the format is not known,
/// the decoding fails.
pub const EXTRINSIC_FORMAT_VERSION: u8 = 4;

/// The `SignaturePayload` of `UncheckedExtrinsic`.
type SignaturePayload<Address, Signature, Extra> = (Address, Signature, Extra);

/// An extrinsic right from the external world. This is unchecked and so can contain a signature.
///
/// An extrinsic is formally described as any external data that is originating from the outside of
/// the runtime and fed into the runtime as a part of the block-body.
///
/// Inherents are special types of extrinsics that are placed into the block by the block-builder.
/// They are unsigned because the assertion is that they are "inherently true" by virtue of getting
/// past all validators.
///
/// Transactions are all other statements provided by external entities that the chain deems values
/// and decided to include in the block. This value is typically in the form of fee payment, but it
/// could in principle be any other interaction. Transactions are either signed or unsigned. A
/// sensible transaction pool should ensure that only transactions that are worthwhile are
/// considered for block-building.
///
/// This type is by no means enforced within Substrate, but given its genericness, it is highly
/// likely that for most use-cases it will suffice. Thus, the encoding of this type will dictate
/// exactly what bytes should be sent to a runtime to transact with it.
///
/// This can be checked using [`Checkable`], yielding a [`CheckedExtrinsic`], which is the
/// counterpart of this type after its signature (and other non-negotiable validity checks) have
/// passed.
#[derive(PartialEq, Eq, Clone)]
pub struct AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Codec,
	Call: Codec,
	Signature: Codec,
	Extra: SignedExtension,
{
	/// The signature, address, number of extrinsics have come before from
	/// the same signer and an era describing the longevity of this transaction,
	/// if this is a signed extrinsic.
	pub signature: Option<SignaturePayload<Address, Signature, Extra>>,
	/// The function that should be called.
	pub function: Call,
}

/// Manual [`TypeInfo`] implementation because of custom encoding. The data is a valid encoded
/// `Vec<u8>`, but requires some logic to extract the signature and payload.
///
/// See [`AppUncheckedExtrinsic::encode`] and [`AppUncheckedExtrinsic::decode`].
impl<A, C, S, E> TypeInfo for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec + StaticTypeInfo,
	C: Codec + StaticTypeInfo,
	S: Codec + StaticTypeInfo,
	E: SignedExtension + StaticTypeInfo,
{
	type Identity = AppUncheckedExtrinsic<A, C, S, E>;

	fn type_info() -> Type {
		Type::builder()
			.path(Path::new("AppUncheckedExtrinsic", module_path!()))
			// Include the type parameter types, even though they are not used directly in any of
			// the described fields. These type definitions can be used by downstream consumers
			// to help construct the custom decoding from the opaque bytes (see below).
			.type_params(vec![
				TypeParameter::new("Address", Some(meta_type::<A>())),
				TypeParameter::new("Call", Some(meta_type::<C>())),
				TypeParameter::new("Signature", Some(meta_type::<S>())),
				TypeParameter::new("Extra", Some(meta_type::<E>())),
			])
			.docs(&["AppUncheckedExtrinsic raw bytes, requires custom decoding routine"])
			// Because of the custom encoding, we can only accurately describe the encoding as an
			// opaque `Vec<u8>`. Downstream consumers will need to manually implement the codec to
			// encode/decode the `signature` and `function` fields.
			.composite(Fields::unnamed().field(|f| f.ty::<Vec<u8>>()))
	}
}

impl<A, C, S, E> AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	C: Codec,
	S: Codec,
	E: SignedExtension,
{
	/// New instance of a signed extrinsic aka "transaction".
	pub fn new_signed(function: C, signed: A, signature: S, extra: E) -> Self {
		Self {
			signature: Some((signed, signature, extra)),
			function,
		}
	}

	/// New instance of an unsigned extrinsic aka "inherent".
	pub fn new_unsigned(function: C) -> Self {
		Self {
			signature: None,
			function,
		}
	}
}

impl<A, C, S, E> AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	pub fn decode_no_vec_prefix<I: Input>(input: &mut I) -> Result<Self, Error> {
		let version = input.read_byte()?;

		let is_signed = version & 0b1000_0000 != 0;
		let version = version & 0b0111_1111;
		if version != EXTRINSIC_FORMAT_VERSION {
			return Err("Invalid transaction version".into());
		}

		let signature = is_signed.then(|| Decode::decode(input)).transpose()?;
		let function = Decode::decode(input)?;

		Ok(Self {
			signature,
			function,
		})
	}
}

impl<A, C, S, E> Extrinsic for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec + TypeInfo,
	S: Codec + TypeInfo,
	C: Codec + TypeInfo,
	E: SignedExtension,
{
	type Call = C;
	type SignaturePayload = SignaturePayload<A, S, E>;

	fn is_signed(&self) -> Option<bool> {
		Some(self.signature.is_some())
	}

	fn new(function: C, signed_data: Option<Self::SignaturePayload>) -> Option<Self> {
		Some(if let Some((address, signature, extra)) = signed_data {
			Self::new_signed(function, address, signature, extra)
		} else {
			Self::new_unsigned(function)
		})
	}
}

impl<LookupSource, AccountId, C, S, E, Lookup> Checkable<Lookup>
	for AppUncheckedExtrinsic<LookupSource, C, S, E>
where
	LookupSource: Codec + Member + MaybeDisplay,
	C: Codec + Member,
	S: Codec + Member + traits::Verify,
	<S as traits::Verify>::Signer: IdentifyAccount<AccountId = AccountId>,
	E: SignedExtension<AccountId = AccountId>,
	AccountId: Member + MaybeDisplay,
	Lookup: traits::Lookup<Source = LookupSource, Target = AccountId>,
{
	type Checked = CheckedExtrinsic<AccountId, C, E>;

	fn check(self, lookup: &Lookup) -> Result<Self::Checked, TransactionValidityError> {
		Ok(match self.signature {
			Some((signed, signature, extra)) => {
				let signed = lookup.lookup(signed)?;
				let raw_payload = SignedPayload::new(self.function, extra)?;
				if !raw_payload.using_encoded(|payload| signature.verify(payload, &signed)) {
					return Err(InvalidTransaction::BadProof.into());
				}

				let (function, extra, _) = raw_payload.deconstruct();
				CheckedExtrinsic {
					signed: Some((signed, extra)),
					function,
				}
			},
			None => CheckedExtrinsic {
				signed: None,
				function: self.function,
			},
		})
	}

	#[cfg(feature = "try-runtime")]
	fn unchecked_into_checked_i_know_what_i_am_doing(
		self,
		lookup: &Lookup,
	) -> Result<Self::Checked, TransactionValidityError> {
		Ok(match self.signature {
			Some((signed, _, extra)) => {
				let signed = lookup.lookup(signed)?;
				let raw_payload = SignedPayload::new(self.function, extra)?;
				let (function, extra, _) = raw_payload.deconstruct();
				CheckedExtrinsic {
					signed: Some((signed, extra)),
					function,
				}
			},
			None => CheckedExtrinsic {
				signed: None,
				function: self.function,
			},
		})
	}
}

impl<A, C, S, E> ExtrinsicMetadata for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	const VERSION: u8 = EXTRINSIC_FORMAT_VERSION;
	type SignedExtensions = E;
}

#[cfg(feature = "runtime")]
impl<A, C, S, E> GetDispatchInfo for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec + GetDispatchInfo,
	E: SignedExtension,
{
	fn get_dispatch_info(&self) -> DispatchInfo {
		self.function.get_dispatch_info()
	}
}

/// A payload that has been signed for an unchecked extrinsics.
///
/// Note that the payload that we sign to produce unchecked extrinsic signature
/// is going to be different than the `SignaturePayload` - so the thing the extrinsic
/// actually contains.
pub struct SignedPayload<Call, Extra: SignedExtension>((Call, Extra, Extra::AdditionalSigned));

impl<Call, Extra> SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
	/// Create new `SignedPayload`.
	///
	/// This function may fail if `additional_signed` of `Extra` is not available.
	pub fn new(call: Call, extra: Extra) -> Result<Self, TransactionValidityError> {
		let additional_signed = extra.additional_signed()?;
		let raw_payload = (call, extra, additional_signed);
		Ok(Self(raw_payload))
	}

	/// Create new `SignedPayload` from raw components.
	pub fn from_raw(call: Call, extra: Extra, additional_signed: Extra::AdditionalSigned) -> Self {
		Self((call, extra, additional_signed))
	}

	/// Deconstruct the payload into it's components.
	pub fn deconstruct(self) -> (Call, Extra, Extra::AdditionalSigned) {
		self.0
	}
}

impl<Call, Extra> Encode for SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
	/// Get an encoded version of this payload.
	///
	/// Payloads longer than 256 bytes are going to be `blake2_256`-hashed.
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		self.0.using_encoded(|payload| {
			if payload.len() > 256 {
				f(&blake2_256(payload)[..])
			} else {
				f(payload)
			}
		})
	}
}

impl<Call, Extra> EncodeLike for SignedPayload<Call, Extra>
where
	Call: Encode,
	Extra: SignedExtension,
{
}

impl<A, C, S, E> Decode for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		// This is a little more complicated than usual since the binary format must be compatible
		// with SCALE's generic `Vec<u8>` type. Basically this just means accepting that there
		// will be a prefix of vector length.
		let expected_length: Compact<u32> = Decode::decode(input)?;
		let before_length = input.remaining_len()?;

		let extrinsic = Self::decode_no_vec_prefix(input)?;

		if let Some((before_length, after_length)) = input
			.remaining_len()?
			.and_then(|a| before_length.map(|b| (b, a)))
		{
			let length = before_length.saturating_sub(after_length);

			if length != expected_length.0 as usize {
				return Err("Invalid length prefix".into());
			}
		}

		Ok(extrinsic)
	}
}

impl<A, C, S, E> Encode for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	fn encode(&self) -> Vec<u8> {
		let mut tmp = Vec::with_capacity(sp_std::mem::size_of::<Self>());

		// 1 byte version id.
		match self.signature.as_ref() {
			Some(s) => {
				tmp.push(EXTRINSIC_FORMAT_VERSION | 0b1000_0000);
				s.encode_to(&mut tmp);
			},
			None => {
				tmp.push(EXTRINSIC_FORMAT_VERSION & 0b0111_1111);
			},
		}
		self.function.encode_to(&mut tmp);

		let compact_len = codec::Compact::<u32>(tmp.len() as u32);

		// Allocate the output buffer with the correct length
		let output_len = compact_len
			.size_hint()
			.checked_add(tmp.len())
			.expect("Cannot encode this `AppUncheckedExtrinsic` into memory");
		let mut output = Vec::with_capacity(output_len);

		compact_len.encode_to(&mut output);
		output.extend(tmp);

		output
	}
}

impl<A, C, S, E> EncodeLike for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
}

#[cfg(feature = "serde")]
impl<A, Sig, C, E> serde::Serialize for AppUncheckedExtrinsic<A, C, Sig, E>
where
	A: Codec,
	Sig: Codec,
	C: Codec,
	E: SignedExtension,
{
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: ::serde::Serializer,
	{
		let encoded = self.encode();
		impl_serde::serialize::serialize(&encoded, s)
	}
}

#[cfg(feature = "serde")]
impl<'a, A, S, C, E> serde::Deserialize<'a> for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	fn deserialize<D>(de: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'a>,
	{
		let r = impl_serde::serialize::deserialize(de)?;
		Decode::decode(&mut &r[..])
			.map_err(|e| serde::de::Error::custom(format!("Decode error: {}", e)))
	}
}

impl<A, C, S, E> Debug for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec + Debug,
	S: Codec,
	C: Codec + Debug,
	E: SignedExtension,
{
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(
			f,
			"AppUncheckedExtrinsic({:?}, {:?})",
			self.signature.as_ref().map(|x| (&x.0, &x.2)),
			self.function,
		)
	}
}

impl<A, C, S, E> GetAppId for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension + GetAppId,
{
	fn app_id(&self) -> AppId {
		self.signature
			.as_ref()
			.map(|(_address, _signature, extra)| extra.app_id())
			.unwrap_or_default()
	}
}

#[cfg(feature = "runtime")]
impl<A, C, S, E> ExtrinsicCall for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec + TypeInfo,
	C: Codec + TypeInfo,
	S: Codec + TypeInfo,
	E: SignedExtension,
{
	fn call(&self) -> &Self::Call {
		&self.function
	}
}

impl<A, C, S, E> From<AppUncheckedExtrinsic<A, C, S, E>> for OpaqueExtrinsic
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	fn from(extrinsic: AppUncheckedExtrinsic<A, C, S, E>) -> Self {
		Self::from_bytes(extrinsic.encode().as_slice()).expect(
			"both OpaqueExtrinsic and AppUncheckedExtrinsic have encoding that is compatible with \
				raw Vec<u8> encoding; qed",
		)
	}
}

impl<AccountId, AccountIndex, C, S, E> MaybeCaller<AccountId>
	for AppUncheckedExtrinsic<MultiAddress<AccountId, AccountIndex>, C, S, E>
where
	C: Codec,
	S: Codec,
	E: SignedExtension,
	MultiAddress<AccountId, AccountIndex>: Codec,
{
	fn caller(&self) -> Option<&AccountId> {
		let sig = self.signature.as_ref()?;
		match sig.0 {
			MultiAddress::Id(ref id) => Some(id),
			_ => None,
		}
	}
}

impl<A, C, S, E> TryFrom<OpaqueExtrinsic> for AppUncheckedExtrinsic<A, C, S, E>
where
	A: Codec,
	S: Codec,
	C: Codec,
	E: SignedExtension,
{
	type Error = codec::Error;

	fn try_from(opaque: OpaqueExtrinsic) -> Result<Self, Self::Error> {
		Self::decode_no_vec_prefix(&mut opaque.0.as_slice())
	}
}

#[cfg(test)]
mod tests {
	use sp_runtime::{
		codec::{Decode, Encode},
		testing::TestSignature as TestSig,
		traits::{DispatchInfoOf, IdentityLookup, SignedExtension},
	};
	use test_case::test_case;

	use super::*;

	type TestContext = IdentityLookup<u64>;
	type TestAccountId = u64;
	type TestCall = Vec<u8>;

	const TEST_ACCOUNT: TestAccountId = 0;

	// NOTE: this is demonstration. One can simply use `()` for testing.
	#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd, TypeInfo)]
	struct TestExtra;
	impl SignedExtension for TestExtra {
		type AccountId = u64;
		type AdditionalSigned = ();
		type Call = ();
		type Pre = ();

		const IDENTIFIER: &'static str = "TestExtra";

		fn additional_signed(&self) -> Result<(), TransactionValidityError> {
			Ok(())
		}

		fn pre_dispatch(
			self,
			_who: &Self::AccountId,
			_call: &Self::Call,
			_info: &DispatchInfoOf<Self::Call>,
			_len: usize,
		) -> Result<Self::Pre, TransactionValidityError> {
			Ok(())
		}
	}

	impl GetAppId for TestExtra {
		fn app_id(&self) -> AppId {
			Default::default()
		}
	}

	type Ex = AppUncheckedExtrinsic<TestAccountId, TestCall, TestSig, TestExtra>;
	type CEx = CheckedExtrinsic<TestAccountId, TestCall, TestExtra>;

	#[test]
	fn unsigned_codec_should_work() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn invalid_length_prefix_is_detected() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let mut encoded = ux.encode();

		let length = Compact::<u32>::decode(&mut &encoded[..]).unwrap();
		Compact(length.0 + 10).encode_to(&mut &mut encoded[..1]);

		assert_eq!(
			Ex::decode(&mut &encoded[..]),
			Err("Invalid length prefix".into())
		);
	}

	#[test]
	fn signed_codec_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, (vec![0u8; 0], TestExtra).encode()),
			TestExtra,
		);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn large_signed_codec_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(
				TEST_ACCOUNT,
				(vec![0u8; 257], TestExtra).using_encoded(crate::from_substrate::blake2_256)[..]
					.to_owned(),
			),
			TestExtra,
		);
		let encoded = ux.encode();
		assert_eq!(Ex::decode(&mut &encoded[..]), Ok(ux));
	}

	#[test]
	fn unsigned_check_should_work() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		assert!(!ux.is_signed().unwrap_or(false));
		assert!(<Ex as Checkable<TestContext>>::check(ux, &Default::default()).is_ok());
	}

	#[test]
	fn badly_signed_check_should_fail() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, vec![0u8; 0]),
			TestExtra,
		);
		assert!(ux.is_signed().unwrap_or(false));
		assert_eq!(
			<Ex as Checkable<TestContext>>::check(ux, &Default::default()),
			Err(InvalidTransaction::BadProof.into()),
		);
	}

	#[test]
	fn signed_check_should_work() {
		let ux = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, (vec![0u8; 0], TestExtra).encode()),
			TestExtra,
		);
		assert!(ux.is_signed().unwrap_or(false));
		assert_eq!(
			<Ex as Checkable<TestContext>>::check(ux, &Default::default()),
			Ok(CEx {
				signed: Some((TEST_ACCOUNT, TestExtra)),
				function: vec![0u8; 0]
			}),
		);
	}

	#[test]
	fn encoding_matches_vec() {
		let ex = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ex.encode();
		let decoded = Ex::decode(&mut encoded.as_slice()).unwrap();
		assert_eq!(decoded, ex);
		let as_vec: Vec<u8> = Decode::decode(&mut encoded.as_slice()).unwrap();
		assert_eq!(as_vec.encode(), encoded);
	}

	#[test]
	fn conversion_to_opaque() {
		let ux = Ex::new_unsigned(vec![0u8; 0]);
		let encoded = ux.encode();
		let opaque: OpaqueExtrinsic = ux.into();
		let opaque_encoded = opaque.encode();
		assert_eq!(opaque_encoded, encoded);
	}

	#[test]
	fn large_bad_prefix_should_work() {
		let encoded = Compact::<u32>::from(u32::MAX).encode();
		assert_eq!(
			Ex::decode(&mut &encoded[..]),
			Err(Error::from("Not enough data to fill buffer"))
		);
	}

	fn unsigned_to_opaque() -> OpaqueExtrinsic {
		let ex = Ex::new_unsigned(vec![1u8, 2, 3]).encode();
		OpaqueExtrinsic::decode(&mut ex.as_slice()).unwrap()
	}

	fn signed_to_opaque() -> OpaqueExtrinsic {
		let ex = Ex::new_signed(
			vec![0u8; 0],
			TEST_ACCOUNT,
			TestSig(TEST_ACCOUNT, (vec![0u8; 0], TestExtra).encode()),
			TestExtra,
		)
		.encode();

		OpaqueExtrinsic::decode(&mut ex.as_slice()).unwrap()
	}

	fn malformed_opaque() -> OpaqueExtrinsic {
		use core::mem::transmute;

		let op = unsigned_to_opaque();
		unsafe {
			// Using `transmute` because `OpaqueExtrinsic.0` is not public.
			let mut raw = transmute::<OpaqueExtrinsic, Vec<u8>>(op);
			raw.pop();
			transmute::<Vec<u8>, OpaqueExtrinsic>(raw)
		}
	}

	#[test_case( unsigned_to_opaque() => true ; "Unsigned Ex")]
	#[test_case( signed_to_opaque() => true ; "Signed Ex")]
	#[test_case( malformed_opaque() => false ; "Invalid opaque")]
	fn opaque_conversion_tests(opaque: OpaqueExtrinsic) -> bool {
		let opaque = opaque.encode();
		Ex::decode(&mut opaque.as_slice()).is_ok()
	}
}
