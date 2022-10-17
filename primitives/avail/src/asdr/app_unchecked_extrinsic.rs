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

use codec::{Compact, Decode, Encode, EncodeLike, Error, Input};
use frame_support::{
	traits::ExtrinsicCall,
	weights::{DispatchInfo, GetDispatchInfo},
};
#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use scale_info::{build::Fields, meta_type, Path, StaticTypeInfo, Type, TypeInfo, TypeParameter};
use sp_io::hashing::blake2_256;
use sp_runtime::{
	generic::CheckedExtrinsic,
	traits::{
		self, Checkable, Extrinsic, ExtrinsicMetadata, IdentifyAccount, MaybeDisplay, Member,
		SignedExtension,
	},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	OpaqueExtrinsic,
};
use sp_std::{
	fmt::{Debug, Formatter, Result as FmtResult},
	vec,
	vec::Vec,
};

use crate::asdr::{AppId, GetAppId};

/// Current version of the [`AppUncheckedExtrinsic`] format.
const EXTRINSIC_VERSION: u8 = 4;

/// A extrinsic right from the external world. This is unchecked and so
/// can contain a signature.
#[derive(PartialEq, Eq, Clone)]
pub struct AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	/// The signature, address, number of extrinsics have come before from
	/// the same signer and an era describing the longevity of this transaction,
	/// if this is a signed extrinsic.
	pub signature: Option<(Address, Signature, Extra)>,
	/// The function that should be called.
	pub function: Call,
}

/// Manual [`TypeInfo`] implementation because of custom encoding. The data is a valid encoded
/// `Vec<u8>`, but requires some logic to extract the signature and payload.
///
/// See [`AppUncheckedExtrinsic::encode`] and [`AppUncheckedExtrinsic::decode`].
impl<Address, Call, Signature, Extra> TypeInfo
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: StaticTypeInfo,
	Call: StaticTypeInfo,
	Signature: StaticTypeInfo,
	Extra: SignedExtension + StaticTypeInfo,
{
	type Identity = AppUncheckedExtrinsic<Address, Call, Signature, Extra>;

	fn type_info() -> Type {
		Type::builder()
			.path(Path::new("AppUncheckedExtrinsic", module_path!()))
			// Include the type parameter types, even though they are not used directly in any of
			// the described fields. These type definitions can be used by downstream consumers
			// to help construct the custom decoding from the opaque bytes (see below).
			.type_params(vec![
				TypeParameter::new("Address", Some(meta_type::<Address>())),
				TypeParameter::new("Call", Some(meta_type::<Call>())),
				TypeParameter::new("Signature", Some(meta_type::<Signature>())),
				TypeParameter::new("Extra", Some(meta_type::<Extra>())),
			])
			.docs(&["AppUncheckedExtrinsic raw bytes, requires custom decoding routine"])
			// Because of the custom encoding, we can only accurately describe the encoding as an
			// opaque `Vec<u8>`. Downstream consumers will need to manually implement the codec to
			// encode/decode the `signature` and `function` fields.
			.composite(Fields::unnamed().field(|f| f.ty::<Vec<u8>>()))
	}
}

#[cfg(feature = "std")]
impl<Address, Call, Signature, Extra> MallocSizeOf
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl<Address, Call, Signature, Extra: SignedExtension>
	AppUncheckedExtrinsic<Address, Call, Signature, Extra>
{
	/// New instance of a signed extrinsic aka "transaction".
	pub fn new_signed(function: Call, signed: Address, signature: Signature, extra: Extra) -> Self {
		Self {
			signature: Some((signed, signature, extra)),
			function,
		}
	}

	/// New instance of an unsigned extrinsic aka "inherent".
	pub fn new_unsigned(function: Call) -> Self {
		Self {
			signature: None,
			function,
		}
	}
}

impl<Address, Call, Signature, Extra: SignedExtension> Extrinsic
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
{
	type Call = Call;
	type SignaturePayload = (Address, Signature, Extra);

	fn is_signed(&self) -> Option<bool> { Some(self.signature.is_some()) }

	fn new(function: Call, signed_data: Option<Self::SignaturePayload>) -> Option<Self> {
		Some(if let Some((address, signature, extra)) = signed_data {
			Self::new_signed(function, address, signature, extra)
		} else {
			Self::new_unsigned(function)
		})
	}
}

impl<Address, AccountId, Call, Signature, Extra, Lookup> Checkable<Lookup>
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Member + MaybeDisplay,
	Call: Encode + Member,
	Signature: Member + traits::Verify,
	<Signature as traits::Verify>::Signer: IdentifyAccount<AccountId = AccountId>,
	Extra: SignedExtension<AccountId = AccountId>,
	AccountId: Member + MaybeDisplay,
	Lookup: traits::Lookup<Source = Address, Target = AccountId>,
	<Extra as SignedExtension>::AdditionalSigned: sp_std::fmt::Debug,
{
	type Checked = CheckedExtrinsic<AccountId, Call, Extra>;

	fn check(self, lookup: &Lookup) -> Result<Self::Checked, TransactionValidityError> {
		Ok(match self.signature {
			Some((signed, signature, extra)) => {
				let signed = lookup.lookup(signed)?;
				let raw_payload = SignedPayload::new(self.function, extra)?;

				log::debug!(
					"AppUncheckedExtrinsic: Signed: {:?}, Signature: {:?}, RawPayload: {:?}",
					signed,
					signature,
					raw_payload
				);

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
}

impl<Address, Call, Signature, Extra> ExtrinsicMetadata
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	type SignedExtensions = Extra;

	const VERSION: u8 = EXTRINSIC_VERSION;
}

impl<Address, Call, Signature, Extra> GetDispatchInfo
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Call: GetDispatchInfo,
	Extra: SignedExtension,
{
	fn get_dispatch_info(&self) -> DispatchInfo { self.function.get_dispatch_info() }
}

/// A payload that has been signed for an unchecked extrinsics.
///
/// Note that the payload that we sign to produce unchecked extrinsic signature
/// is going to be different than the `SignaturePayload` - so the thing the extrinsic
/// actually contains.
pub struct SignedPayload<Call, Extra: SignedExtension>((Call, Extra, Extra::AdditionalSigned));

impl<Call, Extra> Debug for SignedPayload<Call, Extra>
where
	Call: Debug,
	Extra: SignedExtension + Debug,
	Extra::AdditionalSigned: Debug,
{
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(
			f,
			"SignedPayload(call: {:?}, extra: {:?}, additional_signed: {:?})",
			self.0 .0, self.0 .1, self.0 .2
		)
	}
}

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
	pub fn deconstruct(self) -> (Call, Extra, Extra::AdditionalSigned) { self.0 }
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

impl<Address, Call, Signature, Extra> Decode
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Decode,
	Signature: Decode,
	Call: Decode,
	Extra: SignedExtension,
{
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		// This is a little more complicated than usual since the binary format must be compatible
		// with substrate's generic `Vec<u8>` type. Basically this just means accepting that there
		// will be a prefix of vector length (we don't need
		// to use this).
		let _length_do_not_remove_me_see_above: Compact<u32> = Decode::decode(input)?;

		let version = input.read_byte()?;

		let is_signed = version & 0b1000_0000 != 0;
		let version = version & 0b0111_1111;
		if version != EXTRINSIC_VERSION {
			return Err("Invalid transaction version".into());
		}

		Ok(Self {
			signature: if is_signed {
				Some(Decode::decode(input)?)
			} else {
				None
			},
			function: Decode::decode(input)?,
		})
	}
}

impl<Address, Call, Signature, Extra> Encode
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
	fn encode(&self) -> Vec<u8> {
		let mut tmp = Vec::with_capacity(sp_std::mem::size_of::<Self>());

		// 1 byte version id.
		match self.signature.as_ref() {
			Some(s) => {
				tmp.push(EXTRINSIC_VERSION | 0b1000_0000);
				s.encode_to(&mut tmp);
			},
			None => {
				tmp.push(EXTRINSIC_VERSION & 0b0111_1111);
			},
		}
		self.function.encode_to(&mut tmp);

		let compact_len = codec::Compact::<u32>(tmp.len() as u32);

		// Allocate the output buffer with the correct length
		let mut output = Vec::with_capacity(compact_len.size_hint() + tmp.len());

		compact_len.encode_to(&mut output);
		output.extend(tmp);

		output
	}
}

impl<Address, Call, Signature, Extra> EncodeLike
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
}

#[cfg(feature = "std")]
impl<Address: Encode, Signature: Encode, Call: Encode, Extra: SignedExtension> serde::Serialize
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn serialize<S>(&self, seq: S) -> Result<S::Ok, S::Error>
	where
		S: ::serde::Serializer,
	{
		self.using_encoded(|bytes| sp_core::bytes::serialize(bytes, seq))
	}
}

#[cfg(feature = "std")]
impl<'a, Address: Decode, Signature: Decode, Call: Decode, Extra: SignedExtension>
	serde::Deserialize<'a> for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn deserialize<D>(de: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'a>,
	{
		let r = sp_core::bytes::deserialize(de)?;
		Decode::decode(&mut &r[..])
			.map_err(|e| serde::de::Error::custom(format!("Decode error: {}", e)))
	}
}

impl<Address, Call, Signature, Extra> Debug
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: Debug,
	Call: Debug,
	Extra: SignedExtension,
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

impl<Address, Call, Signature, Extra> GetAppId
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension + GetAppId,
{
	fn app_id(&self) -> AppId {
		self.signature
			.as_ref()
			.map(|(_address, _signature, extra)| extra.app_id())
			.unwrap_or_default()
	}
}

impl<Address, Call, Signature, Extra> ExtrinsicCall
	for AppUncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: SignedExtension,
{
	fn call(&self) -> &Self::Call { &self.function }
}

impl<Address, Call, Signature, Extra> From<AppUncheckedExtrinsic<Address, Call, Signature, Extra>>
	for OpaqueExtrinsic
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: SignedExtension,
{
	fn from(extrinsic: AppUncheckedExtrinsic<Address, Call, Signature, Extra>) -> Self {
		Self::from_bytes(extrinsic.encode().as_slice()).expect(
			"both OpaqueExtrinsic and AppUncheckedExtrinsic have encoding that is compatible with \
				raw Vec<u8> encoding; qed",
		)
	}
}

#[cfg(test)]
mod tests {
	use sp_core::blake2_256;
	use sp_runtime::{
		codec::{Decode, Encode},
		testing::TestSignature as TestSig,
		traits::{IdentityLookup, SignedExtension},
	};

	use super::*;

	type TestContext = IdentityLookup<u64>;
	type TestAccountId = u64;
	type TestCall = Vec<u8>;

	const TEST_ACCOUNT: TestAccountId = 0;

	// NOTE: this is demonstration. One can simply use `()` for testing.
	#[derive(
		Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd, TypeInfo, MallocSizeOf,
	)]
	struct TestExtra;
	impl SignedExtension for TestExtra {
		type AccountId = u64;
		type AdditionalSigned = ();
		type Call = ();
		type Pre = ();

		const IDENTIFIER: &'static str = "TestExtra";

		fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
			Ok(())
		}
	}

	impl GetAppId for TestExtra {
		fn app_id(&self) -> AppId { Default::default() }
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
				(vec![0u8; 257], TestExtra).using_encoded(blake2_256)[..].to_owned(),
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
}