use serde::{
	de::{self, EnumAccess, Visitor},
	Deserialize, Deserializer, Serialize, Serializer,
};
use sp_std::{fmt, marker::PhantomData};

#[cfg(feature = "header-backward-compatibility-test")]
use super::v_test;
use super::{v1, Header, HeaderNumberTrait, KateHashTrait};

impl<N, H> Serialize for Header<N, H>
where
	N: HeaderNumberTrait + Serialize,
	H: KateHashTrait,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match &self {
			Self::V1(ref header) => serializer.serialize_newtype_variant("Header", 0, "V1", header),
			#[cfg(feature = "header-backward-compatibility-test")]
			Self::VTest(ref header) => serializer.serialize_newtype_variant("Header", 1, "VTest", header),
		}
	}
}

impl<'de, N, H> Deserialize<'de> for Header<N, H>
where
	N: HeaderNumberTrait,
	H: KateHashTrait,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		enum Field {
			V1,
			#[cfg(feature = "header-backward-compatibility-test")]
			VTest,
		}
		struct FieldVisitor;
		impl<'de> Visitor<'de> for FieldVisitor {
			type Value = Field;

			fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
				write!(fmt, "variant identifier of Header<N,H>")
			}

			fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				match value {
					0u64 => Ok(Field::V1),
					#[cfg(feature = "header-backward-compatibility-test")]
					1u64 => Ok(Field::VTest),
					_ => Err(E::invalid_value(
						de::Unexpected::Unsigned(value),
						&"variant index 0 <= i < 1",
					)),
				}
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				match value {
					"V1" => Ok(Field::V1),
					#[cfg(feature = "header-backward-compatibility-test")]
					"VTest" => Ok(Field::VTest),
					_ => Err(de::Error::unknown_variant(value, VARIANTS)),
				}
			}

			fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				match value {
					b"V1" => Ok(Field::V1),
					#[cfg(feature = "header-backward-compatibility-test")]
					b"VTest" => Ok(Field::VTest),
					_ => {
						let value = String::from_utf8_lossy(value);
						Err(E::unknown_variant(&value, VARIANTS))
					},
				}
			}
		}

		impl<'de> Deserialize<'de> for Field {
			#[inline]
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: Deserializer<'de>,
			{
				Deserializer::deserialize_identifier(deserializer, FieldVisitor)
			}
		}

		struct HeaderVisitor<N: HeaderNumberTrait, H: KateHashTrait> {
			number: PhantomData<N>,
			hash: PhantomData<H>,
		}

		impl<'de, N, H> Visitor<'de> for HeaderVisitor<N, H>
		where
			N: HeaderNumberTrait,
			H: KateHashTrait,
		{
			type Value = Header<N, H>;

			fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
				write!(fmt, "enum Header<N,H>")
			}

			fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
			where
				A: EnumAccess<'de>,
			{
				let (field, variant) = EnumAccess::variant(data)?;
				match (field, variant) {
					(Field::V1, variant) => {
						let header =
							de::VariantAccess::newtype_variant::<v1::Header<N, H>>(variant)?;
						Ok(Header::V1(header))
					},
					#[cfg(feature = "header-backward-compatibility-test")]
					(Field::VTest, variant) => {
						let header =
							de::VariantAccess::newtype_variant::<v_test::Header<N, H>>(variant)?;
						Ok(Header::VTest(header))
					},
				}
			}
		}

		#[cfg(not(feature = "header-backward-compatibility-test"))]
		const VARIANTS: &'static [&'static str] = &["V1"];
		#[cfg(feature = "header-backward-compatibility-test")]
		const VARIANTS: &'static [&'static str] = &["V1", "VTest"];

		let visitor = HeaderVisitor::<N, H> {
			number: Default::default(),
			hash: Default::default(),
		};

		deserializer.deserialize_enum("Header", VARIANTS, visitor)
	}
}
