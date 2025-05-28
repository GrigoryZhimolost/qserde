#![no_std]

/** qserde is a non-std rust library for serializing/deserializing ml-kem(aka kyber) public key, encapsulating/decapsulating 256 bit keys and so on.
## WARNING
Current version of ml-kem crate used in this crate **does not support rand crate of 0.9.x versions**, so if everything doesn't work maybe you should **downgrade the rand crate version** to at least *0.8.5*
# usage
Use _generate_keypair{512/768/1024}_ to generate keypair, encapsulation key's functions *to_bytes*, *from_bytes*, *encapsulate* to do encapsulation, serialize and deserialize it. And *decapsulate* func of DecapsulationKey to decapsulate ciphertexts
Here's usage example below:

` rust
use qserde::*;

let mut rng = rand::thread_rng();

//generating ml_kem keypair of 1024-bit mode
let (dk, ek) = generate_keypair1024(&mut rng);

//encapsulation key deserialized into bytes
let serialized_encapsulaion_key = ek.to_bytes();

//converting bytes into 1024-bit mode encapsulation key
let ek = EncapsulationKey1024::from_bytes(&ek).unwrap();

//encapsulating random 32 bytes
let (ciphertext, shared_secret) = ek.encapsulate(&mut rng).unwrap();

//decapsulating shared secret from ciphertext
let another_shared_secret = dk.decapsulate(&ciphertext).unwrap();

assert_eq!(shared_secret, another_shared_secret);
`
*/

use ml_kem::{MlKem1024, MlKem768, MlKem512};
use ml_kem::KemCore;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::{MlKem1024Params, MlKem768Params, MlKem512Params};
use ml_kem::EncodedSizeUser;

use rand_core::{RngCore, CryptoRng};

///1024-bit ml-kem decapsulation key
pub struct DecapsulationKey1024{
	dk: ml_kem::kem::DecapsulationKey<MlKem1024Params>
}

///768-bit ml-kem decapsulation key
pub struct DecapsulationKey768{
	dk: ml_kem::kem::DecapsulationKey<MlKem768Params>
}

///512-bit ml-kem decapsulation key
pub struct DecapsulationKey512{
	dk: ml_kem::kem::DecapsulationKey<MlKem512Params>
}

///1024-bit ml-kem encapsulation key
pub struct EncapsulationKey1024{
	ek: ml_kem::kem::EncapsulationKey<MlKem1024Params>
}

///768-bit ml-kem encapsulation key
pub struct EncapsulationKey768{
	ek: ml_kem::kem::EncapsulationKey<MlKem768Params>
}

///512-bit ml-kem encapsulation key
pub struct EncapsulationKey512{
	ek: ml_kem::kem::EncapsulationKey<MlKem512Params>
}

impl EncapsulationKey1024{
	#[inline]
	pub fn from(ek: ml_kem::kem::EncapsulationKey<MlKem1024Params>) -> Self {
		Self{ ek }
	}

	///Encapsulation key serialization
	#[inline]
	pub fn to_bytes(&self) -> [u8; 1568]{
		let mut result = [0u8; 1568];

		for (ind, i) in self.ek.as_bytes().iter().enumerate(){
        	result[ind] = *i;
    	}

    	result
	}

	///Encapsulation key deserialization
	#[inline]
	pub fn from_bytes(bytes: &[u8; 1568]) -> Option<Self>{
		if let Ok(val) = ml_kem::array::Array::try_from_iter((*bytes).into_iter()){
			let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem1024Params>> = val;
			return Some(Self{ek: ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation)});
		}
	
		None
	}

	///Encapsulates random bytes
	#[inline]
	pub fn encapsulate <CryptoRngCore>(self, rng: &mut CryptoRngCore) ->
	Option<([u8; 1568], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
		let mr = self.ek.encapsulate(rng);

		if mr.is_err(){
			return None;
		}

		let (en, ss) = mr.unwrap();

		let mut rss = [0u8; 32];
		for (ind, i) in ss.as_slice().iter().enumerate(){
			rss[ind] = *i;
		}

		let mut r = [0u8; 1568];
		for (ind, i) in en.as_slice().iter().enumerate(){
			r[ind] = *i;
		}

		Some((r, rss))
	}
}
impl EncapsulationKey768{
	#[inline]
	pub fn from(ek: ml_kem::kem::EncapsulationKey<MlKem768Params>) -> Self {
		Self{ ek }
	}

	///Encapsulation key serialization
	#[inline]
	pub fn to_bytes(&self) -> [u8; 1184]{
		let mut result = [0u8; 1184];

		for (ind, i) in self.ek.as_bytes().iter().enumerate(){
        	result[ind] = *i;
    	}

    	result
	}

	///Encapsulation key deserialization
	#[inline]
	pub fn from_bytes(bytes: &[u8; 1184]) -> Option<Self>{
		if let Ok(val) = ml_kem::array::Array::try_from_iter((*bytes).into_iter()){
			let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem768Params>> = val;
			return Some(Self{ek: ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation)});
		}
	
		None
	}

	///Encapsulates random bytes
	#[inline]
	pub fn encapsulate <CryptoRngCore>(self, rng: &mut CryptoRngCore) ->
	Option<([u8; 1088], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
		let mr = self.ek.encapsulate(rng);

		if mr.is_err(){
			return None;
		}

		let (en, ss) = mr.unwrap();

		let mut rss = [0u8; 32];
		for (ind, i) in ss.as_slice().iter().enumerate(){
			rss[ind] = *i;
		}

		let mut r = [0u8; 1088];
		for (ind, i) in en.as_slice().iter().enumerate(){
			r[ind] = *i;
		}

		Some((r, rss))
	}
}
impl EncapsulationKey512{
	#[inline]
	pub fn from(ek: ml_kem::kem::EncapsulationKey<MlKem512Params>) -> Self {
		Self{ ek }
	}

	///Encapsulation key serialization
	#[inline]
	pub fn to_bytes(&self) -> [u8; 800]{
		let mut result = [0u8; 800];

		for (ind, i) in self.ek.as_bytes().iter().enumerate(){
        	result[ind] = *i;
    	}

    	result
	}

	///Encapsulation key deserialization
	#[inline]
	pub fn from_bytes(bytes: &[u8; 800]) -> Option<Self>{
		if let Ok(val) = ml_kem::array::Array::try_from_iter((*bytes).into_iter()){
			let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem512Params>> = val;
			return Some(Self{ek: ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation)});
		}
	
		None
	}

	///Encapsulates random bytes
	#[inline]
	pub fn encapsulate <CryptoRngCore>(self, rng: &mut CryptoRngCore) ->
	Option<([u8; 768], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
		let mr = self.ek.encapsulate(rng);

		if mr.is_err(){
			return None;
		}

		let (en, ss) = mr.unwrap();

		let mut rss = [0u8; 32];
		for (ind, i) in ss.as_slice().iter().enumerate(){
			rss[ind] = *i;
		}

		let mut r = [0u8; 768];
		for (ind, i) in en.as_slice().iter().enumerate(){
			r[ind] = *i;
		}

		Some((r, rss))
	}
}

impl DecapsulationKey1024{
	#[inline]
	pub fn from(dk: ml_kem::kem::DecapsulationKey<MlKem1024Params>) -> Self{
		Self{ dk }
	}

	///Decapsulates a ciphertext into a shared secret
	#[inline]
	pub fn decapsulate(&self, data: &[u8; 1568]) ->
	Option<[u8; 32]> {
		use ml_kem::array::typenum;

		let ta: Result<ml_kem::array::Array<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

		if let Err(_) = ta {
			return None;
		}

		let ta  = ta.unwrap();
		let key = self.dk.decapsulate(&ta);

		if key.is_err() {
			return None;
		}
		let key = key.unwrap();
		let key: &[u8] = key.as_slice();

		assert_eq!(key.len(), 32);
		let mut res = [0u8; 32];

		for (ind, i) in key.into_iter().enumerate(){
			res[ind] = *i;
		}

		Some(res)
	}
}
impl DecapsulationKey768{
	#[inline]
	pub fn from(dk: ml_kem::kem::DecapsulationKey<MlKem768Params>) -> Self{
		Self{ dk }
	}

	///Decapsulates a ciphertext into a shared secret
	#[inline]
	pub fn decapsulate(&self, data: &[u8; 1088]) ->
	Option<[u8; 32]> {
		use ml_kem::array::typenum;

		let ta: Result<ml_kem::array::Array<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

		if let Err(_) = ta {
			return None;
		}

		let ta  = ta.unwrap();
		let key = self.dk.decapsulate(&ta);

		if key.is_err() {
			return None;
		}
		let key = key.unwrap();
		let key: &[u8] = key.as_slice();

		assert_eq!(key.len(), 32);
		let mut res = [0u8; 32];

		for (ind, i) in key.into_iter().enumerate(){
			res[ind] = *i;
		}

		Some(res)
	}
}
impl DecapsulationKey512{
	#[inline]
	pub fn from(dk: ml_kem::kem::DecapsulationKey<MlKem512Params>) -> Self{
		Self{ dk }
	}

	///Decapsulates a ciphertext into a shared secret
	#[inline]
	pub fn decapsulate(&self, data: &[u8; 768]) ->
	Option<[u8; 32]> {
		use ml_kem::array::typenum::{uint::*, bit::*};

		let ta: Result<ml_kem::array::Array<_, UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, _>, B1>, _>, _>, B0>, _>, _>, _>, _>, _>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

		if let Err(_) = ta {
			return None;
		}

		let ta  = ta.unwrap();
		let key = self.dk.decapsulate(&ta);

		if key.is_err() {
			return None;
		}
		let key = key.unwrap();
		let key: &[u8] = key.as_slice();

		assert_eq!(key.len(), 32);
		let mut res = [0u8; 32];

		for (ind, i) in key.into_iter().enumerate(){
			res[ind] = *i;
		}

		Some(res)
	}
}

///Creates ml-kem 1024 bit size keypair 
#[inline]
pub fn generate_keypair1024<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(DecapsulationKey1024, 
	EncapsulationKey1024) 
	where CryptoRngCore: RngCore + CryptoRng {

	let (dk, ek) = MlKem1024::generate(rng);
	(DecapsulationKey1024::from(dk), EncapsulationKey1024::from(ek))
}

///Creates ml-kem 768 bit size keypair 
#[inline]
pub fn generate_keypair768<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(DecapsulationKey768, 
	EncapsulationKey768) 
	where CryptoRngCore: RngCore + CryptoRng {

	let (dk, ek) = MlKem768::generate(rng);
	(DecapsulationKey768::from(dk), EncapsulationKey768::from(ek))
}

///Creates ml-kem 512 bit size keypair 
#[inline]
pub fn generate_keypair512<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(DecapsulationKey512, 
	EncapsulationKey512) 
	where CryptoRngCore: RngCore + CryptoRng {

	let (dk, ek) = MlKem512::generate(rng);
	(DecapsulationKey512::from(dk), EncapsulationKey512::from(ek))
}