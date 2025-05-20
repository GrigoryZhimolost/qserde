#![no_std]

use ml_kem::{MlKem1024, MlKem768, MlKem512};
use ml_kem::KemCore;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::{MlKem1024Params, MlKem768Params, MlKem512Params};
use ml_kem::EncodedSizeUser;

use rand_core::{RngCore, CryptoRng};

pub type EncapsulationKey<T> = ml_kem::kem::EncapsulationKey<T>;

///Creates ml-kem 1024 bit size keypair 
#[inline]
pub fn create_keypair_1024<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(ml_kem::kem::DecapsulationKey<MlKem1024Params>, 
	ml_kem::kem::EncapsulationKey<MlKem1024Params>) 
	where CryptoRngCore: RngCore + CryptoRng {
	MlKem1024::generate(rng)
}

///Creates ml-kem 768 bit size keypair 
#[inline]
pub fn create_keypair_768<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(ml_kem::kem::DecapsulationKey<MlKem768Params>, 
	ml_kem::kem::EncapsulationKey<MlKem768Params>) 
	where CryptoRngCore: RngCore + CryptoRng {
	MlKem768::generate(rng)
}

///Creates ml-kem 512 bit size keypair 
#[inline]
pub fn create_keypair_512<CryptoRngCore>(rng: &mut CryptoRngCore) ->
	(ml_kem::kem::DecapsulationKey<MlKem512Params>, 
	ml_kem::kem::EncapsulationKey<MlKem512Params>) 
	where CryptoRngCore: RngCore + CryptoRng {
	MlKem512::generate(rng)
}


///Serializes ml-kem 512 bit size encapsulation key into bytes
#[inline]
pub fn enc_key_to_bytes_512(key: &ml_kem::kem::EncapsulationKey<MlKem512Params>) -> [u8; 800] {
    let mut result = [0u8; 800];
	for (ind, i) in key.as_bytes().iter().enumerate(){
        result[ind] = *i;
    }

    result
}

///Serializes ml-kem 768 bit size encapsulation key into bytes
#[inline]
pub fn enc_key_to_bytes_768(key: &ml_kem::kem::EncapsulationKey<MlKem768Params>) -> [u8; 1184] {
    let mut result = [0u8; 1184];
	for (ind, i) in key.as_bytes().iter().enumerate(){
        result[ind] = *i;
    }

    result
}

///Serializes ml-kem 1024 bit size encapsulation key into bytes
#[inline]
pub fn enc_key_to_bytes_1024(key: &ml_kem::kem::EncapsulationKey<MlKem1024Params>) -> [u8; 1568] {
    let mut result = [0u8; 1568];
	for (ind, i) in key.as_bytes().iter().enumerate(){
        result[ind] = *i;
    }

    result
}

///Restores encapsulation key from bytes
#[inline]
pub fn enc_key_from_bytes_1024(key: &[u8; 1568]) -> Option<ml_kem::kem::EncapsulationKey<MlKem1024Params>> {
    if let Ok(val) = ml_kem::array::Array::try_from_iter((*key).into_iter()){
        let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem1024Params>> = val;
        return Some(ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation));
    }

    None	
}

///Restores encapsulation key from bytes
#[inline]
pub fn enc_key_from_bytes_768(key: &[u8; 1184]) -> Option<ml_kem::kem::EncapsulationKey<MlKem768Params>> {
    if let Ok(val) = ml_kem::array::Array::try_from_iter((*key).into_iter()){
        let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem768Params>> = val;
        return Some(ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation));
    }

    None	
}

///Restores encapsulation key from bytes
#[inline]
pub fn enc_key_from_bytes_512(key: &[u8; 800]) -> Option<ml_kem::kem::EncapsulationKey<MlKem512Params>> {
    if let Ok(val) = ml_kem::array::Array::try_from_iter((*key).into_iter()){
        let type_annotation: ml_kem::Encoded<ml_kem::kem::EncapsulationKey<MlKem512Params>> = val;
        return Some(ml_kem::kem::EncapsulationKey::from_bytes(&type_annotation));
    }

    None	
}

///Encapsulates a random 256 bit key with the given enc key. Returns encapsulated and untouched key as a tuple inside Option
#[inline]
pub fn encapsulate_1024 <CryptoRngCore>(rng: &mut CryptoRngCore, ek: &ml_kem::kem::EncapsulationKey<MlKem1024Params>) ->
	Option<([u8; 1568], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
	let mr = ek.encapsulate(rng);

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

///Encapsulates a random 256 bit key with the given enc key. Returns encapsulated and untouched key as a tuple inside Option
#[inline]
pub fn encapsulate_768 <CryptoRngCore>(rng: &mut CryptoRngCore, ek: &ml_kem::kem::EncapsulationKey<MlKem768Params>) ->
	Option<([u8; 1088], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
	let mr = ek.encapsulate(rng);

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

///Encapsulates a random 256 bit key with the given enc key. Returns encapsulated and untouched key as a tuple inside Option
#[inline]
pub fn encapsulate_512 <CryptoRngCore>(rng: &mut CryptoRngCore, ek: &ml_kem::kem::EncapsulationKey<MlKem512Params>) ->
	Option<([u8; 768], [u8; 32])>
	where CryptoRngCore: RngCore + CryptoRng {
	let mr = ek.encapsulate(rng);

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

///Decapsulates encapsulated key
pub fn decapsulate_1024(data: &[u8; 1568], dk: &ml_kem::kem::DecapsulationKey<MlKem1024Params>) ->
	Option<[u8; 32]> {
	use ml_kem::array::typenum;

	let ta: Result<ml_kem::array::Array<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

	if let Err(_) = ta {
		return None;
	}

	let ta  = ta.unwrap();
	let key = dk.decapsulate(&ta);

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

///Decapsulates encapsulated key
pub fn decapsulate_512(data: &[u8; 768], dk: &ml_kem::kem::DecapsulationKey<MlKem512Params>) ->
	Option<[u8; 32]> {
	use ml_kem::array::typenum::{uint::*, bit::*};

	let ta: Result<ml_kem::array::Array<_, UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, _>, B1>, _>, _>, B0>, _>, _>, _>, _>, _>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

	if let Err(_) = ta {
		return None;
	}

	let ta  = ta.unwrap();
	let key = dk.decapsulate(&ta);

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

///Decapsulates encapsulated key
pub fn decapsulate768(data: &[u8; 1088], dk: &ml_kem::kem::DecapsulationKey<MlKem768Params>) ->
	Option<[u8; 32]> {
	use ml_kem::array::typenum;

	let ta: Result<ml_kem::array::Array<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>, ml_kem::array::TryFromIteratorError> = ml_kem::array::Array::try_from_iter((*data).into_iter());

	if let Err(_) = ta {
		return None;
	}

	let ta  = ta.unwrap();
	let key = dk.decapsulate(&ta);

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