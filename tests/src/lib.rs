#[cfg(test)]
mod tests{
	use qserde::*;
	#[test]
	fn is_everything_ok_512(){
		let mut rng = rand::thread_rng();
		let (dk, ek) = generate_keypair512(&mut rng);
		let ek = EncapsulationKey512::from_bytes(&ek.to_bytes()).unwrap();
		let (enc, ss) = ek.encapsulate(&mut rng).unwrap();
		let ss1 = dk.decapsulate(&enc).unwrap();
		assert_eq!(ss, ss1);
	}
	#[test]
	fn is_everything_ok_768(){
		let mut rng = rand::thread_rng();
		let (dk, ek) = generate_keypair768(&mut rng);
		let ek = EncapsulationKey768::from_bytes(&ek.to_bytes()).unwrap();
		let (enc, ss) = ek.encapsulate(&mut rng).unwrap();
		let ss1 = dk.decapsulate(&enc).unwrap();
		assert_eq!(ss, ss1);
	}
	#[test]
	fn is_everything_ok_1024(){
		let mut rng = rand::thread_rng();
		let (dk, ek) = generate_keypair1024(&mut rng);
		let ek = EncapsulationKey1024::from_bytes(&ek.to_bytes()).unwrap();
		let (enc, ss) = ek.encapsulate(&mut rng).unwrap();
		let ss1 = dk.decapsulate(&enc).unwrap();
		assert_eq!(ss, ss1);
	}
}