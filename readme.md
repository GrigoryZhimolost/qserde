# qserde
It is a rust library for serializing/deserializing ml-kem(aka kyber) public key, encapsulating/decapsulating 256 bit keys. By the way, current version of ml-kem package used in this crate **does not support rand crate of 0.9.x versions**, so if everything doesn't work maybe you should **downgrade the rand version**
# usage
There are create_keypair, enc_key_to_bytes, enc_key_from_bytes, encapsulate and decapsulate functions in this crate for 512, 768, 1024 ml-kem modes(these numbers are added to end of function's name). Here's usage example below:

` rust
use qserde::*;

let mut rng = rand::thread_rng();
let (ek, dk) = create_keypair_1024(&mut rng);

let serialized_enc_key = enc_key_to_bytes_1024(&ek);
let ek = enc_key_from_bytes_1024(&serialized_enc_key).unwrap();

let (encapsulated_shared_secret, shared_secret) = encapsulate_1024(&mut rng, &ek).unwrap();

let second_shared_secret = decapsulate_1024(&encapsulated_shared_secret, &dk).unwrap();

assert_eq!(shared_secret, second_shared_secret);
`