# qserde
It is a non-std rust library for serializing/deserializing ml-kem(aka kyber) public key, encapsulating/decapsulating 256 bit keys and so on.
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