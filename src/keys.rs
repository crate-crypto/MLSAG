use crate::constants::BASEPOINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;

use std::collections::HashSet;
// Public key set represents a set of public keys
// note that this is not a `tuple`. A tuple allows duplicates while a set
// does not. While this is not a limitation placed upon the protocol by the
// maths, placing duplicated keys into this vector is akin
// to proving that you own the same key twice. This restriction will be placed
// onto the protocol at this level, as the author cannot think of a
// context where proving you own the same key twice would be useful.
#[derive(Debug, Clone)]
pub struct PublicSet(pub Vec<RistrettoPoint>);

impl PublicSet {
    // Returns the number of public keys in the set
    pub fn len(&self) -> usize {
        self.0.len()
    }
    // Checks if the public set contains any duplicate keys
    pub fn duplicates_exist(&self) -> bool {
        // XXX: Very in-efficient way to do this.
        // We can wait for upstream crate to implement Hash and use a HashSet instead

        let compressed_points: Vec<CompressedRistretto> =
            self.0.iter().map(|point| point.compress()).collect();

        let hashable_slice: Vec<&[u8; 32]> =
            compressed_points.iter().map(|cp| cp.as_bytes()).collect();

        let uniques: HashSet<_> = hashable_slice.iter().collect();

        self.0.len() != uniques.len()
    }
    // Copies the public key set into a vector of bytes
    pub fn compress(&self) -> Vec<CompressedRistretto> {
        self.0.iter().map(|point| point.compress()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct PrivateSet(pub(crate) Vec<Scalar>);

impl PrivateSet {
    pub fn new(scalars: Vec<Scalar>) -> Self {
        PrivateSet(scalars)
    }
    // Takes a set of private keys
    // and returns the corresponding public key set
    pub fn to_public_set(&self) -> PublicSet {
        let public_keys = self
            .0
            .iter()
            .map(|&x| x * BASEPOINT)
            .collect::<Vec<RistrettoPoint>>();

        PublicSet(public_keys)
    }

    // Returns all of the keyImages for a specific private key set
    // We calculate the key image using the formula keyImage = privateKey * HashToPoint(PublicKey)
    // Note that the HashToPoint must not allow the basepoint in the public key to be factored out
    pub fn compute_key_images(&self, public_set: &PublicSet) -> Vec<RistrettoPoint> {
        // Set of private keys must be the same length as the set of private keys
        assert_eq!(self.len(), public_set.len());

        let num_public_keys = public_set.len();

        let mut key_images: Vec<RistrettoPoint> = Vec::with_capacity(num_public_keys);

        for i in 0..num_public_keys {
            let public_key_i = public_set.0[i].compress();
            let private_key_i = self.0[i];

            let hashed_public_key =
                RistrettoPoint::hash_from_bytes::<Sha512>(public_key_i.as_bytes());

            let key_image = private_key_i * hashed_public_key;

            key_images.push(key_image);
        }

        key_images
    }

    // Returns the number of private keys in the set
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests_helper::*;
    // This test is a sanity check for private to public key sets.
    // The iter method is used when converting from a set of private keys
    // to a set of public keys. In the test, we use a for loop and check that both
    // are equal.
    #[test]
    fn private_set_to_public_set() {
        let private_set = generate_private_set(10);
        let public_set = private_set.to_public_set();

        assert_eq!(private_set.len(), public_set.len());

        for i in 0..private_set.len() {
            match (private_set.0.get(i), public_set.0.get(i)) {
                (Some(private_key), Some(expected_public_key)) => {
                    let public_key = private_key * &BASEPOINT;
                    assert_eq!(public_key, *expected_public_key);
                }
                _ => panic!("could not get the private/public key at index {} ", i),
            }
        }
    }
    #[test]
    fn check_duplicates_exist() {
        let private_set = generate_private_set(10);
        let mut public_set = private_set.to_public_set();

        let dup_exists = public_set.duplicates_exist();
        assert!(!dup_exists);

        let last_element = public_set.0.last().unwrap().clone();
        public_set.0[0] = last_element;

        let dup_exists = public_set.duplicates_exist();
        assert!(dup_exists);
    }
}
