#![feature(test)]
pub mod constants;
pub mod keys;
pub mod member;
pub mod mlsag;
mod signature;
pub mod tests_helper;
mod transcript;

use constants::BASEPOINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;

/// Dummy Hash to curve
pub fn hash_to_curve(bytes: &[u8]) -> EdwardsPoint {
    let s = Scalar::hash_from_bytes::<Sha512>(bytes);
    BASEPOINT * s
}
