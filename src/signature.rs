use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::member::*;

#[derive(Debug)]
pub struct Signature {
    pub(crate) challenge: Scalar,
    pub(crate) responses: Vec<Scalar>,
    pub(crate) key_images: Vec<CompressedRistretto>,
}

pub enum Error {
    // This error occurs if the signature contains an amount of
    // responses, that does not match the number of key images
    IncorrectNumOfResponses,
    // This error occurs if the signature contains an amount of public keys
    // that does not match the number of public keys
    IncorrectNumOfPubKeys,
    // This error occurs when either one of the key images supplied cannot be decompressed
    BadKeyImages,
    // This error occurs when the calculated challenge is different from the challenge in the signature
    ChallengeMismatch,
    // This error occurs when an underlying error from the member package occurs
    MemberError(String),
}

impl From<crate::member::Error> for Error {
    fn from(e: crate::member::Error) -> Error {
        let err_string = format!(" underlying member error {:?}", e);
        Error::MemberError(err_string)
    }
}

impl Signature {
    pub fn verify(&self, public_keys: &mut [RistrettoPoint], msg: &[u8]) -> Result<(), Error> {
        // Skip subgroup check as ristretto points have co-factor 1.

        // -- Check that we have the correct amount of responses
        //  Since `number of public keys = number of users * number of keys per user`
        // And `number of responses = number of users * number of keys per user`
        // `number of responses = number of total public keys`
        // `number of key images = number of keys for the signer`
        //  This is equal to the number of keys per user because all members have the same
        //  amount of keys.
        //  We can then calculate `number of users = number of responses / number of key images`
        let num_key_images = self.key_images.len();
        let num_responses = self.responses.len();
        if num_responses % num_key_images != 0 {
            return Err(Error::IncorrectNumOfResponses);
        }

        // -- Check that we have the correct amount of public keys
        if public_keys.len() != num_responses {
            return Err(Error::IncorrectNumOfPubKeys);
        }

        let chunked_pub_keys: Vec<_> = public_keys.chunks(num_key_images).collect();
        let chunked_responses: Vec<_> = self.responses.chunks(num_key_images).collect();

        let decomp_key_images = self.decompress_key_images()?;
        let mut challenge = self.challenge.clone();
        for (pub_keys, responses) in chunked_pub_keys.iter().zip(chunked_responses.iter()) {
            challenge =
                compute_challenge_ring(pub_keys, &challenge, &decomp_key_images, responses, msg);
        }

        if self.challenge != challenge {
            return Err(Error::ChallengeMismatch);
        }

        Ok(())
    }

    fn decompress_key_images(&self) -> Result<Vec<RistrettoPoint>, Error> {
        let mut decompressed_key_images = Vec::with_capacity(self.key_images.len());
        for key_image in self.key_images.iter() {
            let dec_key_image = key_image.decompress().ok_or(Error::BadKeyImages)?;
            decompressed_key_images.push(dec_key_image);
        }
        Ok(decompressed_key_images)
    }
}

#[cfg(test)]
mod test {
    extern crate test;
    use crate::tests_helper::*;
    use test::Bencher;

    use crate::constants;

    use rand::seq::SliceRandom;
    use rand::thread_rng;

    #[test]
    fn test_verify_fail_shuffle_keys() {
        let num_keys = 2;
        let num_decoys = 11;
        let msg = b"hello world";

        let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
        mlsag.add_member(generate_signer(num_keys));
        let sig = mlsag.sign(msg).unwrap();
        let mut pub_keys = mlsag.public_keys();

        // shuffle public key ordering
        pub_keys.shuffle(&mut thread_rng());
        assert!(sig.verify(&mut pub_keys, msg).is_err());
    }
    #[test]
    fn test_verify_fail_incorrect_num_keys() {
        let num_keys = 2;
        let num_decoys = 11;
        let msg = b"hello world";

        let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
        mlsag.add_member(generate_signer(num_keys));
        let sig = mlsag.sign(msg).unwrap();
        let mut pub_keys = mlsag.public_keys();

        // Add extra key
        pub_keys.push(constants::BASEPOINT);
        assert!(sig.verify(&mut pub_keys, msg).is_err());

        // remove the extra key and test should pass
        pub_keys.remove(pub_keys.len() - 1);
        assert!(sig.verify(&mut pub_keys, msg).is_ok());

        // remove another key and tests should fail
        pub_keys.remove(pub_keys.len() - 1);
        assert!(sig.verify(&mut pub_keys, msg).is_err());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        // One time setup code here
        let num_keys = 2;
        let num_decoys = 11;
        let msg = b"hello world";

        let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
        mlsag.add_member(generate_signer(num_keys));
        let sig = mlsag.sign(msg).unwrap();
        let mut pub_keys = mlsag.public_keys();

        b.iter(|| sig.verify(&mut pub_keys, msg));
    }
}
