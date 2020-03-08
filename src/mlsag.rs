use crate::member::Member;
use crate::signature::Signature;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

// This module will pull together all of the necessary things
// Setting up everything we need
#[derive(Debug)]
pub enum Error {
    // This error occurs when the sign method is called
    // without a signer being in the ring
    NoSigner,
    // This error occurs if there are less than 2 members in the ring
    NotEnoughMembers,
    // This error occurs if all members do not have the same number of keys
    NumberOfKeysMismatch,
    // This error occurs if there is more than one signer in the ring
    MoreThanOneSigner,
    // This error occurs if a member in the ring has duplicate keys
    DuplicateKeysExist,
    // This error occurs when an underlying module produces an error
    UnderlyingErr(String),
}

impl From<crate::member::Error> for crate::mlsag::Error {
    fn from(e: crate::member::Error) -> crate::mlsag::Error {
        match e {
            crate::member::Error::NotASigner => Error::UnderlyingErr(String::from(
                "Tried to use a method specific to a signer in the mlsag module",
            )),
            crate::member::Error::NotADecoy => Error::UnderlyingErr(String::from(
                "Tried to use a method specific to a decoy in the mlsag module",
            )),
        }
    }
}
// This struct is used to construct the mlsag signature
pub struct Mlsag {
    members: Vec<Member>,
}

impl Mlsag {
    // Creates a new Mlsag component with a configured basepoint
    pub fn new() -> Self {
        Mlsag {
            members: Vec::new(),
        }
    }
    // Adds a member to the Mlsag component
    // Use this method to add decoys and signers to the struct
    pub fn add_member(&mut self, member: Member) {
        self.members.push(member);
    }
    // Returns public keys from all known members
    pub fn public_keys(&self) -> Vec<EdwardsPoint> {
        self.members
            .iter()
            .map(|member| &member.public_set.0)
            .flatten()
            .cloned()
            .collect()
    }
    // sign produces a Mlsag signature
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        self.check_format()?;

        let num_members = self.members.len();
        let mut all_challenges: Vec<Scalar> = Vec::with_capacity(num_members);

        // Fetch signer of the ring
        let signer_index = self.find_signer()?;
        let signer = &self.members[signer_index];

        // Compute key images for signer
        let key_images = signer.compute_key_images()?;

        // Commit all randomly generated nonces to produce the first commitment
        // In this phase, we can imagine that each member produces the challenge for the member in
        // the position after them.
        let mut challenge = signer.compute_challenge_commitment(msg)?;
        all_challenges.push(challenge);

        // seed challenge into for loop starting from member after signer
        for decoy in self
            .members
            .iter()
            .cycle()
            .skip(signer_index + 1)
            .take(num_members - 1)
        {
            challenge = decoy.compute_decoy_challenge(&challenge, &key_images, msg)?;
            all_challenges.push(challenge);
        }

        // The last challenge variable should be the one generated by the member before the signer,
        // which will be for the signer. The signer will use this to generate his response values
        // and close the ring
        let mut signers_responses = signer.compute_signer_responses(challenge)?;

        // Collect all responses
        let mut all_responses: Vec<Scalar> = Vec::with_capacity(num_members * signer.num_keys());
        for member in &self.members {
            match member.is_signer() {
                true => {
                    all_responses.append(&mut signers_responses);
                }
                false => {
                    let mut mem_response = member.responses.clone();
                    all_responses.append(&mut mem_response);
                }
            }
        }

        // Collect first members challenge
        // The last element in the vector of challenges will be the signers challenge
        // Since we also know the index `n` of the signer. We need to walk back `n` times
        // This is equivalent to reversing the vector and getting the `n`th element
        // to fetch the first challenge; the challenge corresponding to the first member
        all_challenges.reverse();
        let first_challenge = all_challenges[signer_index];

        // Compress key image points
        let compressed_key_images = key_images.into_iter().map(|x| x.compress()).collect();

        Ok(Signature {
            challenge: first_challenge,
            responses: all_responses,
            key_images: compressed_key_images,
        })
    }
    // Returns the position of the signer in the ring
    // If this call is completed after check_format, it should not fail
    // as check_format ensures there is one signer. This method has been
    // added for a cleaner API. The alternative would be for the method which checks
    // that MLSAG is formatted correctly, to also return the signer.
    pub fn find_signer(&self) -> Result<usize, Error> {
        let signer_index = self
            .members
            .iter()
            .position(|member| member.is_signer())
            .ok_or(Error::NoSigner)?;

        Ok(signer_index)
    }
    // Returns the number of signers in the ring
    pub fn num_signers(&self) -> usize {
        let signers: Vec<&Member> = self
            .members
            .iter()
            .filter(|member| member.is_signer())
            .collect();
        signers.len()
    }
    // Checks that the Mlsag is correctly constructed
    fn check_format(&self) -> Result<(), Error> {
        // Check that we have more than one member
        if self.members.len() < 2 {
            return Err(Error::NotEnoughMembers);
        }

        // Check there is only one signer in the ring
        let num_signers = self.num_signers();
        match num_signers {
            0 => return Err(Error::NoSigner),
            1 => (),
            _ => return Err(Error::MoreThanOneSigner),
        };

        // Check that each member has the same number of keys
        let first_member_num_keys = self.members[0].num_keys();
        let all_same_num_keys = self
            .members
            .iter()
            .all(|member| member.num_keys() == first_member_num_keys);
        if !all_same_num_keys {
            return Err(Error::NumberOfKeysMismatch);
        }

        // Check that each member has no duplicates
        let no_duplicates_exists = self
            .members
            .iter()
            .all(|member| !member.public_set.duplicates_exist());
        if !no_duplicates_exists {
            return Err(Error::DuplicateKeysExist);
        }
        Ok(())
    }
}
#[cfg(test)]
mod test {
    extern crate test;

    use super::*;
    use crate::tests_helper::*;
    use test::Bencher;

    #[test]
    fn test_check_format() {
        let num_decoys = 10;
        let num_keys = 3;
        let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
        let msg = b"hello world";

        // No signer in the ring
        match mlsag.sign(msg) {
            Ok(_) => panic!("expected an error as there is no signer in the ring"),
            Err(Error::NoSigner) => {}
            Err(_) => panic!("got an error, however we expected no signer error"),
        }

        // Add a signer
        mlsag.add_member(generate_signer(num_keys));
        // Another one
        mlsag.add_member(generate_signer(num_keys));

        // More than one signer in the ring
        match mlsag.sign(msg) {
            Ok(_) => panic!("expected an error as there are too many signers in the ring"),
            Err(Error::MoreThanOneSigner) => {}
            Err(_) => panic!("got an error, however we expected a more than one signer error"),
        }

        mlsag = generate_mlsag_with(num_decoys, num_keys);
        // Add different number of keys
        mlsag.add_member(generate_decoy(num_keys + 1));

        // Add correct signer
        mlsag.add_member(generate_signer(num_keys));

        // One member has a different number of keys
        match mlsag.sign(msg) {
            Ok(_) => {
                panic!("expected an error as one member has more keys than another in the ring")
            }
            Err(Error::NumberOfKeysMismatch) => {}
            Err(_) => panic!("got an error, however we expected a `number of keys mismatch` error"),
        };

        mlsag = generate_mlsag_with(num_decoys, num_keys);
        // Add correct signer
        mlsag.add_member(generate_signer(num_keys));

        // Set the first key in members key set to the value of the last key
        let first_member = &mut mlsag.members[0];
        let first_member_last_element = &mut first_member.public_set.0.last().unwrap();
        first_member.public_set.0[0] = first_member_last_element.clone();

        match mlsag.sign(msg) {
            Ok(_) => panic!("expected an error as one member has a duplicate key"),
            Err(Error::DuplicateKeysExist) => {}
            Err(_) => panic!("got an error, however we expected a `duplicate keys` error"),
        };
    }

    #[test]
    fn test_sign_no_error() {
        let num_decoys = 10;
        let num_keys = 3;
        let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
        let msg = b"hello world";
        // Add a signer
        mlsag.add_member(generate_signer(num_keys));

        // Should produce no error
        let signature = mlsag.sign(msg).unwrap();

        // number of key images should equal number of keys
        assert_eq!(num_keys, signature.key_images.len());

        // number of responses should equal number of key images * number of members
        // number of members = number of decoys + signer
        let num_members = num_decoys + 1;
        assert_eq!(num_members * num_keys, signature.responses.len());
    }

    macro_rules! param_bench_verify {
        ($func_name: ident,$num_keys:expr, $num_decoys :expr) => {
            #[bench]
            fn $func_name(b: &mut Bencher) {
                let num_keys = $num_keys;
                let num_decoys = $num_decoys;
                let msg = b"hello world";

                let mut mlsag = generate_mlsag_with(num_decoys, num_keys);
                mlsag.add_member(generate_signer(num_keys));
                let sig = mlsag.sign(msg).unwrap();
                let mut pub_keys = mlsag.public_keys();

                b.iter(|| sig.verify(&mut pub_keys, msg));
            }
        };
    }

    param_bench_verify!(bench_verify_2, 2, 2);
    param_bench_verify!(bench_verify_4, 2, 3);
    param_bench_verify!(bench_verify_6, 2, 5);
    param_bench_verify!(bench_verify_8, 2, 7);
    param_bench_verify!(bench_verify_11, 2, 10);
    param_bench_verify!(bench_verify_16, 2, 15);
    param_bench_verify!(bench_verify_32, 2, 31);
    param_bench_verify!(bench_verify_64, 2, 63);
    param_bench_verify!(bench_verify_128, 2, 127);
    param_bench_verify!(bench_verify_256, 2, 255);
    param_bench_verify!(bench_verify_512, 2, 511);
}
