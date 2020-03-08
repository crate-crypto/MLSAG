use crate::constants::BASEPOINT;
use crate::keys::{PrivateSet, PublicSet};
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;
use sha2::Sha512;

#[derive(Debug)]
pub enum Error {
    // Occurs when you try to use a method specific to
    // a signer as a decoy
    NotASigner,
    // Occurs when you try to use a method specific to
    // a decoy as a signer
    NotADecoy,
}

// A member represents a member in the ring
// This includes the signer of the ring
#[derive(Clone)]
pub struct Member {
    // The signer is the only member with a set of private keys
    private_set: Option<PrivateSet>,

    pub(crate) public_set: PublicSet,

    // The signing member wil have a nonce per public key in the public/private set.
    // In an sigma protocol, this nonce would signify the commit phase.
    pub(crate) nonces: Option<Vec<Scalar>>,

    // Each member will have a response value per public key in their set
    // In an sigma protocol, this would signify the reponse phase.
    pub(crate) responses: Vec<Scalar>,
}

impl Member {
    // Creates a member who will be the signer of the ring
    // Protocol explicitly checks if there is one signer per ring
    pub fn new_signer(private_keys: Vec<Scalar>) -> Self {
        let private_set = PrivateSet::new(private_keys);

        let num_private_keys = private_set.len();

        let nonces = generate_rand_scalars(num_private_keys);

        let responses = Vec::with_capacity(num_private_keys);

        let public_set = private_set.to_public_set();

        Member {
            nonces: Some(nonces),

            public_set: public_set,

            private_set: Some(private_set),

            responses: responses,
        }
    }
    // Creates a member who will be a decoy in the ring
    pub fn new_decoy(public_keys: Vec<RistrettoPoint>) -> Self {
        let num_public_keys = public_keys.len();
        let responses = generate_rand_scalars(num_public_keys);

        Self::new_decoy_with_responses(public_keys, responses)
    }

    // Creates a member who will be used for verification in a signature
    pub(crate) fn new_decoy_with_responses(
        public_keys: Vec<RistrettoPoint>,
        responses: Vec<Scalar>,
    ) -> Self {
        Member {
            nonces: None,

            public_set: PublicSet(public_keys),

            private_set: None,

            responses: responses,
        }
    }
    // Returns true if the member has a set of private keys
    pub fn is_signer(&self) -> bool {
        self.private_set.is_some()
    }
    // Returns the number of keys the member has
    pub fn num_keys(&self) -> usize {
        self.public_set.len()
    }
    // Computes the key images if the member is a signer
    pub fn compute_key_images(&self) -> Result<Vec<RistrettoPoint>, Error> {
        match &self.private_set {
            Some(priv_set) => Ok(priv_set.compute_key_images(&self.public_set)),
            None => Err(Error::NotASigner),
        }
    }

    // This function uses the nonces to calculate the first challenge scalar
    // Effectively committing the current member; the ring will therefore
    // only be completed if the current member can generate the corresponding
    // responses per nonce, which can only be done if the current member possess
    // the discrete log to the public keys corresponding to his position in the ring.
    // returns a challenge scalar or an error if the user is not a signer
    pub fn compute_challenge_commitment(&self, msg: &[u8]) -> Result<Scalar, Error> {
        if !self.is_signer() {
            return Err(Error::NotASigner);
        }

        let nonces = match &self.nonces {
            Some(x) => Ok(x),
            _ => Err(Error::NotASigner),
        }?;

        assert_eq!(nonces.len(), self.public_set.len());

        let mut transcript = Transcript::new(b"mlsag");
        transcript.append_message(b"msg", msg);

        for (nonce, public_key) in nonces.iter().zip(self.public_set.0.iter()) {
            // Add `nonce_i * basepoint` to the transcript
            transcript.append_scalar_mult(b"", nonce, &BASEPOINT);

            // Append `nonce_i * Hash(PublicKey_i)
            transcript.append_scalar_hash_point(b"", nonce, public_key);
        }

        Ok(transcript.challenge_scalar(b""))
    }
    // This function is for the signer and will use the signers
    // private set to calculate the correct response values
    // returns a vector of responses or an error, if the user is not a signer
    pub fn compute_signer_responses(&self, challenge: Scalar) -> Result<Vec<Scalar>, Error> {
        let private_set = self.private_set.as_ref().ok_or(Error::NotASigner)?;
        let nonces = self.nonces.as_ref().ok_or(Error::NotASigner)?;

        let nonces_len = nonces.len();

        let mut signer_responses: Vec<Scalar> = Vec::with_capacity(nonces_len);

        // calculate r_i = nonce_i - c * private_key_i
        for i in 0..nonces_len {
            let nonce = nonces[i];
            let private_key = private_set.0[i];

            let response = nonce - challenge * private_key;

            signer_responses.push(response);
        }

        Ok(signer_responses)
    }
    // This function is ran by all members who did not compute the challenge commitment (decoys)
    // Each member that runs this function, will link themselves to the ring using the challenge
    // passed to them by the newest member of the ring.
    // returns a challenge scalar, to be used by the next member who wants to join the ring
    pub fn compute_decoy_challenge(
        &self,
        challenge: &Scalar,
        key_images: &[RistrettoPoint],
        msg: &[u8],
    ) -> Result<Scalar, Error> {
        if self.private_set.is_some() {
            return Err(Error::NotADecoy);
        }

        assert_eq!(self.public_set.len(), self.responses.len());
        assert_eq!(self.public_set.len(), key_images.len());

        let challenge = compute_challenge_ring(
            &self.public_set.0,
            challenge,
            key_images,
            &self.responses,
            msg,
        );

        Ok(challenge)
    }
}
// A generic function to calculate the challenge for any member in the ring
// While signing, this function will be used by the decoys
// When verifying this function will be used by all members
pub fn compute_challenge_ring(
    public_keys: &[RistrettoPoint],
    challenge: &Scalar,
    key_images: &[RistrettoPoint],
    responses: &[Scalar],
    msg: &[u8],
) -> Scalar {
    let mut transcript = Transcript::new(b"mlsag");
    transcript.append_message(b"msg", msg);

    for i in 0..public_keys.len() {
        let response = &responses[i];
        let public_key = &public_keys[i];
        let key_image = &key_images[i];

        // Append `r_i * basepoint + c * PublicKey_i
        transcript.append_double_scalar_mult_add(
            b"",
            (response, challenge),
            (&BASEPOINT, public_key),
        );

        let hashed_pub_key =
            &RistrettoPoint::hash_from_bytes::<Sha512>(public_key.compress().as_bytes());

        // Append `r_i * HashToPoint(PublicKey_i) + c * KeyImage_i
        transcript.append_double_scalar_mult_add(
            b"",
            (response, challenge),
            (hashed_pub_key, key_image),
        );
    }
    transcript.challenge_scalar(b"")
}

fn generate_rand_scalars(num: usize) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    let mut scalars = Vec::<Scalar>::with_capacity(num);

    for _ in 0..num {
        scalars.push(Scalar::random(&mut rng));
    }

    scalars
}

#[cfg(test)]
mod test {
    use super::*;
    // Simple tests to check that when the members are instantiated
    // We have the correct number of values
    #[test]
    fn test_new() {
        let num_private_keys = 10;
        let scalars = generate_rand_scalars(num_private_keys);

        let signer = Member::new_signer(scalars);

        // We should have a nonce per public/private key for the signer
        match signer.nonces {
            Some(nonces) => {
                assert_eq!(nonces.len(), num_private_keys);
            }
            None => panic!(
                "We should not have a `None` value here as we have instantiated a signing member"
            ),
        }

        // The number of private keys argument we passed in as an argument
        //should equal the length of the private key set
        match signer.private_set {
            Some(priv_set) => {
                assert_eq!(priv_set.len(), num_private_keys);
            }
            _ => panic!("we should not have a `None` value for the private key set"),
        }

        // The number of private keys argument we passed in as an argument
        //should equal the length of the public key set
        assert_eq!(signer.public_set.len(), num_private_keys)
    }
}
