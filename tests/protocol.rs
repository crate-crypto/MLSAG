extern crate curve25519_dalek;
extern crate mlsag;

use mlsag::mlsag::Mlsag;
use mlsag::tests_helper::*;

#[test]
fn test_protocol() {
    // Define setup parameters
    let num_keys = 2;
    let num_decoys = 11;

    // Define a mlsag object which will be used to create a signature
    let mut mlsag = Mlsag::new();

    // Generate and add decoys
    let decoys = generate_decoys(num_decoys, num_keys);
    for decoy in decoys {
        mlsag.add_member(decoy);
    }

    // Generate and add signer
    let signer = generate_signer(num_keys);
    mlsag.add_member(signer);

    let signature = mlsag.sign().unwrap();
    let res = signature.verify(&mut mlsag.public_keys());

    assert!(res.is_ok())
}
