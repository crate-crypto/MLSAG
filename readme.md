## MLSAG

This is a pure Rust implementation of the Multilayered Linkable Spontaneous Anonymous Group construction.

- This implementation has not been reviewed or auditted. Use at your own risk.

## Rust

This implementation requires Rust nightly.

## Details

- This particular version leverages Ristretto255. The basepoint used can be modified accordingly. 

## Monero Differences

- This construction differs from the monero implementation in that we do not assume a specific context for the scheme, therefore all key images are needed to validate the signature.

- Using `Merlin` transcripts, we do allow prefixing before items are added into the transcript. For no other reason than simplicity, we have opted to not add any extra items into the hash function. This should not affect the security of the scheme.

## Further Applied Explorations

This particular library aims at a more generic construction for MLSAG therefore, the following features may be explored:

- Custom ordering of members in the ring before signing. This can be done by adding a "tag" field to each member and allowing the user to pass in a closure to sort on this "tag".

- Generic group trait to allow an instantiation of any Group to be used.

- Currently code does not check if one members key is a permutation of anothers. This may not be consequential.

## Known attacks

- Since the Ristretto255 co-factor is 1. This implementation does not suffer form a small-order subgroup attack.

- Another attack vector that can be explored is through the hash to point construction for the key image. If the hash to point construction allows for any commutativity, then the privacy feature of a ring signature will be lost.

For example:

- Let P = x * G

- HashToPoint(P) = (sha_256)(P) * G

- KeyImage(x) = x * HashToPoint(P) = x * (sha_256(P) * G) = (x * G) * (sha_256(P)) = P * sha_256(P)

This allows an outsider to calculate the key Image of the signer with knowledge of just the public key.

## Benchmarks

- Processor : 2.2Ghz intel core i7

## License

Licensed under MIT: 

- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Design decisions

The Verify method takes a reference to the public keys
- In the context of blockchains, the public key will be derived by deserailising a blob of bytes. In this sense, it will not be coming from another part of the program. It is therefore likely that it may be used in another process after verification; in some state management logic.

The Sign method does not take a reference to the the private key
- The private key is consumed for safety and for contexttual reasons. In the blockchain context, a user can only sign once with a particular private key. If a user would like to sign the same/different message with a new set of decoys, this must be intentional; the user must create a new mlsag object, pick the same private keys and a different set of decoys. For safety, once a user has completed signing, the author does not believe that keeping the private key in the program is beneficial. If a user would like to use the private key again, they must re-generate. It is therefore impossible to continuously sign different messages on accident.

We could equally argue that the private key should take a reference and the destroying of it, should not be this libraries responsibility.

- This library does not mamnage any state, therefore if a user produces two signatures with the same linkability tags, there will be no errors. This logic is usually handled in a state machine.