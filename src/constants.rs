use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;

pub const BASEPOINT: EdwardsPoint = ED25519_BASEPOINT_POINT;
