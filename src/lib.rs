use num_bigint::BigUint;
use std::convert::From;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub mod proto {
    tonic::include_proto!("zkp_auth");
}

pub mod crypto;

impl From<(BigUint, BigUint)> for proto::NumTuple {
    fn from((t1, t2): (BigUint, BigUint)) -> Self {
        proto::NumTuple {
            t1: t1.to_bytes_be(),
            t2: t2.to_bytes_be(),
        }
    }
}

impl From<proto::NumTuple> for (BigUint, BigUint) {
    fn from(item: proto::NumTuple) -> Self {
        (
            BigUint::from_bytes_be(&item.t1),
            BigUint::from_bytes_be(&item.t2),
        )
    }
}
