use num_bigint::BigUint;
use std::convert::From;

pub mod proto {
    tonic::include_proto!("zkp_auth");
}

#[derive(Debug)]
pub struct Committs {
    pub y1: BigUint,
    pub y2: BigUint,
}

impl From<Committs> for proto::Committs {
    fn from(item: Committs) -> Self {
        proto::Committs {
            y1: item.y1.to_bytes_be(),
            y2: item.y2.to_bytes_be(),
        }
    }
}

impl From<proto::Committs> for Committs {
    fn from(item: proto::Committs) -> Self {
        Committs {
            y1: BigUint::from_bytes_be(&item.y1),
            y2: BigUint::from_bytes_be(&item.y2),
        }
    }
}
