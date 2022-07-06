use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;

pub type NumTuple = (BigUint, BigUint);

#[derive(Debug)]
pub struct Consts {
    pub g: BigUint,
    pub h: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

pub fn create_register_commits(consts: &Consts, secret_x: BigUint) -> (BigUint, BigUint) {
    let y1 = consts.g.modpow(&secret_x, &consts.p);
    let y2 = consts.h.modpow(&secret_x, &consts.p);

    (y1, y2)
}

pub fn prove_authentication(
    k: BigUint,
    q: BigUint,
    secret_x: BigUint,
    challenge_c: BigUint,
) -> BigUint {
    let k: BigInt = k.into();
    let q: BigInt = q.into();
    let cx = (challenge_c * secret_x).to_bigint().unwrap();
    let (_, rem) = (k - cx).div_mod_floor(&q);

    rem.to_biguint().unwrap()
}

pub fn verify_authentication(
    consts: Consts,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    challenge_c: BigUint,
    answer_s: BigUint,
) -> bool {
    let s = answer_s;
    let c = challenge_c;
    let h = consts.h;
    let g = consts.g;
    let p = consts.p;

    // r1 === g^s * y1^c mod p
    let (_, r1_calc) = (g.modpow(&s, &p) * y1.modpow(&c, &p)).div_mod_floor(&p);

    // r2 === h^s * y2^c mod p
    let (_, r2_calc) = (h.modpow(&s, &p) * y2.modpow(&c, &p)).div_mod_floor(&p);

    r1.eq(&r1_calc) && r2.eq(&r2_calc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
     * Toy example from https://crypto.stackexchange.com/a/99265
     * p = 23
     * q = 11 (divides p-1 (23−1) evenly)
     * g = 4
     * h = 9
     * x = 4 (secret)
     * y1, y2 = 2, 3
     * k = 7 (picks random number)
     * r1, r2 = 8, 4
     * c = 4 (picks random number)
     * s = (k-cx) mod q = (7-4*6) mod 11 = 5
     * r1 == g^s * y1^c mod p = 8
     * r2 == h^s * y2^c mod p = 4
     */

    fn consts() -> Consts {
        Consts {
            g: BigUint::from(4_u32),
            h: BigUint::from(9_u32),
            p: BigUint::from(23_u32),
            q: BigUint::from(11_u32),
        }
    }

    #[test]
    fn test_create_register_commits() {
        let consts = consts();
        let secret_x = BigUint::from(6_u32);
        let (y1, y2) = create_register_commits(&consts, secret_x);

        assert_eq!(y1, (BigUint::from(2_u32)));
        assert_eq!(y2, (BigUint::from(3_u32)));
    }

    #[test]
    fn test_prove_authentication() {
        let k = BigUint::from(7_u64);
        let q = BigUint::from(11_u64);
        let secret_x = BigUint::from(6_u32);
        let challenge_c = BigUint::from(4_u32);

        let s = prove_authentication(k, q, secret_x, challenge_c);
        assert_eq!(s, BigUint::from(5_u32));
    }

    #[test]
    fn test_verify_authentication() {
        let consts = consts();
        let (y1, y2): (BigUint, BigUint) = (2_u32.into(), 3_u32.into());
        let (r1, r2): (BigUint, BigUint) = (8_u32.into(), 4_u32.into());
        let challenge_c: BigUint = 4_u32.into();
        let answer_s: BigUint = 5_u32.into();

        assert!(verify_authentication(
            consts,
            y1,
            y2,
            r1,
            r2,
            challenge_c,
            answer_s
        ));
    }
}
