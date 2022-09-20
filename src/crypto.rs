use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;

pub type NumTuple = (BigUint, BigUint);

#[derive(Debug, Clone)]
pub struct Consts {
    pub g: BigUint,
    pub h: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

pub fn create_register_commits(consts: &Consts, secret_x: &BigUint) -> (BigUint, BigUint) {
    let y1 = consts.g.modpow(secret_x, &consts.p);
    let y2 = consts.h.modpow(secret_x, &consts.p);

    (y1, y2)
}

pub fn prove_authentication(
    k: &BigUint,
    q: &BigUint,
    secret_x: &BigUint,
    challenge_c: &BigUint,
) -> BigUint {
    let k: BigInt = k.to_bigint().unwrap();
    let q = q.to_bigint().unwrap();
    let cx = (challenge_c * secret_x).to_bigint().unwrap();
    let (_, rem) = (k - cx).div_mod_floor(&q);

    rem.to_biguint().unwrap()
}

pub fn verify_authentication(
    consts: &Consts,
    y1: &BigUint,
    y2: &BigUint,
    r1: &BigUint,
    r2: &BigUint,
    challenge_c: &BigUint,
    answer_s: &BigUint,
) -> bool {
    let s = answer_s;
    let c = challenge_c;
    let h = &consts.h;
    let g = &consts.g;
    let p = &consts.p;

    // r1 === g^s * y1^c mod p
    let (_, r1_calc) = (g.modpow(s, p) * y1.modpow(c, p)).div_mod_floor(p);

    // r2 === h^s * y2^c mod p
    let (_, r2_calc) = (h.modpow(s, p) * y2.modpow(c, p)).div_mod_floor(p);

    r1.eq(&r1_calc) && r2.eq(&r2_calc)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    pub fn test(
        consts: &Consts,
        x: &BigUint,
        k: &BigUint,
        (y1, y2): &NumTuple,
        (r1, r2): &NumTuple,
        c: &BigUint,
        s: &BigUint,
    ) {
        let (y1_, y2_) = create_register_commits(consts, x);
        assert_eq!(&y1_, y1);
        assert_eq!(&y2_, y2);

        let s_ = prove_authentication(k, &consts.q, x, c);
        assert_eq!(&s_, s);
        assert!(verify_authentication(consts, y1, y2, r1, r2, c, s));
    }

    #[test]
    fn toy_example() {
        /*
         * Toy example from https://crypto.stackexchange.com/a/99265
         */
        let consts = &Consts {
            g: 4_u32.into(),
            h: 9_u32.into(),
            p: 23_u32.into(),
            q: 11_u32.into(),
        };

        let x = &6_u64.into();
        let k = &7_u64.into();
        let ys = &(2_u64.into(), 3_u64.into());
        let rs = &(8_u64.into(), 4_u64.into());
        let c = &4_u32.into();
        let s = &5_u64.into();

        test(consts, x, k, ys, rs, c, s);
    }

    #[test]
    fn bigger_numbers() {
        let consts = &Consts {
            g: 4_u32.into(),
            h: 9_u32.into(),
            p: BigUint::from_str("22_777_933_733").unwrap(),
            q: 11_u32.into(),
        };

        let x = &6_u64.into();
        let k = &7_u64.into();
        let ys = &(4096_u64.into(), 531441_u64.into());
        let rs = &(8_u64.into(), 4_u64.into());
        let c = &4_u32.into();
        let s = &5_u64.into();

        test(consts, x, k, ys, rs, c, s);
    }

    use num_traits::One;
    use quickcheck::{Arbitrary, Gen};

    #[derive(Debug, Clone)]
    struct Wrapped(BigUint);

    impl Arbitrary for Wrapped {
        fn arbitrary(g: &mut Gen) -> Wrapped {
            Wrapped(BigUint::from(u64::arbitrary(g)) + BigUint::one())
        }
    }

    impl Arbitrary for BigUint {
        fn arbitrary(g: &mut Gen) -> BigUint {
            panic!("at the disco")
        }
    }

    impl Arbitrary for Consts {
        fn arbitrary(g: &mut Gen) -> Consts {
            Consts {
                g: Wrapped::arbitrary(g).0,
                h: Wrapped::arbitrary(g).0,
                p: Wrapped::arbitrary(g).0,
                q: Wrapped::arbitrary(g).0,
            }
        }
    }

    quickcheck! {
        fn property1(consts: Consts, secret_x: Wrapped) -> bool             {
            let secret_x: BigUint = secret_x.0;
            let (y1, y2) = create_register_commits(&consts, &secret_x);

            let k = BigUint::from(7_u64);
            let q = BigUint::from(11_u64);
            let challenge_c = BigUint::from(4_u32);

            let answer_s = prove_authentication(&k, &q, &secret_x, &challenge_c);

            let (r1, r2): (BigUint, BigUint) = (8_u32.into(), 4_u32.into());
            let challenge_c: BigUint = 4_u32.into();

            !verify_authentication(
                &consts,
                &y1,
                &y2,
                &r1,
                &r2,
                &challenge_c,
                &answer_s
            )
        }

        fn property2() -> bool {
            true
        }
    }
}
