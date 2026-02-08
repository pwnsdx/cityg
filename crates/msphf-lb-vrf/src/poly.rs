use rand::{CryptoRng, RngCore};

// #[derive(Clone, Debug)]
// pub struct Poly32 {
//     coeff: [u32; 32],
//     degree: usize,
//     modulus: u32,
// }

pub trait PolyArith {
    const DEGREE: usize = 0;
    const MODULUS: i64 = 0;

    // arith
    fn add(a: &Self, b: &Self) -> Self;
    fn add_assign(&mut self, b: &Self)
    where
        Self: std::marker::Sized,
    {
        *self = Self::add(self, b);
    }

    fn sub(a: &Self, b: &Self) -> Self;
    fn sub_assign(&mut self, b: &Self)
    where
        Self: std::marker::Sized,
    {
        *self = Self::sub(self, b);
    }

    fn mul(a: &Self, b: &Self) -> Self;
    fn mul_assign(&mut self, b: &Self)
    where
        Self: std::marker::Sized,
    {
        *self = Self::mul(self, b);
    }

    fn mul_trinary(a: &Self, trinary: &Self) -> Self;
    fn mul_karatsuba(a: &Self, b: &Self) -> Self;

    // lift the coefficients to [0, q-1)
    fn normalized(&mut self);

    // lift the coefficients to [-q/2, q/2)
    fn centered(&mut self);

    // assign
    fn zero() -> Self;

    // random polynomials modulo Q
    fn uniform_random<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self;

    // random polynomials modulus beta
    fn rand_mod_beta<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self;

    fn rand_trinary<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self;
}

#[cfg(test)]
mod tests {
    use super::PolyArith;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DummyPoly(i64);

    impl PolyArith for DummyPoly {
        const DEGREE: usize = 8;
        const MODULUS: i64 = 97;

        fn add(a: &Self, b: &Self) -> Self {
            Self(a.0 + b.0)
        }

        fn sub(a: &Self, b: &Self) -> Self {
            Self(a.0 - b.0)
        }

        fn mul(a: &Self, b: &Self) -> Self {
            Self(a.0 * b.0)
        }

        fn mul_trinary(a: &Self, trinary: &Self) -> Self {
            Self(a.0 * trinary.0)
        }

        fn mul_karatsuba(a: &Self, b: &Self) -> Self {
            Self::mul(a, b)
        }

        fn normalized(&mut self) {
            self.0 = ((self.0 % Self::MODULUS) + Self::MODULUS) % Self::MODULUS;
        }

        fn centered(&mut self) {
            self.normalized();
            if self.0 >= Self::MODULUS / 2 {
                self.0 -= Self::MODULUS;
            }
        }

        fn zero() -> Self {
            Self(0)
        }

        fn uniform_random<R: RngCore + rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
            Self((rng.next_u64() % Self::MODULUS as u64) as i64)
        }

        fn rand_mod_beta<R: RngCore + rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
            Self((rng.next_u64() % 5) as i64 - 2)
        }

        fn rand_trinary<R: RngCore + rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
            match rng.next_u32() % 3 {
                0 => Self(-1),
                1 => Self(0),
                _ => Self(1),
            }
        }
    }

    #[test]
    fn assign_helpers_delegate_to_arithmetic() {
        let mut acc = DummyPoly(10);
        acc.add_assign(&DummyPoly(7));
        assert_eq!(acc, DummyPoly(17));

        acc.sub_assign(&DummyPoly(4));
        assert_eq!(acc, DummyPoly(13));

        acc.mul_assign(&DummyPoly(3));
        assert_eq!(acc, DummyPoly(39));
    }

    #[test]
    fn normalization_centering_and_zero_behave_as_expected() {
        let mut value = DummyPoly(-3);
        value.normalized();
        assert_eq!(value, DummyPoly(94));

        value.centered();
        assert_eq!(value, DummyPoly(-3));

        let mut high = DummyPoly(96);
        high.centered();
        assert_eq!(high, DummyPoly(-1));

        assert_eq!(DummyPoly::zero(), DummyPoly(0));
        assert_eq!(DummyPoly::DEGREE, 8);
        assert_eq!(DummyPoly::MODULUS, 97);
    }

    #[test]
    fn random_and_multiplication_helpers_cover_ranges() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let uniform = DummyPoly::uniform_random(&mut rng);
        assert!((0..DummyPoly::MODULUS).contains(&uniform.0));

        let mod_beta = DummyPoly::rand_mod_beta(&mut rng);
        assert!((-2..=2).contains(&mod_beta.0));

        let trinary = DummyPoly::rand_trinary(&mut rng);
        assert!([-1, 0, 1].contains(&trinary.0));

        let a = DummyPoly(9);
        let b = DummyPoly(-2);
        assert_eq!(DummyPoly::mul(&a, &b), DummyPoly(-18));
        assert_eq!(DummyPoly::mul_karatsuba(&a, &b), DummyPoly(-18));
        assert_eq!(DummyPoly::mul_trinary(&a, &DummyPoly(1)), DummyPoly(9));
    }
}
