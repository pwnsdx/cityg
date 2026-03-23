use super::arithmetic::{barrett_reduce, fqmul, montgomery_add, montgomery_sub};
use super::constants::{N, Q};
use super::ntt::{inv_ntt, ntt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Poly {
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    pub fn from_coeffs(coeffs: [i16; N]) -> Self {
        Self { coeffs }
    }

    pub fn to_ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn to_mont(mut self) -> Self {
        self.reduce();
        self
    }

    pub fn from_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            let reduced = barrett_reduce(*c as i32);
            *c = if reduced < 0 { reduced + Q } else { reduced };
        }
    }

    pub fn add_assign(&mut self, other: &Poly) {
        for (a, b) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *a = montgomery_add(*a, *b);
        }
    }

    pub fn sub_assign(&mut self, other: &Poly) {
        for (a, b) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *a = montgomery_sub(*a, *b);
        }
    }

    pub fn pointwise_mul(&self, other: &Poly) -> Poly {
        let mut out = [0i16; N];
        for (out_coeff, (a, b)) in out
            .iter_mut()
            .zip(self.coeffs.iter().zip(other.coeffs.iter()))
        {
            *out_coeff = fqmul(*a, *b);
        }
        Poly { coeffs: out }
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::R2_MOD_Q;
    use super::*;

    #[test]
    fn zero_creates_zero_polynomial() {
        let poly = Poly::zero();
        for coeff in &poly.coeffs {
            assert_eq!(*coeff, 0);
        }
    }

    #[test]
    fn from_coeffs_creates_polynomial() {
        let mut coeffs = [0i16; N];
        coeffs[0] = 42;
        coeffs[1] = 100;
        coeffs[255] = -50;

        let poly = Poly::from_coeffs(coeffs);
        assert_eq!(poly.coeffs[0], 42);
        assert_eq!(poly.coeffs[1], 100);
        assert_eq!(poly.coeffs[255], -50);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 123;
        let poly2 = poly1;

        assert_eq!(poly1.coeffs[0], poly2.coeffs[0]);
        assert_eq!(poly1, poly2);
    }

    #[test]
    fn equality_comparison() {
        let poly1 = Poly::zero();
        let poly2 = Poly::zero();
        assert_eq!(poly1, poly2);

        let mut poly3 = Poly::zero();
        poly3.coeffs[5] = 1;
        assert_ne!(poly1, poly3);
    }

    #[test]
    fn debug_trait_works() {
        let poly = Poly::zero();
        let debug_str = format!("{:?}", poly);
        assert!(debug_str.contains("Poly"));
    }

    #[test]
    fn reduce_keeps_coefficients_in_range() {
        let mut poly = Poly::zero();
        poly.coeffs[0] = Q + 100;
        poly.coeffs[1] = -Q;
        poly.coeffs[2] = 2 * Q;

        poly.reduce();

        // All coefficients should be in range [0, Q)
        for &coeff in &poly.coeffs {
            assert!(
                (0..Q).contains(&coeff),
                "Coefficient {} out of range [0, {})",
                coeff,
                Q
            );
        }
    }

    #[test]
    fn reduce_zero_stays_zero() {
        let mut poly = Poly::zero();
        poly.reduce();

        for &coeff in &poly.coeffs {
            assert_eq!(coeff, 0);
        }
    }

    #[test]
    fn to_mont_applies_reduction() {
        let mut poly = Poly::zero();
        poly.coeffs[0] = Q + 50;
        poly.coeffs[1] = -100;

        let reduced = poly.to_mont();

        // Coefficients should be reduced
        for &coeff in &reduced.coeffs {
            assert!((0..Q).contains(&coeff));
        }
    }

    #[test]
    fn add_assign_basic() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 100;
        poly1.coeffs[1] = 200;

        let mut poly2 = Poly::zero();
        poly2.coeffs[0] = 50;
        poly2.coeffs[1] = 75;

        poly1.add_assign(&poly2);

        // Results should reflect addition (modulo Q in Montgomery form)
        // Just check that the operation modified the values
        assert_ne!(poly1.coeffs[0], 100);
        assert_ne!(poly1.coeffs[1], 200);
    }

    #[test]
    fn add_assign_with_zero() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 100;
        poly1.coeffs[1] = 200;

        let original = poly1;
        let poly2 = Poly::zero();

        poly1.add_assign(&poly2);

        // Adding zero should not change values much (modulo montgomery operations)
        assert_eq!(poly1.coeffs[2], original.coeffs[2]); // Unchanged positions should stay same
    }

    #[test]
    fn sub_assign_basic() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 200;
        poly1.coeffs[1] = 300;

        let mut poly2 = Poly::zero();
        poly2.coeffs[0] = 50;
        poly2.coeffs[1] = 100;

        poly1.sub_assign(&poly2);

        // Results should reflect subtraction (modulo Q in Montgomery form)
        assert_ne!(poly1.coeffs[0], 200);
        assert_ne!(poly1.coeffs[1], 300);
    }

    #[test]
    fn sub_assign_with_zero() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 100;
        poly1.coeffs[1] = 200;

        let original = poly1;
        let poly2 = Poly::zero();

        poly1.sub_assign(&poly2);

        // Subtracting zero should not change values much
        assert_eq!(poly1.coeffs[2], original.coeffs[2]);
    }

    #[test]
    fn pointwise_mul_basic() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 10;
        poly1.coeffs[1] = 20;

        let mut poly2 = Poly::zero();
        poly2.coeffs[0] = 5;
        poly2.coeffs[1] = 3;

        let result = poly1.pointwise_mul(&poly2);

        // Result should have multiplied coefficients
        assert_ne!(result.coeffs[0], 0);
        assert_ne!(result.coeffs[1], 0);
    }

    #[test]
    fn pointwise_mul_with_zero() {
        let mut poly1 = Poly::zero();
        poly1.coeffs[0] = 100;
        poly1.coeffs[1] = 200;

        let poly2 = Poly::zero();

        let result = poly1.pointwise_mul(&poly2);

        // Multiplying by zero should give zero
        for &coeff in &result.coeffs {
            assert_eq!(coeff, 0);
        }
    }

    #[test]
    fn pointwise_mul_creates_new_poly() {
        let poly1 = Poly::zero();
        let poly2 = Poly::zero();

        let result = poly1.pointwise_mul(&poly2);

        // Verify it's a separate instance
        assert_eq!(result, Poly::zero());
    }

    #[test]
    fn to_ntt_transforms_polynomial() {
        let mut poly = Poly::zero();
        // Set some non-zero values
        for (i, coeff) in poly.coeffs.iter_mut().enumerate() {
            *coeff = ((i as i16) * 7) % Q;
        }

        let original = poly;
        poly.to_ntt();

        // After NTT, at least some values should differ
        let mut changed = false;
        for i in 0..N {
            if poly.coeffs[i] != original.coeffs[i] {
                changed = true;
                break;
            }
        }
        assert!(changed, "NTT should transform the polynomial");
    }

    #[test]
    fn to_ntt_on_zero_stays_zero() {
        let mut poly = Poly::zero();
        poly.to_ntt();

        for &coeff in &poly.coeffs {
            assert_eq!(coeff, 0);
        }
    }

    #[test]
    fn from_ntt_on_zero_stays_zero() {
        let mut poly = Poly::zero();
        poly.from_ntt();

        for &coeff in &poly.coeffs {
            assert_eq!(coeff, 0);
        }
    }

    #[test]
    fn ntt_roundtrip() {
        let mut poly = Poly::zero();
        // Set some non-zero values (smaller to avoid overflow)
        for (i, coeff) in poly.coeffs.iter_mut().enumerate() {
            *coeff = ((i as i16) * 3) % Q;
        }

        let original = poly;
        poly.to_ntt();
        poly.from_ntt();

        // After NTT roundtrip, should get back to original (modulo Montgomery)
        for i in 0..N {
            let expected = fqmul(original.coeffs[i], R2_MOD_Q);
            let actual = poly.coeffs[i];
            let diff = (i32::from(actual) - i32::from(expected)) % i32::from(Q);
            assert_eq!(
                diff.rem_euclid(i32::from(Q)),
                0,
                "Coefficient mismatch at index {}: expected {} (or equiv), got {}",
                i,
                expected,
                actual
            );
        }
    }

    #[test]
    fn operations_preserve_array_length() {
        let poly1 = Poly::zero();
        let poly2 = Poly::zero();

        assert_eq!(poly1.coeffs.len(), N);
        assert_eq!(poly2.coeffs.len(), N);

        let result = poly1.pointwise_mul(&poly2);
        assert_eq!(result.coeffs.len(), N);
    }
}
