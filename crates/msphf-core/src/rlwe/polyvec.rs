use super::constants::K;
use super::poly::Poly;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyVec {
    pub polys: [Poly; K],
}

impl PolyVec {
    pub fn zero() -> Self {
        Self {
            polys: [Poly::zero(), Poly::zero(), Poly::zero()],
        }
    }

    pub fn ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.to_ntt();
        }
    }

    pub fn inv_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.from_ntt();
        }
    }
}

impl Default for PolyVec {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::{K, N, Q, R2_MOD_Q};
    use super::*;

    #[test]
    fn zero_creates_zero_polyvec() {
        let pv = PolyVec::zero();
        for poly in &pv.polys {
            for coeff in &poly.coeffs {
                assert_eq!(*coeff, 0);
            }
        }
    }

    #[test]
    fn default_equals_zero() {
        let pv_default = PolyVec::default();
        let pv_zero = PolyVec::zero();
        assert_eq!(pv_default, pv_zero);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let mut pv1 = PolyVec::zero();
        pv1.polys[0].coeffs[0] = 42;
        let pv2 = pv1.clone();

        assert_eq!(pv1, pv2);
        assert_eq!(pv2.polys[0].coeffs[0], 42);
    }

    #[test]
    fn equality_comparison() {
        let pv1 = PolyVec::zero();
        let pv2 = PolyVec::zero();
        assert_eq!(pv1, pv2);

        let mut pv3 = PolyVec::zero();
        pv3.polys[1].coeffs[5] = 1;
        assert_ne!(pv1, pv3);
    }

    #[test]
    fn ntt_transforms_all_polys() {
        let mut pv = PolyVec::zero();
        // Set some non-zero values in each polynomial
        for (i, poly) in pv.polys.iter_mut().enumerate() {
            for (j, coeff) in poly.coeffs.iter_mut().enumerate() {
                // Use smaller values to stay within safe bounds
                *coeff = ((i as i16 * 50 + j as i16) * 7) % Q;
            }
        }

        let original = pv.clone();
        pv.ntt();

        // After NTT, values should be different (unless they were all zero)
        // Check that at least one polynomial changed
        let mut changed = false;
        for i in 0..K {
            if pv.polys[i] != original.polys[i] {
                changed = true;
                break;
            }
        }
        assert!(changed, "NTT should transform the polynomials");
    }

    #[test]
    fn inv_ntt_reverses_ntt() {
        let mut pv = PolyVec::zero();
        // Set some non-zero values in each polynomial (using smaller values to avoid overflow)
        for (i, poly) in pv.polys.iter_mut().enumerate() {
            for (j, coeff) in poly.coeffs.iter_mut().enumerate() {
                // Use smaller multiplier and ensure values are within safe bounds
                *coeff = ((i as i16 * 100 + j as i16) * 3) % Q;
            }
        }

        let original = pv.clone();
        pv.ntt();
        pv.inv_ntt();

        // After NTT followed by inv_ntt, we should get back to original
        // (modulo Montgomery reduction)
        for i in 0..K {
            for j in 0..N {
                let expected =
                    super::super::arithmetic::fqmul(original.polys[i].coeffs[j], R2_MOD_Q);
                let actual = pv.polys[i].coeffs[j];
                let diff = (i32::from(actual) - i32::from(expected)) % i32::from(Q);
                assert_eq!(
                    diff.rem_euclid(i32::from(Q)),
                    0,
                    "Coefficient mismatch at poly[{}].coeffs[{}]: expected {} (or equiv), got {}",
                    i,
                    j,
                    expected,
                    actual
                );
            }
        }
    }

    #[test]
    fn ntt_on_zero_stays_zero() {
        let mut pv = PolyVec::zero();
        pv.ntt();

        for poly in &pv.polys {
            for coeff in &poly.coeffs {
                assert_eq!(*coeff, 0);
            }
        }
    }

    #[test]
    fn inv_ntt_on_zero_stays_zero() {
        let mut pv = PolyVec::zero();
        pv.inv_ntt();

        for poly in &pv.polys {
            for coeff in &poly.coeffs {
                assert_eq!(*coeff, 0);
            }
        }
    }

    #[test]
    fn debug_trait_works() {
        let pv = PolyVec::zero();
        let debug_str = format!("{:?}", pv);
        assert!(debug_str.contains("PolyVec"));
    }

    #[test]
    fn polyvec_has_k_polynomials() {
        let pv = PolyVec::zero();
        assert_eq!(pv.polys.len(), K);
    }
}
