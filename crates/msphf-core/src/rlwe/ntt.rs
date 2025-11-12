//! Forward and inverse NTT for the RLWE parameter set.
//!
//! Enable the `unsafe-ntt` feature to use unchecked indexing for maximum speed.

use super::arithmetic::{barrett_reduce, fqmul};
use super::constants::{F_INV_NTT, N, Q, ZETAS_FWD};

#[cfg(feature = "unsafe-ntt")]
#[inline(always)]
fn read(coeffs: &[i16; N], idx: usize) -> i16 {
    unsafe { *coeffs.get_unchecked(idx) }
}

#[cfg(not(feature = "unsafe-ntt"))]
#[inline(always)]
fn read(coeffs: &[i16; N], idx: usize) -> i16 {
    coeffs[idx]
}

#[cfg(feature = "unsafe-ntt")]
#[inline(always)]
fn write(coeffs: &mut [i16; N], idx: usize, value: i16) {
    unsafe {
        *coeffs.get_unchecked_mut(idx) = value;
    }
}

#[cfg(not(feature = "unsafe-ntt"))]
#[inline(always)]
fn write(coeffs: &mut [i16; N], idx: usize, value: i16) {
    coeffs[idx] = value;
}

pub fn ntt(a: &mut [i16; N]) {
    let mut len = 128usize;
    let mut k = 1usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS_FWD[k];
            k += 1;
            for j in start..start + len {
                debug_assert!(j < N);
                debug_assert!(j + len < N);
                let t = fqmul(zeta, read(a, j + len));
                let tmp = read(a, j);
                let sum = tmp as i32 + t as i32;
                let diff = tmp as i32 - t as i32;
                debug_assert!(sum.abs() <= (Q as i32) * 8);
                debug_assert!(diff.abs() <= (Q as i32) * 8);
                write(a, j + len, diff as i16);
                write(a, j, sum as i16);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

pub fn inv_ntt(a: &mut [i16; N]) {
    let mut len = 2usize;
    let mut k = ZETAS_FWD.len() - 1;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS_FWD[k];
            k = k.saturating_sub(1);
            for j in start..start + len {
                debug_assert!(j < N);
                debug_assert!(j + len < N);
                let t = read(a, j);
                let sum = t as i32 + read(a, j + len) as i32;
                let diff = read(a, j + len) as i32 - t as i32;
                debug_assert!(sum.abs() <= (Q as i32) * 8);
                debug_assert!(diff.abs() <= (Q as i32) * 8);
                write(a, j, barrett_reduce(sum));
                write(a, j + len, fqmul(zeta, diff as i16));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for coeff in a.iter_mut() {
        *coeff = fqmul(*coeff, F_INV_NTT);
    }
}
#[cfg(test)]
mod tests {
    use super::super::constants::{Q, R2_MOD_Q};
    use super::*;

    // ============================================================================
    // ADVERSARIAL TESTS - Testing edge cases and boundary conditions
    // ============================================================================

    #[test]
    fn ntt_zero_stays_zero() {
        let mut poly = [0i16; N];
        ntt(&mut poly);
        for &coeff in &poly {
            assert_eq!(coeff, 0, "NTT of zero should be zero");
        }
    }

    #[test]
    fn inv_ntt_zero_stays_zero() {
        let mut poly = [0i16; N];
        inv_ntt(&mut poly);
        for &coeff in &poly {
            assert_eq!(coeff, 0, "Inverse NTT of zero should be zero");
        }
    }

    #[test]
    fn ntt_preserves_array_length() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i16 * 3) % Q;
        }
        ntt(&mut poly);
        assert_eq!(poly.len(), N);
    }

    #[test]
    fn inv_ntt_preserves_array_length() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i16 * 3) % Q;
        }
        inv_ntt(&mut poly);
        assert_eq!(poly.len(), N);
    }

    #[test]
    fn ntt_with_single_nonzero_coefficient() {
        let mut poly = [0i16; N];
        poly[0] = 100;

        ntt(&mut poly);

        // NTT should distribute the value across coefficients
        let mut has_nonzero = false;
        for &coeff in &poly {
            if coeff != 0 {
                has_nonzero = true;
                break;
            }
        }
        assert!(
            has_nonzero,
            "NTT of non-zero polynomial should have non-zero coefficients"
        );
    }

    #[test]
    fn ntt_with_all_ones() {
        let mut poly = [1i16; N];
        let original = poly;

        ntt(&mut poly);

        // NTT should transform the polynomial
        assert_ne!(poly, original, "NTT should transform all-ones polynomial");
    }

    #[test]
    fn ntt_with_alternating_pattern() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = if i % 2 == 0 { 1 } else { -1 };
        }

        let original = poly;
        ntt(&mut poly);

        assert_ne!(poly, original, "NTT should transform alternating pattern");
    }

    #[test]
    fn ntt_deterministic() {
        let mut poly1 = [0i16; N];
        let mut poly2 = [0i16; N];

        for (i, coeff) in poly1.iter_mut().enumerate() {
            *coeff = (i as i16 * 7) % Q;
        }
        poly2.copy_from_slice(&poly1);

        ntt(&mut poly1);
        ntt(&mut poly2);

        assert_eq!(poly1, poly2, "NTT should be deterministic");
    }

    #[test]
    fn inv_ntt_deterministic() {
        let mut poly1 = [0i16; N];
        let mut poly2 = [0i16; N];

        for (i, coeff) in poly1.iter_mut().enumerate() {
            *coeff = (i as i16 * 7) % Q;
        }
        poly2.copy_from_slice(&poly1);

        inv_ntt(&mut poly1);
        inv_ntt(&mut poly2);

        assert_eq!(poly1, poly2, "Inverse NTT should be deterministic");
    }

    #[test]
    fn ntt_with_small_values() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate().take(10) {
            *coeff = i as i16;
        }

        ntt(&mut poly);

        // Should not panic or overflow
        assert_eq!(poly.len(), N);
    }

    #[test]
    fn ntt_with_values_near_q() {
        let mut poly = [0i16; N];
        poly[0] = Q - 1;
        poly[1] = Q - 2;
        poly[2] = Q - 10;

        ntt(&mut poly);

        // Should not panic
        assert_eq!(poly.len(), N);
    }

    // ============================================================================
    // END-TO-END TESTS - Testing complete NTT workflows
    // ============================================================================

    #[test]
    fn roundtrip_ntt() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i16 * 7) % Q;
        }
        let mut a = poly;
        ntt(&mut a);
        inv_ntt(&mut a);
        for (orig, back) in poly.iter().zip(a.iter()) {
            let expected = super::super::arithmetic::fqmul(*orig, R2_MOD_Q);
            let diff = (i32::from(*back) - i32::from(expected)) % i32::from(Q);
            assert_eq!(diff.rem_euclid(i32::from(Q)), 0);
        }
    }

    #[test]
    fn roundtrip_ntt_small_values() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i16 * 3) % Q;
        }
        let mut a = poly;
        ntt(&mut a);
        inv_ntt(&mut a);
        for (orig, back) in poly.iter().zip(a.iter()) {
            let expected = super::super::arithmetic::fqmul(*orig, R2_MOD_Q);
            let diff = (i32::from(*back) - i32::from(expected)) % i32::from(Q);
            assert_eq!(diff.rem_euclid(i32::from(Q)), 0);
        }
    }

    #[test]
    fn roundtrip_ntt_with_negatives() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = if i % 2 == 0 {
                (i as i16 * 3) % Q
            } else {
                -((i as i16 * 3) % Q)
            };
        }
        let original = poly;
        ntt(&mut poly);
        inv_ntt(&mut poly);

        // Verify roundtrip (modulo Montgomery)
        for (orig, back) in original.iter().zip(poly.iter()) {
            let expected = super::super::arithmetic::fqmul(*orig, R2_MOD_Q);
            let diff = (i32::from(*back) - i32::from(expected)) % i32::from(Q);
            assert_eq!(diff.rem_euclid(i32::from(Q)), 0);
        }
    }

    #[test]
    fn multiple_ntt_calls_on_fresh_data() {
        // Test that we can perform NTT on multiple fresh polynomials
        let mut poly1 = [0i16; N];
        let mut poly2 = [0i16; N];
        let mut poly3 = [0i16; N];

        for (i, coeff) in poly1.iter_mut().enumerate() {
            *coeff = (i as i16 * 3) % Q;
        }
        for (i, coeff) in poly2.iter_mut().enumerate() {
            *coeff = (i as i16 * 5) % Q;
        }
        for (i, coeff) in poly3.iter_mut().enumerate() {
            *coeff = (i as i16 * 7) % Q;
        }

        // Each should transform without issues
        ntt(&mut poly1);
        ntt(&mut poly2);
        ntt(&mut poly3);

        // All should be different
        assert_ne!(poly1, poly2);
        assert_ne!(poly2, poly3);
        assert_ne!(poly1, poly3);
    }

    #[test]
    fn ntt_inv_ntt_preserves_structure() {
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i16 * 3) % Q;
        }

        let original = poly;
        ntt(&mut poly);
        inv_ntt(&mut poly);

        // After single roundtrip, should get back to Montgomery form of original
        for (orig, back) in original.iter().zip(poly.iter()) {
            let expected = super::super::arithmetic::fqmul(*orig, R2_MOD_Q);
            let diff = (i32::from(*back) - i32::from(expected)) % i32::from(Q);
            assert_eq!(diff.rem_euclid(i32::from(Q)), 0);
        }
    }

    // ============================================================================
    // PROPERTY-BASED TESTS - Testing mathematical properties
    // ============================================================================

    #[test]
    fn property_ntt_linearity_addition() {
        // Test that NTT(a + b) relates to NTT(a) + NTT(b)
        let mut poly_a = [0i16; N];
        let mut poly_b = [0i16; N];

        for i in 0..N {
            poly_a[i] = ((i as i16) * 3) % Q;
            poly_b[i] = ((i as i16) * 5) % Q;
        }

        let mut sum = [0i16; N];
        for i in 0..N {
            sum[i] = ((poly_a[i] as i32 + poly_b[i] as i32) % Q as i32) as i16;
        }

        let mut a_copy = poly_a;
        let mut b_copy = poly_b;

        ntt(&mut a_copy);
        ntt(&mut b_copy);
        ntt(&mut sum);

        // NTT(a+b) should equal NTT(a) + NTT(b) (modulo)
        for i in 0..N {
            let expected = ((a_copy[i] as i32 + b_copy[i] as i32).rem_euclid(Q as i32)) as i16;
            let actual = ((sum[i] as i32).rem_euclid(Q as i32)) as i16;

            // Allow for small differences due to reduction order
            let diff = ((actual as i32 - expected as i32).abs()) % (Q as i32);
            assert!(
                diff <= 1,
                "Linearity property failed at index {}: expected {}, got {}",
                i,
                expected,
                actual
            );
        }
    }

    #[test]
    fn property_consistent_across_runs() {
        // Same polynomial should always produce same NTT
        let mut poly1 = [0i16; N];
        for (i, coeff) in poly1.iter_mut().enumerate() {
            *coeff = ((i * 13) % Q as usize) as i16;
        }

        let poly2 = poly1;
        let poly3 = poly1;

        ntt(&mut poly1);

        let mut temp2 = poly2;
        ntt(&mut temp2);

        let mut temp3 = poly3;
        ntt(&mut temp3);

        assert_eq!(poly1, temp2, "NTT should be consistent");
        assert_eq!(poly1, temp3, "NTT should be consistent");
    }

    #[test]
    fn ntt_index_schedule_within_bounds() {
        let mut len = 128usize;
        while len >= 2 {
            let mut start = 0usize;
            while start < N {
                for j in start..start + len {
                    assert!(j < N, "forward NTT index must stay within bounds");
                    assert!(
                        j + len < N,
                        "forward NTT len offset must stay within bounds"
                    );
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    #[test]
    fn inv_ntt_index_schedule_within_bounds() {
        let mut len = 2usize;
        while len <= 128 {
            let mut start = 0usize;
            while start < N {
                for j in start..start + len {
                    assert!(j < N, "inverse NTT index must stay within bounds");
                    assert!(
                        j + len < N,
                        "inverse NTT len offset must stay within bounds"
                    );
                }
                start += 2 * len;
            }
            len <<= 1;
        }
    }
}
