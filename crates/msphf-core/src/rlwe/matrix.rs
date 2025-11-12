use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::arithmetic::montgomery_reduce;
use super::constants::{K, N, Q, R2_MOD_Q};
use super::poly::Poly;

pub type Matrix = [[Poly; K]; K];

#[inline(always)]
fn ct_select_i16(current: i16, replacement: i16, mask: i16) -> i16 {
    (current & !mask) | (replacement & mask)
}

pub fn expand_a(seed: &[u8; 32]) -> Matrix {
    let mut matrix = [[Poly::zero(); K]; K];
    for (i, row) in matrix.iter_mut().enumerate() {
        for (j, poly) in row.iter_mut().enumerate() {
            *poly = generate_poly(seed, i as u8, j as u8);
        }
    }
    matrix
}

fn generate_poly(seed: &[u8; 32], a: u8, b: u8) -> Poly {
    let mut shake = Shake128::default();
    shake.update(seed);
    shake.update(&[a, b]);
    let mut reader = shake.finalize_xof();

    let mut coeffs = [0i16; N];
    let mut buf = [0u8; 3 * N.div_ceil(2)];
    let mut filled = 0usize;
    while filled < N {
        reader.read(&mut buf);
        let mut idx = 0usize;
        while idx + 3 <= buf.len() {
            let t0 = ((buf[idx] as u16) | ((buf[idx + 1] as u16) << 8)) & 0x0FFF;
            let t1 = (((buf[idx + 1] as u16) >> 4) | ((buf[idx + 2] as u16) << 4)) & 0x0FFF;
            idx += 3;
            let idx0 = filled.min(N - 1);
            let space0 = ((filled as i32 - N as i32) >> 31) & 1;
            let valid0 = ((t0 as i32 - Q as i32) >> 31) & 1;
            let take0 = valid0 & space0;
            let mask0 = -{ take0 } as i16;
            let value0 = montgomery_reduce((t0 as i32) * R2_MOD_Q as i32);
            coeffs[idx0] = ct_select_i16(coeffs[idx0], value0, mask0);
            filled += take0 as usize;

            let idx1 = filled.min(N - 1);
            let space1 = ((filled as i32 - N as i32) >> 31) & 1;
            let valid1 = ((t1 as i32 - Q as i32) >> 31) & 1;
            let take1 = valid1 & space1;
            let mask1 = -{ take1 } as i16;
            let value1 = montgomery_reduce((t1 as i32) * R2_MOD_Q as i32);
            coeffs[idx1] = ct_select_i16(coeffs[idx1], value1, mask1);
            filled += take1 as usize;

            if filled >= N {
                break;
            }
        }
    }

    Poly { coeffs }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // ADVERSARIAL TESTS - Testing edge cases and boundary conditions
    // ============================================================================

    #[test]
    fn expand_a_zero_seed() {
        let seed = [0u8; 32];
        let matrix = expand_a(&seed);

        // Verify matrix structure
        assert_eq!(matrix.len(), K);
        for row in &matrix {
            assert_eq!(row.len(), K);
            for poly in row {
                assert_eq!(poly.coeffs.len(), N);
            }
        }
    }

    #[test]
    fn expand_a_all_ones_seed() {
        let seed = [0xFFu8; 32];
        let matrix = expand_a(&seed);

        // Verify matrix structure
        assert_eq!(matrix.len(), K);
        for row in &matrix {
            assert_eq!(row.len(), K);
        }
    }

    #[test]
    fn expand_a_sequential_seed() {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let matrix = expand_a(&seed);

        // Verify all polynomials are populated
        for row in &matrix {
            for poly in row {
                // Coefficients should be in valid range
                for &coeff in &poly.coeffs {
                    assert!((0..Q).contains(&coeff));
                }
            }
        }
    }

    #[test]
    fn expand_a_different_seeds_produce_different_matrices() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x24u8; 32];

        let matrix1 = expand_a(&seed1);
        let matrix2 = expand_a(&seed2);

        // Matrices should be different
        assert_ne!(matrix1, matrix2);
    }

    #[test]
    fn expand_a_single_bit_difference() {
        let seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        seed2[0] = 1; // Single bit difference

        let matrix1 = expand_a(&seed1);
        let matrix2 = expand_a(&seed2);

        // Even small seed difference should produce different matrices
        assert_ne!(matrix1, matrix2);
    }

    #[test]
    fn generate_poly_deterministic() {
        let seed = [0x55u8; 32];

        let poly1 = generate_poly(&seed, 0, 0);
        let poly2 = generate_poly(&seed, 0, 0);

        assert_eq!(poly1, poly2);
    }

    #[test]
    fn generate_poly_different_positions_produce_different_polys() {
        let seed = [0xAAu8; 32];

        let poly_00 = generate_poly(&seed, 0, 0);
        let poly_01 = generate_poly(&seed, 0, 1);
        let poly_10 = generate_poly(&seed, 1, 0);

        // Different positions should produce different polynomials
        assert_ne!(poly_00, poly_01);
        assert_ne!(poly_00, poly_10);
        assert_ne!(poly_01, poly_10);
    }

    #[test]
    fn generate_poly_all_positions() {
        let seed = [0x77u8; 32];

        // Generate polynomials for all K x K positions
        for i in 0..K {
            for j in 0..K {
                let poly = generate_poly(&seed, i as u8, j as u8);

                // Verify coefficients are in valid range
                for &coeff in &poly.coeffs {
                    assert!((0..Q).contains(&coeff));
                }
            }
        }
    }

    #[test]
    fn generate_poly_coefficients_in_valid_range() {
        let seed = [0x33u8; 32];
        let poly = generate_poly(&seed, 1, 2);

        // All coefficients should be in [0, Q)
        for (i, &coeff) in poly.coeffs.iter().enumerate() {
            assert!(
                (0..Q).contains(&coeff),
                "Coefficient {} at index {} out of range [0, {})",
                coeff,
                i,
                Q
            );
        }
    }

    #[test]
    fn ct_select_i16_mask_all_zeros() {
        let current = 100i16;
        let replacement = 200i16;
        let mask = 0i16;

        let result = ct_select_i16(current, replacement, mask);
        assert_eq!(result, current);
    }

    #[test]
    fn ct_select_i16_mask_all_ones() {
        let current = 100i16;
        let replacement = 200i16;
        let mask = -1i16; // All bits set

        let result = ct_select_i16(current, replacement, mask);
        assert_eq!(result, replacement);
    }

    // ============================================================================
    // END-TO-END TESTS - Testing complete matrix generation workflows
    // ============================================================================

    #[test]
    fn expand_a_deterministic() {
        let seed = [3u8; 32];
        let matrix1 = expand_a(&seed);
        let matrix2 = expand_a(&seed);
        assert_eq!(matrix1, matrix2);
    }

    #[test]
    fn e2e_expand_a_full_matrix() {
        let seed = [0x99u8; 32];
        let matrix = expand_a(&seed);

        // Verify matrix is K x K
        assert_eq!(matrix.len(), K);

        // Verify all polynomials have N coefficients in valid range
        for (i, row) in matrix.iter().enumerate() {
            assert_eq!(row.len(), K);
            for (j, poly) in row.iter().enumerate() {
                assert_eq!(poly.coeffs.len(), N);

                for &coeff in &poly.coeffs {
                    assert!(
                        (0..Q).contains(&coeff),
                        "Invalid coefficient in matrix[{}][{}]",
                        i,
                        j
                    );
                }
            }
        }
    }

    #[test]
    fn e2e_expand_a_multiple_seeds() {
        // Test with multiple different seeds
        let seeds = [[0x00u8; 32], [0xFFu8; 32], [0x55u8; 32], [0xAAu8; 32]];

        let mut matrices = Vec::new();

        for seed in &seeds {
            let matrix = expand_a(seed);
            matrices.push(matrix);

            // Verify structure
            assert_eq!(matrix.len(), K);
            for row in &matrix {
                assert_eq!(row.len(), K);
            }
        }

        // Verify all matrices are different
        for i in 0..matrices.len() {
            for j in i + 1..matrices.len() {
                assert_ne!(
                    matrices[i], matrices[j],
                    "Matrices {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn e2e_generate_poly_all_combinations() {
        let seed = [0xCCu8; 32];

        // Generate all K x K polynomials
        let mut polys = Vec::new();

        for i in 0..K {
            for j in 0..K {
                let poly = generate_poly(&seed, i as u8, j as u8);
                polys.push((i, j, poly));
            }
        }

        // Verify all are different (same seed, different positions)
        for idx1 in 0..polys.len() {
            for idx2 in idx1 + 1..polys.len() {
                let (i1, j1, ref poly1) = polys[idx1];
                let (i2, j2, ref poly2) = polys[idx2];

                assert_ne!(
                    poly1, poly2,
                    "Polynomials at positions ({}, {}) and ({}, {}) should be different",
                    i1, j1, i2, j2
                );
            }
        }
    }

    // ============================================================================
    // PROPERTY-BASED TESTS - Testing mathematical and security properties
    // ============================================================================

    #[test]
    fn property_expand_a_consistency() {
        // Same seed should always produce same matrix
        let seed = [0xDDu8; 32];

        let matrix1 = expand_a(&seed);
        let matrix2 = expand_a(&seed);
        let matrix3 = expand_a(&seed);

        assert_eq!(matrix1, matrix2);
        assert_eq!(matrix2, matrix3);
    }

    #[test]
    fn property_expand_a_avalanche() {
        // Small change in seed should cause large change in output
        let seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        seed2[31] ^= 1; // Flip one bit

        let matrix1 = expand_a(&seed1);
        let matrix2 = expand_a(&seed2);

        // Count differences
        let mut different_polys = 0;
        for i in 0..K {
            for j in 0..K {
                if matrix1[i][j] != matrix2[i][j] {
                    different_polys += 1;
                }
            }
        }

        // With proper avalanche, all or nearly all polynomials should differ
        assert!(
            different_polys >= K * K / 2,
            "Only {} out of {} polynomials differ (expected avalanche effect)",
            different_polys,
            K * K
        );
    }

    #[test]
    fn property_generate_poly_uniform_output() {
        // Verify that generated polynomials use a good range of coefficients
        let seed = [0xBBu8; 32];
        let poly = generate_poly(&seed, 0, 0);

        // Count unique coefficients
        let mut seen = std::collections::HashSet::new();
        for &coeff in &poly.coeffs {
            seen.insert(coeff);
        }

        // Should have reasonable diversity (at least 50 unique values out of N)
        assert!(
            seen.len() >= 50,
            "Only {} unique coefficients (expected more diversity)",
            seen.len()
        );
    }

    #[test]
    fn property_ct_select_constant_time_structure() {
        // While we can't test constant-time in unit tests,
        // we can verify the function structure is correct

        let test_cases = [
            (100i16, 200i16, 0i16, 100i16),  // mask=0 -> current
            (100i16, 200i16, -1i16, 200i16), // mask=-1 -> replacement
            (50i16, 150i16, 0i16, 50i16),
            (50i16, 150i16, -1i16, 150i16),
        ];

        for (current, replacement, mask, expected) in test_cases {
            let result = ct_select_i16(current, replacement, mask);
            assert_eq!(
                result, expected,
                "ct_select({}, {}, {}) = {} (expected {})",
                current, replacement, mask, result, expected
            );
        }
    }

    #[test]
    fn property_matrix_independence() {
        // Each position in matrix should be independent
        let seed = [0xEEu8; 32];
        let matrix = expand_a(&seed);

        // Verify no two polynomials in the matrix are identical
        for i1 in 0..K {
            for j1 in 0..K {
                for i2 in 0..K {
                    for j2 in 0..K {
                        if i1 != i2 || j1 != j2 {
                            assert_ne!(
                                matrix[i1][j1], matrix[i2][j2],
                                "Polynomials at ({}, {}) and ({}, {}) should be different",
                                i1, j1, i2, j2
                            );
                        }
                    }
                }
            }
        }
    }
}
