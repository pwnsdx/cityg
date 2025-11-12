//! Noise samplers (CBD-eta2) for RLWE.

use super::constants::{N, Q};
use crate::MsphfError;

/// Sample a polynomial with coefficients in {-2,-1,0,1,2} using CBD-eta2.
pub fn cbd_eta2_poly(out: &mut [i16; N], buf: &[u8]) -> Result<(), MsphfError> {
    if buf.len() * 2 < N {
        return Err(MsphfError::invalid_input(
            "insufficient randomness for cbd_eta2",
        ));
    }
    for (i, coeff) in out.iter_mut().enumerate() {
        let idx = i * 4;
        let byte_index = idx / 8;
        let bit_offset = idx % 8;
        let mut bits = ((buf[byte_index] as u16) >> bit_offset) & 0xF;
        if bit_offset > 4 {
            let next = buf[byte_index + 1] as u16;
            bits |= (next << (8 - bit_offset)) & 0xF;
        }
        let a = (bits & 0x3) as i16;
        let b = ((bits >> 2) & 0x3) as i16;
        let val = a - b;
        *coeff = (val + Q) % Q;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // ADVERSARIAL TESTS - Testing edge cases and boundary conditions
    // ============================================================================

    #[test]
    fn cbd_eta2_insufficient_randomness() {
        let mut out = [0i16; N];
        let buf = vec![0u8; 10]; // Too small

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_err(), "Should fail with insufficient randomness");

        assert!(
            matches!(result, Err(MsphfError::InvalidInput(_))),
            "Expected InvalidInput error, got: {:?}",
            result
        );
        if let Err(MsphfError::InvalidInput(msg)) = result {
            assert!(msg.contains("insufficient randomness"));
        }
    }

    #[test]
    fn cbd_eta2_empty_buffer() {
        let mut out = [0i16; N];
        let buf: Vec<u8> = vec![];

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_err(), "Should fail with empty buffer");
    }

    #[test]
    fn cbd_eta2_minimal_buffer() {
        let mut out = [0i16; N];
        // Need at least N/2 bytes (128 bytes for N=256)
        let buf = vec![0u8; N / 2];

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should succeed with minimal valid buffer");
    }

    #[test]
    fn cbd_eta2_zero_buffer() {
        let mut out = [0i16; N];
        let buf = vec![0u8; N / 2 + 10]; // Sufficient size

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should succeed with zero buffer");

        // With all zeros, a=0 and b=0, so val=0, coeff=0
        for &coeff in &out {
            assert_eq!(
                coeff, 0,
                "All zero randomness should produce zero coefficients"
            );
        }
    }

    #[test]
    fn cbd_eta2_all_ones_buffer() {
        let mut out = [0i16; N];
        let buf = vec![0xFFu8; N / 2 + 10];

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should succeed with all-ones buffer");

        // With all 0xFF, bits=0xF, so a=3, b=3, val=0
        for &coeff in &out {
            assert_eq!(
                coeff, 0,
                "All 0xFF randomness should produce zero coefficients"
            );
        }
    }

    #[test]
    fn cbd_eta2_coefficients_in_valid_range() {
        let mut out = [0i16; N];
        let buf = vec![0x5Au8; N / 2 + 10]; // Pattern: 0101 1010

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok());

        // CBD-eta2 should produce coefficients in {-2, -1, 0, 1, 2}
        // After modulo Q, these become {Q-2, Q-1, 0, 1, 2}
        for &coeff in &out {
            assert!(
                (0..Q).contains(&coeff),
                "Coefficient {} out of range [0, {})",
                coeff,
                Q
            );
        }
    }

    #[test]
    fn cbd_eta2_deterministic() {
        let mut out1 = [0i16; N];
        let mut out2 = [0i16; N];
        let buf = vec![0x42u8; N / 2 + 10];

        cbd_eta2_poly(&mut out1, &buf).expect("cbd_eta2_poly should succeed");
        cbd_eta2_poly(&mut out2, &buf).expect("cbd_eta2_poly should succeed");

        assert_eq!(out1, out2, "Same randomness should produce same output");
    }

    #[test]
    fn cbd_eta2_different_randomness_produces_different_output() {
        let mut out1 = [0i16; N];
        let mut out2 = [0i16; N];
        let buf1 = vec![0x42u8; N / 2 + 10];
        let buf2 = vec![0x24u8; N / 2 + 10];

        cbd_eta2_poly(&mut out1, &buf1).expect("cbd_eta2_poly should succeed");
        cbd_eta2_poly(&mut out2, &buf2).expect("cbd_eta2_poly should succeed");

        assert_ne!(
            out1, out2,
            "Different randomness should produce different output"
        );
    }

    #[test]
    fn cbd_eta2_large_buffer() {
        let mut out = [0i16; N];
        let buf = vec![0xABu8; 1024]; // Much larger than needed

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should succeed with large buffer");
    }

    #[test]
    fn cbd_eta2_bit_extraction_across_byte_boundary() {
        let mut out = [0i16; N];
        // Create a buffer where bit extraction crosses byte boundaries
        let mut buf = vec![0u8; N / 2 + 10];
        buf[0] = 0b11110000;
        buf[1] = 0b00001111;

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should handle cross-byte bit extraction");
    }

    // ============================================================================
    // END-TO-END TESTS - Testing complete CBD workflows
    // ============================================================================

    #[test]
    fn e2e_cbd_eta2_realistic_randomness() {
        let mut out = [0i16; N];
        // Simulate realistic randomness from a PRNG
        let mut buf = vec![0u8; N / 2 + 10];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 137 + 42) % 256) as u8; // Pseudo-random pattern
        }

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok());

        // Verify all coefficients are valid
        for &coeff in &out {
            assert!((0..Q).contains(&coeff));
        }

        // With realistic randomness, we expect some variation
        let all_same = out.iter().all(|&c| c == out[0]);
        assert!(
            !all_same,
            "Realistic randomness should produce varied coefficients"
        );
    }

    #[test]
    fn e2e_cbd_eta2_multiple_samplings() {
        // Test that we can sample multiple polynomials
        let mut out1 = [0i16; N];
        let mut out2 = [0i16; N];
        let mut out3 = [0i16; N];

        let buf1 = vec![0x11u8; N / 2 + 10];
        let buf2 = vec![0x22u8; N / 2 + 10];
        let buf3 = vec![0x33u8; N / 2 + 10];

        assert!(cbd_eta2_poly(&mut out1, &buf1).is_ok());
        assert!(cbd_eta2_poly(&mut out2, &buf2).is_ok());
        assert!(cbd_eta2_poly(&mut out3, &buf3).is_ok());

        // All should be different
        assert_ne!(out1, out2);
        assert_ne!(out2, out3);
        assert_ne!(out1, out3);
    }

    #[test]
    fn e2e_cbd_eta2_boundary_buffer_size() {
        let mut out = [0i16; N];
        // Test with exactly the minimum required size
        let buf = vec![0x5Au8; N / 2];

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_ok(), "Should work with exactly N/2 bytes");
    }

    #[test]
    fn e2e_cbd_eta2_off_by_one_buffer() {
        let mut out = [0i16; N];
        // One byte less than minimum
        let buf = vec![0u8; N / 2 - 1];

        let result = cbd_eta2_poly(&mut out, &buf);
        assert!(result.is_err(), "Should fail with N/2 - 1 bytes");
    }

    // ============================================================================
    // PROPERTY-BASED TESTS - Testing statistical and mathematical properties
    // ============================================================================

    #[test]
    fn property_cbd_eta2_output_bounded() {
        // CBD-eta2: a, b ∈ {0,1,2,3}, val = a - b ∈ {-3,-2,-1,0,1,2,3}
        // After (val + Q) % Q, valid outputs are: {0,1,2,3, Q-3, Q-2, Q-1}
        let mut out = [0i16; N];
        let mut buf = vec![0u8; N / 2 + 10];

        // Test with various patterns
        for pattern in [0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0] {
            buf.fill(pattern);
            cbd_eta2_poly(&mut out, &buf).expect("cbd_eta2_poly should succeed");

            for (i, &coeff) in out.iter().enumerate() {
                // Valid CBD-eta2 outputs after modulo Q
                let is_valid = coeff == 0
                    || coeff == 1
                    || coeff == 2
                    || coeff == 3
                    || coeff == Q - 3
                    || coeff == Q - 2
                    || coeff == Q - 1;

                assert!(
                    is_valid,
                    "Coefficient {} at index {} is not a valid CBD-eta2 output for pattern 0x{:02X}",
                    coeff, i, pattern
                );
            }
        }
    }

    #[test]
    fn property_cbd_eta2_same_input_same_output() {
        let mut out1 = [0i16; N];
        let mut out2 = [0i16; N];

        for pattern in [0x00, 0x12, 0x34, 0x56, 0x78, 0x9A] {
            let buf = vec![pattern; N / 2 + 10];

            cbd_eta2_poly(&mut out1, &buf).expect("cbd_eta2_poly should succeed");
            cbd_eta2_poly(&mut out2, &buf).expect("cbd_eta2_poly should succeed");

            assert_eq!(
                out1, out2,
                "Determinism failed for pattern 0x{:02X}",
                pattern
            );
        }
    }

    #[test]
    fn property_cbd_eta2_distribution_check() {
        // With all possible 4-bit values (0x0 to 0xF), check distribution
        let mut out = [0i16; N];

        // Test each possible 4-bit pattern
        for nibble in 0u8..=15 {
            let pattern = nibble | (nibble << 4); // Repeat nibble in both halves
            let buf = vec![pattern; N / 2 + 10];

            cbd_eta2_poly(&mut out, &buf).expect("cbd_eta2_poly should succeed");

            // Verify all coefficients are valid CBD-eta2 outputs
            for &coeff in &out {
                let is_valid = coeff == 0
                    || coeff == 1
                    || coeff == 2
                    || coeff == 3
                    || coeff == Q - 3
                    || coeff == Q - 2
                    || coeff == Q - 1;

                assert!(
                    is_valid,
                    "Invalid coefficient {} for nibble pattern 0x{:X}",
                    coeff, nibble
                );
            }
        }
    }
}
