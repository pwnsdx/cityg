use crate::param::{P, R_BASE};
use crate::poly::PolyArith;
use crate::poly32::Poly32;
use crate::poly32::poly32_inner_product;
use crate::poly256::Poly256;
use crate::serde::Serdes;
use proptest::prelude::*;
use zeroize::Zeroize;

#[test]
fn test_rand_mod_p() {
    let mut rng = rand::thread_rng();
    let a: Poly32 = PolyArith::uniform_random(&mut rng);
    for e in a.coeff.iter() {
        assert!(*e < Poly32::MODULUS, "coefficient greater than Q")
    }
}

#[test]
fn test_poly32_mul() {
    let mut rng = rand::thread_rng();

    // zero
    let a = Poly32::zero();
    let b = Poly32::uniform_random(&mut rng);
    let c = Poly32::mul(&a, &b);
    for e in c.coeff.iter() {
        assert!(*e == 0, "coefficient not zero")
    }

    // associative

    let a = Poly32::uniform_random(&mut rng);
    let b = Poly32::uniform_random(&mut rng);
    let c = Poly32::mul(&a, &b);
    let d = Poly32::mul(&b, &a);
    assert!(c == d, "coefficient not zero");

    // (x+1) * (x+1) = x^2 + 2x + 1
    let mut a = Poly32::zero();
    a.coeff[0] = 1;
    a.coeff[1] = 1;
    let b = Poly32::mul(&a, &a);
    assert!(b.coeff[0] == 1);
    assert!(b.coeff[1] == 2);
    assert!(b.coeff[2] == 1);
    for i in 3..Poly32::DEGREE {
        assert!(b.coeff[i] == 0)
    }
}

fn poly32_strategy() -> impl Strategy<Value = Poly32> {
    prop::collection::vec(0..Poly32::MODULUS, Poly32::DEGREE).prop_map(|coeffs| {
        let mut arr = [0i64; Poly32::DEGREE];
        for (i, value) in coeffs.into_iter().enumerate() {
            arr[i] = value % Poly32::MODULUS;
        }
        Poly32 { coeff: arr }
    })
}

proptest! {
    #[test]
    fn add_commutative(a in poly32_strategy(), b in poly32_strategy()) {
        let lhs = Poly32::add(&a, &b);
        let rhs = Poly32::add(&b, &a);
        prop_assert_eq!(lhs.coeff, rhs.coeff);
    }

    #[test]
    fn add_sub_inverse(a in poly32_strategy(), b in poly32_strategy()) {
        let sum = Poly32::add(&a, &b);
        let recovered = Poly32::sub(&sum, &b);
        prop_assert_eq!(recovered.coeff, a.coeff);
    }

    #[test]
    fn serialize_roundtrip(a in poly32_strategy()) {
        let mut buf = Vec::new();
        match a.serialize(&mut buf) {
            Ok(_) => {},
            Err(_) => unreachable!("serialize poly32 should not fail"),
        }
        let decoded = match Poly32::deserialize(&mut buf.as_slice()) {
            Ok(d) => d,
            Err(_) => unreachable!("deserialize poly32 should not fail"),
        };
        prop_assert_eq!(decoded.coeff, a.coeff);
    }
}

#[test]
fn test_poly32_inner_prod() {
    let mut a = Poly32::zero();
    a.coeff[0] = 1;
    a.coeff[1] = -1;
    let vec_a = [a; 4];
    let vec_b = [a; 4];
    let c = poly32_inner_product(vec_a.as_ref(), vec_b.as_ref());
    println!("{:?}", c);
    assert!(c.coeff[0] == 4);
    assert!(c.coeff[1] == P - 8);
    assert!(c.coeff[2] == 4);
    for i in 3..Poly32::DEGREE {
        assert!(c.coeff[i] == 0)
    }
    println!(
        "{:?}",
        a.coeff.iter().map(|x| *x as i32).collect::<Vec<i32>>()
    );
}

#[test]
fn test_poly32_serdes() -> Result<(), Box<dyn std::error::Error>> {
    // zero poly
    let a = Poly32::zero();
    let mut buf: Vec<u8> = vec![];
    assert!(a.serialize(&mut buf).is_ok());
    let b = Poly32::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(a, b);

    // random poly
    let mut rng = rand::thread_rng();
    let a: Poly32 = PolyArith::uniform_random(&mut rng);
    let mut buf: Vec<u8> = vec![];
    assert!(a.serialize(&mut buf).is_ok());
    let b = Poly32::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(a, b);
    Ok(())
}

#[test]
fn test_karatsuba() {
    use crate::poly32::{karatsuba, school_book};

    let mut rng = rand::thread_rng();

    // Test 100 random pairs to ensure correctness
    for _ in 0..100 {
        let a = Poly32::uniform_random(&mut rng);
        let b = Poly32::uniform_random(&mut rng);

        let result_schoolbook = school_book(&a, &b);
        let result_karatsuba = karatsuba(&a, &b);

        assert_eq!(
            result_schoolbook.coeff, result_karatsuba.coeff,
            "Karatsuba and school-book results must match"
        );
    }

    // Test edge cases
    let zero = Poly32::zero();
    let a = Poly32::uniform_random(&mut rng);

    assert_eq!(
        school_book(&zero, &a).coeff,
        karatsuba(&zero, &a).coeff,
        "Multiplication by zero"
    );

    // Test (x+1) * (x+1) = x^2 + 2x + 1
    let mut poly = Poly32::zero();
    poly.coeff[0] = 1;
    poly.coeff[1] = 1;

    let result_sb = school_book(&poly, &poly);
    let result_ka = karatsuba(&poly, &poly);

    assert_eq!(result_sb.coeff, result_ka.coeff, "Simple polynomial test");
    assert_eq!(result_ka.coeff[0], 1);
    assert_eq!(result_ka.coeff[1], 2);
    assert_eq!(result_ka.coeff[2], 1);
}

#[test]
fn test_from_poly256_matches_manual_fold() {
    let mut source = Poly256::zero();
    for j in 0..8usize {
        source.coeff[j << 5] = (j as i64) + 1;
        source.coeff[1 + (j << 5)] = (j as i64) + 3;
    }

    let converted = Poly32::from(source);
    for i in 0..Poly32::DEGREE {
        let mut expected = 0i64;
        for (j, r) in R_BASE.iter().enumerate() {
            expected += source.coeff[i + (j << 5)] * (*r);
        }
        expected %= P;
        assert_eq!(converted.coeff[i], expected, "index {i} mismatch");
    }
}

#[test]
fn test_wrapper_methods_and_zeroize() {
    let mut rng = rand::thread_rng();
    let a = Poly32::uniform_random(&mut rng);
    let b = Poly32::rand_trinary(&mut rng);

    assert_eq!(Poly32::mul(&a, &b), Poly32::mul_trinary(&a, &b));
    assert_eq!(Poly32::mul(&a, &b), Poly32::mul_karatsuba(&a, &b));

    let mut z = a;
    z.zeroize();
    assert!(z.coeff.iter().all(|c| *c == 0));
}

#[test]
fn test_normalized_centered_and_random_ranges() {
    let mut poly = Poly32 {
        coeff: [
            -1,
            -P - 1,
            P + 2,
            2 * P + 3,
            -3 * P - 4,
            5,
            -6,
            7,
            -8,
            9,
            -10,
            11,
            -12,
            13,
            -14,
            15,
            -16,
            17,
            -18,
            19,
            -20,
            21,
            -22,
            23,
            -24,
            25,
            -26,
            27,
            -28,
            29,
            -30,
            31,
        ],
    };
    let original = poly.coeff;
    poly.normalized();
    for (i, (before, after)) in original.iter().zip(poly.coeff.iter()).enumerate() {
        let expected = (before + (P << 1)) % P;
        assert_eq!(*after, expected, "normalized mismatch at index {i}");
        assert!(
            *after > -P && *after < P,
            "normalized coefficient out of reduced range at index {i}"
        );
    }

    let normalized = poly.coeff;
    poly.centered();
    for (i, (before, after)) in normalized.iter().zip(poly.coeff.iter()).enumerate() {
        let mut expected = (before + (P << 1)) % P;
        if (expected << 1) > P {
            expected -= P;
        }
        assert_eq!(*after, expected, "centered mismatch at index {i}");
    }

    let mut rng = rand::thread_rng();
    let beta_poly = Poly32::rand_mod_beta(&mut rng);
    let beta_high = crate::param::BETA_M2_P1 as i64 - crate::param::BETA - 1;
    assert!(
        beta_poly
            .coeff
            .iter()
            .all(|c| *c >= -crate::param::BETA && *c <= beta_high)
    );

    let tri = Poly32::rand_trinary(&mut rng);
    assert!(tri.coeff.iter().all(|c| (-1..=1).contains(c)));
}

#[test]
fn test_inner_product_length_mismatch_panics_in_debug() {
    let a = [Poly32::zero(); 2];
    let b = [Poly32::zero(); 1];
    let result = std::panic::catch_unwind(|| {
        let _ = poly32_inner_product(&a, &b);
    });
    assert!(result.is_err());
}

#[test]
fn bench_poly32_multiplication() {
    use crate::poly32::{karatsuba, school_book};
    use std::time::Instant;

    let mut rng = rand::thread_rng();
    let test_pairs: Vec<(Poly32, Poly32)> = (0..1000)
        .map(|_| {
            (
                Poly32::uniform_random(&mut rng),
                Poly32::uniform_random(&mut rng),
            )
        })
        .collect();

    // Verify correctness: both methods must produce identical results
    for (a, b) in &test_pairs {
        let result_schoolbook = school_book(a, b);
        let result_karatsuba = karatsuba(a, b);
        assert_eq!(
            result_schoolbook.coeff, result_karatsuba.coeff,
            "Karatsuba and schoolbook results must match for all inputs"
        );
    }

    // Benchmark school-book
    let start = Instant::now();
    for (a, b) in &test_pairs {
        let _ = school_book(a, b);
    }
    let schoolbook_time = start.elapsed();

    // Benchmark Karatsuba
    let start = Instant::now();
    for (a, b) in &test_pairs {
        let _ = karatsuba(a, b);
    }
    let karatsuba_time = start.elapsed();

    println!("\n=== Poly32 Multiplication Benchmark (1000 iterations) ===");
    println!("School-book: {:?}", schoolbook_time);
    println!("Karatsuba:   {:?}", karatsuba_time);
    println!(
        "Speedup:     {:.2}×",
        schoolbook_time.as_secs_f64() / karatsuba_time.as_secs_f64()
    );
}
