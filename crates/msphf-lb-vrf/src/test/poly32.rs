use crate::param::P;
use crate::poly::PolyArith;
use crate::poly32::Poly32;
use crate::poly32::poly32_inner_product;
use crate::serde::Serdes;
use proptest::prelude::*;

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
        a.serialize(&mut buf).expect("serialize poly32");
        let decoded = Poly32::deserialize(&mut buf.as_slice()).expect("deserialize poly32");
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
fn test_poly32_serdes() {
    // zero poly
    let a = Poly32::zero();
    let mut buf: Vec<u8> = vec![];
    assert!(a.serialize(&mut buf).is_ok());
    let b = Poly32::deserialize(&mut buf[..].as_ref()).expect("deserialize zero poly");
    assert_eq!(a, b);

    // random poly
    let mut rng = rand::thread_rng();
    let a: Poly32 = PolyArith::uniform_random(&mut rng);
    let mut buf: Vec<u8> = vec![];
    assert!(a.serialize(&mut buf).is_ok());
    let b = Poly32::deserialize(&mut buf[..].as_ref()).expect("deserialize random poly");
    assert_eq!(a, b);
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
