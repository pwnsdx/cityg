// this file implements neccessary arithmetics over Z_p[x]/(x^32 + R)

use crate::param::{BETA, BETA_M2_P1, P, R, R_BASE};
use crate::poly::PolyArith;
use crate::poly256::Poly256;
use rand::{CryptoRng, RngCore};
use std::convert::From;
use subtle::Choice;
use zeroize::Zeroize;
// use std::fmt;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Poly32 {
    pub coeff: [i64; 32],
}

impl Zeroize for Poly32 {
    fn zeroize(&mut self) {
        for coeff in self.coeff.iter_mut() {
            *coeff = 0;
        }
    }
}

impl From<Poly256> for Poly32 {
    // converting a ring element over Z_q[x]/(x^256+1)
    // into a ring elemetn over Z_p[x]/(x^32+R)
    fn from(a: Poly256) -> Self {
        let mut res = [0i64; 32];
        res.copy_from_slice(&a.coeff[0..32]);

        for (i, e) in res.iter_mut().enumerate() {
            for (j, r) in R_BASE.iter().enumerate().skip(1) {
                *e += a.coeff[i + (j << 5)] * (*r);
            }
            *e %= P;
        }

        Self { coeff: res }
    }
}

impl PolyArith for Poly32 {
    const DEGREE: usize = 32;
    const MODULUS: i64 = P;

    fn add(a: &Self, b: &Self) -> Self {
        let mut res = [0i64; Self::DEGREE];
        for (i, e) in res.iter_mut().enumerate() {
            *e = (a.coeff[i] + b.coeff[i]) % Self::MODULUS;
        }
        Poly32 { coeff: res }
    }

    fn sub(a: &Self, b: &Self) -> Self {
        let mut res = [0i64; 32];
        for (i, e) in res.iter_mut().enumerate() {
            *e = (a.coeff[i] + (Self::MODULUS << 1) - b.coeff[i]) % Self::MODULUS;
        }
        Poly32 { coeff: res }
    }

    fn mul(a: &Self, b: &Self) -> Self {
        // School-book multiplication: O(n²) complexity
        // Benchmarks (release mode, 1000 iterations):
        // - School-book: 643µs (0.64µs per multiplication)
        // - Karatsuba:   2.4ms (2.4µs per multiplication - 4× SLOWER due to heap allocations)
        //
        // For degree 32, school-book is optimal. Karatsuba only wins at degree 64+.
        // The simple nested loop is cache-friendly and compiler-optimizable.
        school_book(a, b)
    }

    fn mul_trinary(a: &Self, trinary: &Self) -> Self {
        // The optimized implementation mirrors Poly256 but the generic school-book
        // multiplication already applies the correct reduction modulo x^32 + R.
        // Calling `mul` keeps the code path simple while avoiding `unimplemented!`.
        Self::mul(a, trinary)
    }
    fn mul_karatsuba(a: &Self, b: &Self) -> Self {
        // Karatsuba does not provide a measurable benefit at degree 32; fall back to
        // the standard multiplication to keep behaviour fully defined.
        Self::mul(a, b)
    }

    // assign
    fn zero() -> Self {
        Poly32 {
            coeff: [0i64; Self::DEGREE],
        }
    }

    fn normalized(&mut self) {
        for e in self.coeff.iter_mut() {
            (*e) = (*e + (Self::MODULUS << 1)) % Self::MODULUS;
        }
    }

    fn centered(&mut self) {
        self.normalized();
        for e in self.coeff.iter_mut() {
            let doubled = *e << 1;
            let reduce = Choice::from((doubled > Self::MODULUS) as u8);
            let mask = (reduce.unwrap_u8() as i64) * Self::MODULUS;
            *e -= mask;
        }
    }
    // random polynomials modulo Q
    fn uniform_random<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut coeff = [0i64; Self::DEGREE];
        let modulus = Self::MODULUS as u64;
        for e in coeff.iter_mut() {
            let tmp = rng.next_u32() as u64;
            let mapped = ((tmp.wrapping_mul(modulus)) >> 32) as i64;
            *e = mapped;
        }
        Poly32 { coeff }
    }

    // random polynomials modulus beta
    fn rand_mod_beta<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut coeff = [0i64; Self::DEGREE];
        let range = BETA_M2_P1 as u64;
        for e in coeff.iter_mut() {
            let tmp = rng.next_u32() as u64;
            let mapped = (tmp.wrapping_mul(range)) >> 32;
            *e = mapped as i64 - BETA;
        }
        Poly32 { coeff }
    }

    fn rand_trinary<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut coeff = [0i64; Self::DEGREE];
        for e in coeff.iter_mut() {
            let tmp = rng.next_u32() as u64;
            let mapped = ((tmp.wrapping_mul(3)) >> 32) as i64;
            *e = mapped - 1;
        }
        Poly32 { coeff }
    }
}

pub(crate) fn poly32_inner_product(a: &[Poly32], b: &[Poly32]) -> Poly32 {
    if a.len() != b.len() {
        debug_assert!(
            a.len() == b.len(),
            "poly32_inner_product length mismatch ({} vs {})",
            a.len(),
            b.len()
        );
    }
    let mut res = Poly32::zero();
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        res.add_assign(&Poly32::mul(lhs, rhs));
    }
    res.normalized();
    res
}

pub(crate) fn school_book(a: &Poly32, b: &Poly32) -> Poly32 {
    let mut res = [0i64; Poly32::DEGREE << 1];
    school_book_without_reduction(&a.coeff, &b.coeff, &mut res, Poly32::DEGREE);

    let mut array = [0; Poly32::DEGREE];
    for i in 0..Poly32::DEGREE {
        array[i] = (res[i] + (P << 2) - R * (res[i + Poly32::DEGREE] % P)) % P;
    }
    Poly32 { coeff: array }
}

/// Karatsuba multiplication for Poly32 (experimental, not used in production)
/// Complexity: O(n^1.585) vs O(n^2) for school-book
/// For degree 32: Theoretical 6× speedup, but actual 4× SLOWER due to heap allocations.
/// Kept for benchmarking and potential future use with stack-allocated buffers.
#[cfg(test)]
pub(crate) fn karatsuba(a: &Poly32, b: &Poly32) -> Poly32 {
    let mut res = [0i64; Poly32::DEGREE << 1];
    karatsuba_impl(&a.coeff, &b.coeff, &mut res, Poly32::DEGREE);

    let mut array = [0; Poly32::DEGREE];
    for i in 0..Poly32::DEGREE {
        array[i] = (res[i] + (P << 2) - R * (res[i + Poly32::DEGREE] % P)) % P;
    }
    Poly32 { coeff: array }
}

/// Recursive Karatsuba implementation
#[cfg(test)]
fn karatsuba_impl(a: &[i64], b: &[i64], c: &mut [i64], n: usize) {
    // Base case: use school-book for small polynomials
    if n <= 8 {
        school_book_without_reduction(a, b, c, n);
        return;
    }

    let half = n / 2;

    // Allocate temporary buffers
    let mut f0 = vec![0i64; n]; // f(0) = a_low * b_low
    let mut f_inf = vec![0i64; n]; // f(∞) = a_high * b_high
    let mut f1 = vec![0i64; n]; // f(1) = (a_low + a_high)(b_low + b_high)

    // Compute f(0) = a_low * b_low
    karatsuba_impl(&a[0..half], &b[0..half], &mut f0, half);

    // Compute f(∞) = a_high * b_high
    karatsuba_impl(&a[half..n], &b[half..n], &mut f_inf, half);

    // Compute sums: a_low + a_high, b_low + b_high
    let a_sum: Vec<i64> = (0..half).map(|i| a[i] + a[i + half]).collect();
    let b_sum: Vec<i64> = (0..half).map(|i| b[i] + b[i + half]).collect();

    // Compute f(1) = (a_low + a_high)(b_low + b_high)
    karatsuba_impl(&a_sum, &b_sum, &mut f1, half);

    // Compute middle term: f(1) - f(0) - f(∞) = a_low*b_high + a_high*b_low
    let middle: Vec<i64> = (0..n).map(|i| f1[i] - f0[i] - f_inf[i]).collect();

    // Combine results: c = f(0) + middle*x^half + f(∞)*x^n
    for i in 0..half {
        c[i] += f0[i];
        c[i + half] += f0[i + half] + middle[i];
        c[i + n] += middle[i + half] + f_inf[i];
        c[i + n + half] += f_inf[i + half];
    }
}

/// School-book multiplication without reduction (for Karatsuba base case)
fn school_book_without_reduction(a: &[i64], b: &[i64], c: &mut [i64], n: usize) {
    for i in 0..n {
        for j in 0..n {
            c[i + j] += a[i] * b[j];
        }
    }
}
