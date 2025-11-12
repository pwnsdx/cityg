use anyhow::{Result, anyhow};
use ark_ff::Field;

use super::{ArithPermutation, poseidon_params};
use crate::field::{BaseField, FieldElement};

/// Poseidon permutation instantiated over BN254-like field with width = rate + 1 capacity.
#[derive(Clone, Debug)]
pub struct PoseidonPermutation {
    config: ark_sponge::poseidon::PoseidonConfig<BaseField>,
}

impl PoseidonPermutation {
    pub fn new(rate: usize) -> Result<Self> {
        if rate != 2 {
            return Err(anyhow!(
                "poseidon parameters currently only available for rate=2"
            ));
        }
        let config = poseidon_params::poseidon_config_rate_2();
        Ok(Self { config })
    }

    fn width_internal(&self) -> usize {
        self.config.rate + self.config.capacity
    }

    fn apply_s_box(&self, state: &mut [BaseField], is_full_round: bool) {
        if is_full_round {
            for elem in state.iter_mut() {
                *elem = elem.pow([self.config.alpha]);
            }
        } else if let Some(first) = state.first_mut() {
            *first = first.pow([self.config.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [BaseField], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            *state_elem += self.config.ark[round_number][i];
        }
    }

    fn apply_mds(&self, state: &mut [BaseField]) {
        let mut new_state = vec![BaseField::ZERO; state.len()];
        for (row_idx, new_elem) in new_state.iter_mut().enumerate() {
            for (col_idx, state_elem) in state.iter().enumerate() {
                *new_elem += *state_elem * self.config.mds[row_idx][col_idx];
            }
        }
        state.copy_from_slice(&new_state);
    }

    fn permute_base(&self, state: &mut [BaseField]) {
        let full_rounds_over_2 = self.config.full_rounds / 2;

        for i in 0..full_rounds_over_2 {
            self.apply_ark(state, i);
            self.apply_s_box(state, true);
            self.apply_mds(state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.config.partial_rounds) {
            self.apply_ark(state, i);
            self.apply_s_box(state, false);
            self.apply_mds(state);
        }

        for i in (full_rounds_over_2 + self.config.partial_rounds)
            ..(self.config.partial_rounds + self.config.full_rounds)
        {
            self.apply_ark(state, i);
            self.apply_s_box(state, true);
            self.apply_mds(state);
        }
    }
}

impl ArithPermutation for PoseidonPermutation {
    fn width(&self) -> usize {
        self.width_internal()
    }

    fn apply(&self, state: &mut [FieldElement]) {
        assert_eq!(state.len(), self.width_internal());
        let mut base_vec: Vec<BaseField> = state.iter().map(|fe| fe.as_base()).collect();
        self.permute_base(&mut base_vec);
        for (dst, src) in state.iter_mut().zip(base_vec.iter()) {
            dst.0 = *src;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn poseidon_width_three_sample() {
        let perm = PoseidonPermutation::new(2).expect("params");
        assert_eq!(perm.width(), 3);
        let mut state = vec![
            FieldElement::from_base(BaseField::from(1u64)),
            FieldElement::from_base(BaseField::from(2u64)),
            FieldElement::from_base(BaseField::from(3u64)),
        ];
        perm.apply(&mut state);
        let expected = [
            "20731498007075377806227063087136653870377425758593369711890226233450742536781",
            "8823471519575131389981555722120588537128536673538146539323802874427380525833",
            "19484191902595336660794804167147433811406035260799267340256254867788422538388",
        ];
        for (elem, exp) in state.iter().zip(expected.iter()) {
            assert_eq!(
                elem.as_base(),
                BaseField::from_str(exp).expect("BaseField::from_str")
            );
        }
    }

    #[test]
    fn poseidon_rejects_unsupported_rate() {
        let err = PoseidonPermutation::new(3).expect_err("rate 3 unsupported");
        assert!(
            err.to_string()
                .contains("poseidon parameters currently only available for rate=2")
        );
    }
}
