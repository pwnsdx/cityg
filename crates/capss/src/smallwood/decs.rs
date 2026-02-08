use anyhow::{Result, anyhow, bail};
use ark_ff::{BigInteger, PrimeField};
use blake3::Hasher;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::HashSet;

use crate::field::BaseField;

use super::{commit::field_to_bytes, polynomial::eval, rng::RoundSeeder};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DecsChallengeFormat {
    Powers,
    #[default]
    Uniform,
    Hybrid,
}

#[derive(Clone, Debug)]
pub struct DecsConfig {
    pub nb_polys: usize,
    pub degree: usize,
    pub eta: usize,
    pub nb_queries: usize,
    pub nb_evals: usize,
    pub format_challenge: DecsChallengeFormat,
    pub pow_opening_bits: u32,
    pub use_commitment_tapes: bool,
    pub digest_bytes: usize,
    pub salt_bytes: usize,
    pub tree_arity: Vec<usize>,
    pub tree_truncation: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct DecsCommitment {
    pub config: DecsConfig,
}

#[derive(Clone, Debug)]
pub struct DecsState {
    pub shares: Vec<Vec<BaseField>>, // evaluations per column (polys + masks)
    pub mask_polys: Vec<Vec<BaseField>>,
    pub tree: ShakeMerkleTree,
    pub eps: Vec<Vec<BaseField>>,
    pub commitment_tapes: Vec<Vec<u8>>,
}

impl DecsCommitment {
    pub fn new(config: DecsConfig) -> Self {
        Self { config }
    }

    pub fn commit(
        &self,
        salt: &[u8],
        polynomials: &[Vec<BaseField>],
        round_seeder: Option<&RoundSeeder>,
    ) -> Result<(Vec<u8>, DecsState)> {
        let cfg = &self.config;
        if salt.len() < cfg.salt_bytes {
            return Err(anyhow!("decs salt length mismatch"));
        }
        let salt = &salt[..cfg.salt_bytes];
        if polynomials.len() != cfg.nb_polys {
            return Err(anyhow!("decs polynomial count mismatch"));
        }
        for poly in polynomials {
            if poly.len() > cfg.degree + 1 {
                return Err(anyhow!("polynomial degree exceeds bound"));
            }
        }

        let seeder =
            round_seeder.ok_or_else(|| anyhow!("decs commitment requires round seeder"))?;
        let mask_polys = self.sample_mask_polys(seeder);
        let domain_size = self.evaluation_domain_size();
        let mut shares = Vec::with_capacity(domain_size);
        let mut hashed_leaves = Vec::with_capacity(domain_size);
        let mut commitment_tapes = Vec::with_capacity(domain_size);

        for idx in 0..domain_size {
            let point = self.evaluation_point(idx);
            let mut row = Vec::with_capacity(cfg.nb_polys + cfg.eta);
            for poly in polynomials {
                row.push(eval(poly, point));
            }
            for mask in &mask_polys {
                row.push(eval(mask, point));
            }

            let row_bytes = pack_field_values(&row);
            let tape = if cfg.use_commitment_tapes {
                derive_commitment_tape(salt, idx, cfg.digest_bytes)
            } else {
                Vec::new()
            };
            let leaf_hash = hash_leaf(salt, idx, &row_bytes, &tape, cfg.digest_bytes);

            shares.push(row);
            hashed_leaves.push(leaf_hash);
            commitment_tapes.push(tape);
        }

        let mut all_leaves = hashed_leaves.clone();
        while all_leaves.len() < cfg.nb_evals {
            all_leaves.push(vec![0u8; cfg.digest_bytes]);
        }

        let tree = ShakeMerkleTree::from_leaves(
            cfg.tree_arity.clone(),
            cfg.tree_truncation,
            cfg.digest_bytes,
            domain_size,
            all_leaves,
        );
        let root = tree.root().to_vec();
        let hash_mt = hash_merkle_root(&root, cfg.digest_bytes);

        let gamma = self.derive_gamma(&hash_mt);
        let eps = self.compute_eps(polynomials, &mask_polys, &gamma);
        let mut eps_flat = Vec::with_capacity(cfg.eta * (cfg.degree + 1));
        for poly in &eps {
            eps_flat.extend_from_slice(poly);
        }
        let eps_bytes = pack_field_values(&eps_flat);

        let mut commitment = Vec::new();
        commitment.extend_from_slice(&hash_mt);
        commitment.extend_from_slice(&eps_bytes);

        Ok((
            commitment,
            DecsState {
                shares,
                mask_polys,
                tree,
                eps,
                commitment_tapes,
            },
        ))
    }

    /// Derive the DEC challenge matrix γ using the Blake3-XOF helper.
    pub fn derive_gamma(&self, seed: &[u8]) -> Vec<Vec<BaseField>> {
        let cfg = &self.config;
        let mut hasher = Shake128::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        match cfg.format_challenge {
            DecsChallengeFormat::Uniform => (0..cfg.eta)
                .map(|_| {
                    (0..cfg.nb_polys)
                        .map(|_| sample_field_from_reader(&mut reader))
                        .collect::<Vec<_>>()
                })
                .collect(),
            DecsChallengeFormat::Powers => {
                let mut bases = Vec::with_capacity(cfg.eta);
                for _ in 0..cfg.eta {
                    bases.push(sample_field_from_reader(&mut reader));
                }
                bases
                    .into_iter()
                    .map(|base| {
                        let mut coeffs = Vec::with_capacity(cfg.nb_polys);
                        let mut power = BaseField::from(1u64);
                        for _ in 0..cfg.nb_polys {
                            coeffs.push(power);
                            power *= base;
                        }
                        coeffs
                    })
                    .collect()
            }
            DecsChallengeFormat::Hybrid => {
                let rows = cfg.eta;
                let cols = cfg.nb_polys;
                let mut random_matrix = Vec::with_capacity(rows);
                for _ in 0..rows {
                    let mut row = Vec::with_capacity(rows + 1);
                    for _ in 0..=rows {
                        row.push(sample_field_from_reader(&mut reader));
                    }
                    random_matrix.push(row);
                }
                let mut base_powers = Vec::with_capacity(rows + 1);
                for _ in 0..=rows {
                    let base = sample_field_from_reader(&mut reader);
                    let mut powers = Vec::with_capacity(cols);
                    let mut acc = BaseField::from(1u64);
                    for _ in 0..cols {
                        powers.push(acc);
                        acc *= base;
                    }
                    base_powers.push(powers);
                }
                let mut gamma = Vec::with_capacity(rows);
                for random_row in random_matrix.iter() {
                    let mut coeffs = vec![BaseField::from(0u64); cols];
                    for (power_idx, rnd) in random_row.iter().enumerate() {
                        for (coeff, base_power) in
                            coeffs.iter_mut().zip(base_powers[power_idx].iter())
                        {
                            *coeff += *rnd * *base_power;
                        }
                    }
                    gamma.push(coeffs);
                }
                gamma
            }
        }
    }

    fn sample_mask_polys(&self, round_seeder: &RoundSeeder) -> Vec<Vec<BaseField>> {
        (0..self.config.eta)
            .map(|mask_idx| {
                let context = (mask_idx as u64).to_le_bytes();
                let branch = round_seeder.branch(b"decs/mask", &context);
                (0..=self.config.degree)
                    .map(|coeff_idx| {
                        let coeff_ctx = (coeff_idx as u64).to_le_bytes();
                        branch.field(b"decs/mask/coeff", &coeff_ctx)
                    })
                    .collect()
            })
            .collect()
    }

    fn compute_eps(
        &self,
        polynomials: &[Vec<BaseField>],
        mask_polys: &[Vec<BaseField>],
        gamma: &[Vec<BaseField>],
    ) -> Vec<Vec<BaseField>> {
        let degree = self.config.degree;
        let mut eps = Vec::with_capacity(self.config.eta);
        for j in 0..self.config.eta {
            let mut poly = vec![BaseField::from(0u64); degree + 1];
            for (dst, src) in poly.iter_mut().zip(mask_polys[j].iter()) {
                *dst = *src;
            }
            for (k, witness_poly) in polynomials.iter().enumerate() {
                let coeff = gamma[j][k];
                for (dst, src) in poly.iter_mut().zip(witness_poly.iter()) {
                    *dst += coeff * *src;
                }
            }
            eps.push(poly);
        }
        eps
    }

    pub fn open(
        &self,
        state: &DecsState,
        queries: &[BaseField],
    ) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
        let cfg = &self.config;
        let nb_evals = state.shares.len();
        let mut opened = Vec::with_capacity(queries.len());
        let mut masks = Vec::with_capacity(queries.len());
        let mut paths = Vec::with_capacity(queries.len());
        let mut tapes = Vec::with_capacity(queries.len());

        for query in queries {
            let idx = self.find_index(query, nb_evals)?;
            let row = &state.shares[idx];
            opened.push(row[..cfg.nb_polys].to_vec());
            masks.push(row[cfg.nb_polys..].to_vec());
            paths.push(state.tree.authentication_path(idx));
            tapes.push(state.commitment_tapes[idx].clone());
        }

        let mut proof = Vec::new();
        let mask_flat: Vec<BaseField> = masks.iter().flat_map(|row| row.iter().cloned()).collect();
        let mask_bytes = pack_field_values(&mask_flat);
        proof.extend_from_slice(&mask_bytes);

        let keep = cfg.nb_queries;
        let eps_high_flat: Vec<BaseField> = state
            .eps
            .iter()
            .flat_map(|poly| poly[keep..].iter().cloned())
            .collect();
        let eps_bytes = pack_field_values(&eps_high_flat);
        proof.extend_from_slice(&eps_bytes);

        if cfg.use_commitment_tapes {
            for tape in &tapes {
                proof.extend_from_slice(tape);
            }
        }

        let level_siblings: Vec<usize> = self
            .config
            .tree_arity
            .iter()
            .rev()
            .map(|branch| branch.saturating_sub(1))
            .collect();
        let level_padding = null_digest(self.config.digest_bytes);
        for path in &paths {
            debug_assert_eq!(path.len(), level_siblings.len());
            for (level_idx, siblings) in path.iter().enumerate() {
                let expected = level_siblings[level_idx];
                debug_assert!(siblings.len() <= expected);
                for digest in siblings.iter().take(expected) {
                    proof.extend_from_slice(digest);
                }
                if siblings.len() < expected {
                    for _ in 0..(expected - siblings.len()) {
                        proof.extend_from_slice(&level_padding);
                    }
                }
            }
        }

        Ok((opened, proof))
    }

    pub fn recompute_commitment(
        &self,
        salt: &[u8],
        queries: &[BaseField],
        opened_values: &[Vec<BaseField>],
        proof: &[u8],
    ) -> Result<Vec<u8>> {
        if queries.len() != opened_values.len() {
            return Err(anyhow!("query/open mismatch"));
        }
        if salt.len() < self.config.salt_bytes {
            return Err(anyhow!("decs salt length mismatch"));
        }
        let salt = &salt[..self.config.salt_bytes];

        let bit_len = BaseField::MODULUS_BIT_SIZE as usize;
        let mask_count = queries.len() * self.config.eta;
        let mask_bits = mask_count * bit_len;
        let mask_bytes_len = mask_bits.div_ceil(8);
        if proof.len() < mask_bytes_len {
            return Err(anyhow!("proof truncated (mask bytes)"));
        }
        let mask_flat = unpack_field_values(&proof[..mask_bytes_len], mask_count)?;
        let mut mask_rows = Vec::with_capacity(queries.len());
        for chunk in mask_flat.chunks(self.config.eta) {
            mask_rows.push(chunk.to_vec());
        }
        let mut cursor = &proof[mask_bytes_len..];

        let eps_high_len = self.config.degree + 1 - self.config.nb_queries;
        let eps_high_count = self.config.eta * eps_high_len;
        let eps_bits = eps_high_count * bit_len;
        let eps_bytes_len = eps_bits.div_ceil(8);
        if cursor.len() < eps_bytes_len {
            return Err(anyhow!("proof truncated (epsilon bytes)"));
        }
        let eps_high_segment = &cursor[..eps_bytes_len];
        let eps_high_flat = unpack_field_values(eps_high_segment, eps_high_count)?;
        cursor = &cursor[eps_bytes_len..];
        let mut eps_high = Vec::with_capacity(self.config.eta);
        for chunk in eps_high_flat.chunks(eps_high_len) {
            eps_high.push(chunk.to_vec());
        }

        let mut commitment_tapes = Vec::with_capacity(queries.len());
        if self.config.use_commitment_tapes {
            let tape_len = self.config.digest_bytes;
            for _ in 0..queries.len() {
                if cursor.len() < tape_len {
                    return Err(anyhow!("proof truncated (tape bytes)"));
                }
                commitment_tapes.push(cursor[..tape_len].to_vec());
                cursor = &cursor[tape_len..];
            }
        } else {
            commitment_tapes.resize(queries.len(), Vec::new());
        }

        let level_siblings: Vec<usize> = self
            .config
            .tree_arity
            .iter()
            .rev()
            .map(|branch| branch.saturating_sub(1))
            .collect();
        let per_query_paths_bytes: usize = level_siblings
            .iter()
            .map(|siblings| siblings * self.config.digest_bytes)
            .sum();
        let total_path_bytes = per_query_paths_bytes * queries.len();
        if cursor.len() < total_path_bytes {
            return Err(anyhow!("proof truncated (path data)"));
        }

        let mut paths = Vec::with_capacity(queries.len());
        for _ in 0..queries.len() {
            let mut levels = Vec::with_capacity(level_siblings.len());
            for &count in &level_siblings {
                let mut siblings = Vec::with_capacity(count);
                for _ in 0..count {
                    let digest = cursor[..self.config.digest_bytes].to_vec();
                    cursor = &cursor[self.config.digest_bytes..];
                    siblings.push(digest);
                }
                levels.push(siblings);
            }
            paths.push(levels);
        }

        if !cursor.is_empty() {
            return Err(anyhow!("proof trailing data"));
        }

        let nb_evals = self.evaluation_domain_size();
        let mut root_opt: Option<Vec<u8>> = None;
        for i in 0..queries.len() {
            let query = &queries[i];
            let row_full = &opened_values[i];
            let mask_row = &mask_rows[i];
            let path = &paths[i];
            let tape = &commitment_tapes[i];

            let idx = self.find_index(query, nb_evals)?;
            if row_full.len() < self.config.nb_polys {
                return Err(anyhow!("witness length mismatch"));
            }
            if mask_row.len() != self.config.eta {
                return Err(anyhow!("mask length mismatch"));
            }

            let mut row = row_full[..self.config.nb_polys].to_vec();
            row.extend_from_slice(mask_row);
            let row_bytes = pack_field_values(&row);
            let leaf = hash_leaf(salt, idx, &row_bytes, tape, self.config.digest_bytes);
            let root = ShakeMerkleTree::verify_path(
                &self.config.tree_arity,
                self.config.digest_bytes,
                idx,
                leaf,
                path,
            )?;
            if let Some(prev) = &root_opt {
                if prev != &root {
                    return Err(anyhow!("authentication root mismatch"));
                }
            } else {
                root_opt = Some(root);
            }
        }

        let root = root_opt.ok_or_else(|| anyhow!("empty proof"))?;
        let hash_mt = hash_merkle_root(&root, self.config.digest_bytes);
        let gamma = self.derive_gamma(&hash_mt);
        let keep = self.config.nb_queries;
        let mut reconstructed = Vec::with_capacity(self.config.eta);
        for (j, high) in eps_high.iter().enumerate() {
            let mut relations = Vec::with_capacity(queries.len());
            for (i, query) in queries.iter().enumerate() {
                let row_full = &opened_values[i];
                let witness = &row_full[..self.config.nb_polys];
                let mask_row = &mask_rows[i];
                let value = self.epsilon_value(j, &gamma[j], witness, mask_row);
                relations.push((*query, value));
            }
            let coeffs = self.restore_epsilon_poly(high, &relations)?;
            reconstructed.push(coeffs);
        }

        let mut eps_full_flat = Vec::with_capacity(self.config.eta * (self.config.degree + 1));
        for coeffs in &reconstructed {
            eps_full_flat.extend_from_slice(coeffs);
        }
        let eps_bytes_recomputed = pack_field_values(&eps_full_flat);
        let mut commitment = Vec::new();
        commitment.extend_from_slice(&hash_mt);
        commitment.extend_from_slice(&eps_bytes_recomputed);

        let mut eps_high_check_flat =
            Vec::with_capacity(self.config.eta * (self.config.degree + 1 - keep));
        for coeffs in &reconstructed {
            eps_high_check_flat.extend_from_slice(&coeffs[keep..]);
        }
        let eps_high_bytes_recomputed = pack_field_values(&eps_high_check_flat);
        if eps_high_bytes_recomputed != eps_high_segment {
            return Err(anyhow!("epsilon serialization mismatch"));
        }
        Ok(commitment)
    }

    fn find_index(&self, query: &BaseField, nb_evals: usize) -> Result<usize> {
        if nb_evals == 0 {
            return Err(anyhow!("empty evaluation domain"));
        }
        let bytes = field_to_bytes(query);
        let mut raw_bytes = [0u8; 8];
        raw_bytes.copy_from_slice(&bytes[..8]);
        let raw = u64::from_le_bytes(raw_bytes);

        let idx = raw.wrapping_sub(1);
        let idx_u64 = idx;
        let nb = nb_evals as u64;

        // Constant-time masks: `is_zero_mask` == 1 when `raw == 0`, else 0.
        let is_zero_mask = (((raw | raw.wrapping_neg()) >> 63) ^ 1) & 1;
        let nonzero_mask = 1 ^ is_zero_mask;

        // `within_mask` == 1 when `idx < nb`, else 0.
        let within_mask = {
            let diff = nb.wrapping_sub(idx_u64.wrapping_add(1));
            ((diff >> 63) ^ 1) & 1
        };

        let valid_mask = nonzero_mask & within_mask;
        if valid_mask == 0 {
            return Err(anyhow!("query outside evaluation domain"));
        }

        Ok(idx_u64 as usize)
    }

    fn epsilon_value(
        &self,
        j: usize,
        gamma_row: &[BaseField],
        witness: &[BaseField],
        mask_row: &[BaseField],
    ) -> BaseField {
        let mut value = BaseField::from(0u64);
        for (coef, share) in gamma_row.iter().zip(witness.iter()) {
            value += *coef * *share;
        }
        value + mask_row[j]
    }

    fn restore_epsilon_poly(
        &self,
        high: &[BaseField],
        relations: &[(BaseField, BaseField)],
    ) -> Result<Vec<BaseField>> {
        let rels: Vec<(BaseField, Vec<BaseField>)> = relations
            .iter()
            .map(|(point, value)| (*value, vec![*point]))
            .collect();
        Ok(super::polynomial::restore_from_relations(
            &rels,
            high,
            self.config.degree,
        ))
    }

    fn evaluation_domain_size(&self) -> usize {
        if self.config.nb_evals > 0 {
            self.config.nb_evals
        } else {
            let base = self.config.degree + self.config.eta + 1;
            base.next_power_of_two().max(1)
        }
    }

    fn evaluation_point(&self, idx: usize) -> BaseField {
        BaseField::from((idx + 1) as u64)
    }

    pub fn sample_query_points(
        &self,
        fs_domain: &str,
        statement_bytes: &[u8],
        commitment: &[u8],
        nb_queries: usize,
    ) -> Vec<BaseField> {
        let mut binding = Hasher::new();
        binding.update(fs_domain.as_bytes());
        binding.update(statement_bytes);
        binding.update(commitment);
        let binding_digest = binding.finalize();

        let domain = self.evaluation_domain_size();
        assert!(domain > 0, "DECS evaluation domain must be non-empty");

        let pow_mask = if self.config.pow_opening_bits == 0 {
            0
        } else {
            (1u64 << self.config.pow_opening_bits).saturating_sub(1)
        };

        let mut counter: u32 = 0;
        loop {
            let mut hasher = Hasher::new();
            hasher.update(b"decs/open");
            hasher.update(&counter.to_le_bytes());
            hasher.update(binding_digest.as_bytes());
            let mut xof = hasher.finalize_xof();

            let mut seen = HashSet::with_capacity(nb_queries);
            let mut indices = Vec::with_capacity(nb_queries);
            let mut tmp = [0u8; 8];
            for _ in 0..nb_queries {
                xof.fill(&mut tmp);
                let idx = (u64::from_le_bytes(tmp) as usize) % domain;
                if !seen.insert(idx) {
                    indices.clear();
                    break;
                }
                indices.push(idx);
            }

            if indices.len() != nb_queries {
                counter = counter.wrapping_add(1);
                continue;
            }

            if pow_mask != 0 {
                xof.fill(&mut tmp);
                let pow_val = u64::from_le_bytes(tmp) & pow_mask;
                if pow_val != 0 {
                    counter = counter.wrapping_add(1);
                    continue;
                }
            }

            return indices
                .into_iter()
                .map(|idx| self.evaluation_point(idx))
                .collect();
        }
    }

    pub fn get_random_opening(&self, binding: &[u8]) -> (Vec<BaseField>, Vec<u8>) {
        let mut counter: u32 = 0;
        loop {
            if let Some(columns) = self.sample_open_columns(binding, counter) {
                let queries = columns
                    .into_iter()
                    .map(|idx| self.evaluation_point(idx))
                    .collect();
                return (queries, counter.to_le_bytes().to_vec());
            }
            counter = counter.wrapping_add(1);
        }
    }

    pub fn recompute_random_opening(&self, aux: &[u8], binding: &[u8]) -> Result<Vec<BaseField>> {
        if aux.len() != std::mem::size_of::<u32>() {
            return Err(anyhow!("invalid DEC aux length"));
        }
        let counter = u32::from_le_bytes(
            aux.try_into()
                .map_err(|_| anyhow!("invalid DEC counter encoding"))?,
        );
        let columns = self
            .sample_open_columns(binding, counter)
            .ok_or_else(|| anyhow!("invalid DEC opening binding"))?;
        Ok(columns
            .into_iter()
            .map(|idx| self.evaluation_point(idx))
            .collect())
    }

    fn sample_open_columns(&self, binding: &[u8], counter: u32) -> Option<Vec<usize>> {
        let domain = self.evaluation_domain_size();
        if domain == 0 {
            return None;
        }
        let mut hasher = Hasher::new();
        hasher.update(b"decs/random_opening");
        hasher.update(binding);
        hasher.update(&counter.to_le_bytes());
        let mut reader = hasher.finalize_xof();

        let mut tmp = [0u8; 8];
        let mut seen = HashSet::with_capacity(self.config.nb_queries);
        let mut columns = Vec::with_capacity(self.config.nb_queries);
        for _ in 0..self.config.nb_queries {
            reader.fill(&mut tmp);
            let idx = (u64::from_le_bytes(tmp) as usize) % domain;
            if !seen.insert(idx) {
                return None;
            }
            columns.push(idx);
        }

        if self.config.pow_opening_bits > 0 {
            reader.fill(&mut tmp);
            let mask = if self.config.pow_opening_bits >= 64 {
                u64::MAX
            } else {
                (1u64 << self.config.pow_opening_bits) - 1
            };
            if (u64::from_le_bytes(tmp) & mask) != 0 {
                return None;
            }
        }

        Some(columns)
    }
}

pub(crate) fn packed_field_bytes(count: usize) -> usize {
    let bit_len = BaseField::MODULUS_BIT_SIZE as usize;
    (bit_len * count).div_ceil(8)
}

pub(crate) fn pack_field_values(values: &[BaseField]) -> Vec<u8> {
    let bit_len = BaseField::MODULUS_BIT_SIZE as usize;
    let mut bytes = vec![0u8; packed_field_bytes(values.len())];
    for (idx, value) in values.iter().enumerate() {
        let bigint = (*value).into_bigint();
        let repr = bigint.to_bytes_le();
        for bit in 0..bit_len {
            let byte_idx = bit / 8;
            let bit_idx = bit % 8;
            let source = if byte_idx < repr.len() {
                repr[byte_idx]
            } else {
                0
            };
            let bit_val = (source >> bit_idx) & 1;
            let out_index = idx * bit_len + bit;
            bytes[out_index / 8] |= bit_val << (out_index % 8);
        }
    }
    bytes
}

pub(crate) fn unpack_field_values(bytes: &[u8], count: usize) -> Result<Vec<BaseField>> {
    let bit_len = BaseField::MODULUS_BIT_SIZE as usize;
    let total_bits = bit_len * count;
    if bytes.len() * 8 < total_bits {
        bail!("insufficient bits to decode field elements");
    }
    let mut values = Vec::with_capacity(count);
    for idx in 0..count {
        let start_bit = idx * bit_len;
        let mut elem_bytes = [0u8; 32];
        for bit in 0..bit_len {
            let global_bit = start_bit + bit;
            let byte = bytes[global_bit / 8];
            let bit_val = (byte >> (global_bit % 8)) & 1;
            elem_bytes[bit / 8] |= bit_val << (bit % 8);
        }
        values.push(BaseField::from_le_bytes_mod_order(&elem_bytes));
    }
    Ok(values)
}

fn sample_field_from_reader(reader: &mut Shake128Reader) -> BaseField {
    let mut bytes = [0u8; 32];
    reader.read(&mut bytes);
    BaseField::from_le_bytes_mod_order(&bytes)
}

fn derive_commitment_tape(salt: &[u8], index: usize, digest_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(b"decs/tape");
    hasher.update(salt);
    hasher.update(&(index as u64).to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; digest_len];
    reader.read(&mut out);
    out
}

fn hash_leaf(
    salt: &[u8],
    index: usize,
    row_bytes: &[u8],
    tape: &[u8],
    digest_len: usize,
) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(salt);
    let idx_bytes = [(index & 0xFF) as u8, ((index >> 8) & 0xFF) as u8];
    hasher.update(&idx_bytes);
    hasher.update(row_bytes);
    if !tape.is_empty() {
        hasher.update(tape);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; digest_len];
    reader.read(&mut out);
    out
}

fn hash_children(children: &[Vec<u8>], digest_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    for child in children {
        hasher.update(child);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; digest_len];
    reader.read(&mut out);
    out
}

fn hash_merkle_root(root: &[u8], digest_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(&[1u8]);
    hasher.update(root);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; digest_len];
    reader.read(&mut out);
    out
}

fn null_digest(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{field::BaseField, smallwood::rng::SmallwoodSeeder};

    fn simple_config() -> DecsCommitment {
        DecsCommitment::new(DecsConfig {
            nb_polys: 1,
            degree: 0,
            eta: 0,
            nb_queries: 0,
            nb_evals: 4,
            format_challenge: DecsChallengeFormat::Uniform,
            pow_opening_bits: 0,
            use_commitment_tapes: false,
            digest_bytes: 32,
            salt_bytes: 16,
            tree_arity: vec![2, 2],
            tree_truncation: None,
        })
    }

    fn richer_config(format: DecsChallengeFormat, use_tapes: bool) -> DecsCommitment {
        DecsCommitment::new(DecsConfig {
            nb_polys: 2,
            degree: 2,
            eta: 1,
            nb_queries: 1,
            nb_evals: 4,
            format_challenge: format,
            pow_opening_bits: 0,
            use_commitment_tapes: use_tapes,
            digest_bytes: 16,
            salt_bytes: 8,
            tree_arity: vec![2, 2],
            tree_truncation: None,
        })
    }

    #[test]
    fn find_index_accepts_domain_points() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = simple_config();
        for raw in 1..=4 {
            let query = BaseField::from(raw);
            let idx = commitment.find_index(&query, 4)?;
            assert_eq!(idx, (raw - 1) as usize);
        }
        Ok(())
    }

    #[test]
    fn find_index_rejects_out_of_range() {
        let commitment = simple_config();
        let zero = BaseField::from(0u64);
        assert!(commitment.find_index(&zero, 4).is_err());

        let too_large = BaseField::from(5u64);
        assert!(commitment.find_index(&too_large, 4).is_err());
    }

    #[test]
    fn commit_open_and_recompute_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let decs = richer_config(DecsChallengeFormat::Uniform, true);
        let seeder = SmallwoodSeeder::new("decs/test", b"stmt");
        let round = seeder.round(0);
        let salt = round.salt(decs.config.salt_bytes);
        let polynomials = vec![
            vec![
                BaseField::from(1u64),
                BaseField::from(2u64),
                BaseField::from(3u64),
            ],
            vec![
                BaseField::from(4u64),
                BaseField::from(5u64),
                BaseField::from(6u64),
            ],
        ];

        let (commitment, state) = decs.commit(&salt, &polynomials, Some(&round))?;
        let queries = decs.sample_query_points("decs/test", b"stmt", &commitment, 1);
        let (opened, proof) = decs.open(&state, &queries)?;
        let recomputed = decs.recompute_commitment(&salt, &queries, &opened, &proof)?;
        assert_eq!(recomputed, commitment);

        let binding = b"binding";
        let (rand_queries, aux) = decs.get_random_opening(binding);
        let recomputed_queries = decs.recompute_random_opening(&aux, binding)?;
        assert_eq!(rand_queries, recomputed_queries);
        assert!(decs.recompute_random_opening(&aux[..3], binding).is_err());
        Ok(())
    }

    #[test]
    fn commit_input_validation_errors() {
        let decs = richer_config(DecsChallengeFormat::Uniform, false);
        let seeder = SmallwoodSeeder::new("decs/test", b"stmt");
        let round = seeder.round(0);
        let salt = round.salt(decs.config.salt_bytes);
        let poly = vec![vec![BaseField::from(1u64), BaseField::from(2u64)]];

        assert!(decs.commit(&salt[..2], &poly, Some(&round)).is_err());
        assert!(decs.commit(&salt, &poly, Some(&round)).is_err()); // wrong poly count

        let over_degree = vec![
            vec![
                BaseField::from(1u64),
                BaseField::from(2u64),
                BaseField::from(3u64),
                BaseField::from(4u64),
            ],
            vec![BaseField::from(5u64)],
        ];
        assert!(decs.commit(&salt, &over_degree, Some(&round)).is_err());

        let valid = vec![
            vec![
                BaseField::from(1u64),
                BaseField::from(2u64),
                BaseField::from(3u64),
            ],
            vec![
                BaseField::from(4u64),
                BaseField::from(5u64),
                BaseField::from(6u64),
            ],
        ];
        assert!(decs.commit(&salt, &valid, None).is_err());
    }

    #[test]
    fn recompute_commitment_validation_errors() -> Result<(), Box<dyn std::error::Error>> {
        let decs = richer_config(DecsChallengeFormat::Uniform, false);
        let seeder = SmallwoodSeeder::new("decs/test", b"stmt");
        let round = seeder.round(0);
        let salt = round.salt(decs.config.salt_bytes);
        let polynomials = vec![
            vec![
                BaseField::from(1u64),
                BaseField::from(2u64),
                BaseField::from(3u64),
            ],
            vec![
                BaseField::from(4u64),
                BaseField::from(5u64),
                BaseField::from(6u64),
            ],
        ];
        let (commitment, state) = decs.commit(&salt, &polynomials, Some(&round))?;
        let queries = decs.sample_query_points("decs/test", b"stmt", &commitment, 1);
        let (opened, proof) = decs.open(&state, &queries)?;

        assert!(
            decs.recompute_commitment(&salt, &queries, &[], &proof)
                .is_err()
        );
        assert!(
            decs.recompute_commitment(&salt[..2], &queries, &opened, &proof)
                .is_err()
        );
        assert!(
            decs.recompute_commitment(&salt, &queries, &opened, &[])
                .is_err()
        );

        let mut with_trailing = proof.clone();
        with_trailing.push(0xFF);
        assert!(
            decs.recompute_commitment(&salt, &queries, &opened, &with_trailing)
                .is_err()
        );

        let mut bad_opened = opened.clone();
        bad_opened[0].pop();
        assert!(
            decs.recompute_commitment(&salt, &queries, &bad_opened, &proof)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn gamma_pack_and_random_opening_helpers_cover_variants()
    -> Result<(), Box<dyn std::error::Error>> {
        let seed = b"seed";
        for format in [
            DecsChallengeFormat::Uniform,
            DecsChallengeFormat::Powers,
            DecsChallengeFormat::Hybrid,
        ] {
            let decs = richer_config(format, false);
            let gamma = decs.derive_gamma(seed);
            assert_eq!(gamma.len(), decs.config.eta);
            assert!(gamma.iter().all(|row| row.len() == decs.config.nb_polys));
        }

        let values = vec![BaseField::from(7u64), BaseField::from(8u64)];
        let packed = pack_field_values(&values);
        let unpacked = unpack_field_values(&packed, values.len())?;
        assert_eq!(values, unpacked);
        assert!(unpack_field_values(&packed[..1], values.len()).is_err());

        let decs = DecsCommitment::new(DecsConfig {
            nb_polys: 1,
            degree: 1,
            eta: 0,
            nb_queries: 5, // impossible to sample unique columns in a domain of 4
            nb_evals: 4,
            format_challenge: DecsChallengeFormat::Uniform,
            pow_opening_bits: 0,
            use_commitment_tapes: false,
            digest_bytes: 16,
            salt_bytes: 8,
            tree_arity: vec![2, 2],
            tree_truncation: None,
        });
        assert!(decs.sample_open_columns(b"binding", 0).is_none());
        Ok(())
    }

    #[test]
    fn shake_merkle_tree_helpers_validate_paths() -> Result<(), Box<dyn std::error::Error>> {
        let digest_len = 8;
        let leaves = vec![
            vec![1u8; digest_len],
            vec![2u8; digest_len],
            vec![3u8; digest_len],
        ];
        let tree = ShakeMerkleTree::from_leaves(vec![2, 2], None, digest_len, 3, leaves);
        let root = tree.root().to_vec();
        for index in 0..3usize {
            let path = tree.authentication_path(index);
            let leaf = tree.levels.last().expect("leaf level exists")[index].clone();
            let reconstructed =
                ShakeMerkleTree::verify_path(&[2, 2], digest_len, index, leaf, &path)?;
            assert_eq!(reconstructed, root);
        }
        assert!(
            ShakeMerkleTree::verify_path(&[2], digest_len, 0, vec![0; digest_len], &[]).is_err()
        );
        assert!(
            ShakeMerkleTree::verify_path(&[2, 2], digest_len, 0, vec![0; digest_len], &[vec![]])
                .is_err()
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ShakeMerkleTree {
    arity: Vec<usize>,
    digest_len: usize,
    leaf_count: usize,
    levels: Vec<Vec<Vec<u8>>>,
}

impl ShakeMerkleTree {
    fn from_leaves(
        arity: Vec<usize>,
        truncation: Option<usize>,
        digest_len: usize,
        leaf_count: usize,
        mut leaves: Vec<Vec<u8>>,
    ) -> Self {
        if let Some(trunc) = truncation {
            assert_eq!(trunc, 0, "truncated merkle trees not yet supported");
        }
        if leaves.is_empty() {
            leaves.push(null_digest(digest_len));
        }
        let mut current = leaves;
        let mut levels = Vec::new();
        levels.push(current.clone());
        for &branch in arity.iter().rev() {
            assert!(branch != 0, "merkle arity must be non-zero");
            let remainder = current.len() % branch;
            if remainder != 0 {
                let padding = branch - remainder;
                for _ in 0..padding {
                    current.push(null_digest(digest_len));
                }
            }
            let mut next = Vec::with_capacity(current.len() / branch);
            for chunk in current.chunks(branch) {
                let mut children = Vec::with_capacity(branch);
                children.extend_from_slice(chunk);
                if children.len() < branch {
                    children.resize(branch, null_digest(digest_len));
                }
                next.push(hash_children(&children, digest_len));
            }
            levels.push(next.clone());
            current = next;
        }
        levels.reverse();
        Self {
            arity,
            digest_len,
            leaf_count,
            levels,
        }
    }

    fn root(&self) -> &[u8] {
        &self.levels[0][0]
    }

    fn authentication_path(&self, mut index: usize) -> Vec<Vec<Vec<u8>>> {
        assert!(index < self.leaf_count, "index outside leaf domain");
        let mut path = Vec::with_capacity(self.arity.len());
        let depth = self.levels.len();
        for (level_offset, &branch) in self.arity.iter().rev().enumerate() {
            let nodes = &self.levels[depth - 1 - level_offset];
            let group_start = (index / branch) * branch;
            let idx_mod = index % branch;
            let mut siblings = Vec::with_capacity(branch.saturating_sub(1));
            for offset in 0..branch {
                if offset == idx_mod {
                    continue;
                }
                let node_idx = group_start + offset;
                if node_idx < nodes.len() {
                    siblings.push(nodes[node_idx].clone());
                } else {
                    siblings.push(null_digest(self.digest_len));
                }
            }
            path.push(siblings);
            index /= branch;
        }
        path
    }

    fn verify_path(
        arity: &[usize],
        digest_len: usize,
        mut index: usize,
        mut current: Vec<u8>,
        path: &[Vec<Vec<u8>>],
    ) -> Result<Vec<u8>> {
        if path.len() != arity.len() {
            return Err(anyhow!("authentication path arity mismatch"));
        }
        for (siblings, &branch) in path.iter().zip(arity.iter().rev()) {
            if siblings.len() + 1 != branch {
                return Err(anyhow!("authentication path sibling count mismatch"));
            }
            let idx_mod = index % branch;
            let mut children = Vec::with_capacity(branch);
            let mut sib_iter = siblings.iter();
            for pos in 0..branch {
                if pos == idx_mod {
                    children.push(current.clone());
                } else {
                    let digest = sib_iter
                        .next()
                        .cloned()
                        .unwrap_or_else(|| null_digest(digest_len));
                    children.push(digest);
                }
            }
            current = hash_children(&children, digest_len);
            index /= branch;
        }
        Ok(current)
    }
}
