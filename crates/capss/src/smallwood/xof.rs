use blake3::{Hasher, OutputReader};

/// Simple Blake3-XOF wrapper with domain separation helpers.
pub struct Blake3Xof {
    reader: OutputReader,
}

impl Blake3Xof {
    pub fn new(label: &[u8], data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(label);
        hasher.update(data);
        let reader = hasher.finalize_xof();
        Self { reader }
    }

    pub fn fill(&mut self, output: &mut [u8]) {
        self.reader.fill(output);
    }
}

#[cfg(test)]
mod tests {
    use super::Blake3Xof;

    #[test]
    fn deterministic() {
        let mut x1 = Blake3Xof::new(b"label", b"data");
        let mut x2 = Blake3Xof::new(b"label", b"data");
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        x1.fill(&mut out1);
        x2.fill(&mut out2);
        assert_eq!(out1, out2);
    }
}
