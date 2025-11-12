use anyhow::Result;

use crate::{
    CapssContext, CapssVerifier, smallwood,
    types::{CapssSignature, CapssStatement},
};

#[derive(Clone, Debug)]
pub struct SmallwoodVerifier {
    context: CapssContext,
}

impl SmallwoodVerifier {
    pub fn new(context: CapssContext) -> Self {
        Self { context }
    }
}

impl CapssVerifier for SmallwoodVerifier {
    fn verify(&self, statement: &CapssStatement, signature: &CapssSignature) -> Result<()> {
        let config = self.context.smallwood_config();
        smallwood::verify(config, statement, signature)
    }
}
