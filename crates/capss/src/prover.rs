use crate::{
    CapssContext, CapssProver, smallwood,
    types::{CapssSignature, CapssStatement},
};

#[derive(Clone, Debug)]
pub struct SmallwoodProver {
    context: CapssContext,
}

impl SmallwoodProver {
    pub fn new(context: CapssContext) -> Self {
        Self { context }
    }
}

impl CapssProver for SmallwoodProver {
    fn prove(&self, statement: &CapssStatement) -> anyhow::Result<CapssSignature> {
        let config = self.context.smallwood_config().clone();
        let proof = smallwood::prove(&config, statement)?;
        Ok(proof.into())
    }
}
