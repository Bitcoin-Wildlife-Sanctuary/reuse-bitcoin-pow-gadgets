use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::BlockHash;
use bitvm::treepp::*;

pub struct BlockHashGadget;

impl BlockHashGadget {
    pub fn from_constant(hash: &BlockHash) -> Script {
        script! {
            { hash.as_raw_hash().into_32().to_vec() }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_SHA256 OP_SHA256
        }
    }
}
