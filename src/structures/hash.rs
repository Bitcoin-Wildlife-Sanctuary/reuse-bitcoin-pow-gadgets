use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::BlockHash;
use bitvm::treepp::*;
use covenants_gadgets::utils::pseudo::OP_CAT6;

pub struct BlockHashGadget;

impl BlockHashGadget {
    pub fn from_constant(hash: &BlockHash) -> Script {
        script! {
            { hash.as_raw_hash().into_32().to_vec() }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_CAT6
            OP_SHA256 OP_SHA256
        }
    }
}
