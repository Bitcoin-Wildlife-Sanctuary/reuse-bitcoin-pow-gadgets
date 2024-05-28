use crate::treepp::*;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::TxMerkleNode;
use covenants_gadgets::utils::pseudo::OP_CAT2;

pub struct MerkleHashGadget;

impl MerkleHashGadget {
    pub fn from_constant(tx_merkle_node: &TxMerkleNode) -> Script {
        script! {
            { tx_merkle_node.as_raw_hash().into_32().to_vec() }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_CAT2
            OP_SHA256 OP_SHA256
        }
    }
}
