use crate::treepp::*;
use bitcoin::TxMerkleNode;
use covenants_gadgets::utils::pseudo::OP_CAT2;

pub struct MerkleHashGadget;

impl MerkleHashGadget {
    pub fn from_constant(tx_merkle_node: &TxMerkleNode) -> Script {
        script! {
            { AsRef::<[u8]>::as_ref(&tx_merkle_node).to_vec() }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_CAT2
            OP_SHA256 OP_SHA256
        }
    }
}
