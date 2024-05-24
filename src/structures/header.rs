use crate::structures::compact_target::CompactTargetGadget;
use crate::structures::hash::BlockHashGadget;
use crate::structures::merkle_hash::MerkleHashGadget;
use crate::structures::nonce::NonceGadget;
use crate::structures::time::TimeGadget;
use crate::structures::version::VersionGadget;
use bitcoin::block::Header;
pub use bitvm::treepp::*;
use covenants_gadgets::utils::pseudo::OP_CAT6;

pub struct HeaderGadget;

impl HeaderGadget {
    pub fn from_constant(block: &Header) -> Script {
        script! {
            { VersionGadget::from_constant(&block.version) }
            { BlockHashGadget::from_constant(&block.prev_blockhash) }
            { MerkleHashGadget::from_constant(&block.merkle_root) }
            { TimeGadget::from_constant(block.time) }
            { CompactTargetGadget::from_constant(&block.bits) }
            { NonceGadget::from_constant(block.nonce) }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_CAT6
            { BlockHashGadget::compute_hash_from_stack() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::structures::header::HeaderGadget;
    use bitcoin::block::Header;
    use bitcoin::consensus::Decodable;
    use bitcoin::secp256k1::ThirtyTwoByteHash;
    use bitvm::treepp::*;
    use covenants_gadgets::utils::pseudo::OP_CAT6;

    #[test]
    fn test_header() {
        let hex = hex::decode("00c0232b218e0a0b7edc4abb2087cc813b7d867400c5b9c60b62000000000000000000007ecc6032126c1b6a17652495e28d7d973111764ace8a8219d67c0b00ff41ad299e424f66f05503172fe99011").unwrap();

        let header = Header::consensus_decode(&mut hex.as_slice()).unwrap();

        let script = script! {
            { HeaderGadget::from_constant(&header) }
            OP_CAT6
            { hex }
            OP_EQUALVERIFY

            { HeaderGadget::from_constant(&header) }
            { HeaderGadget::compute_hash_from_stack() }
            { header.block_hash().as_raw_hash().into_32().to_vec() }
            OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
