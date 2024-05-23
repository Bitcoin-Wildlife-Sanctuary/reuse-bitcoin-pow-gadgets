use crate::structures::hash::BlockHashGadget;
use crate::structures::merkle_hash::MerkleHashGadget;
use crate::structures::time::TimeGadget;
use crate::structures::version::VersionGadget;
use bitcoin::block::Header;
pub use bitvm::treepp::*;

pub struct HeaderGadget;

impl HeaderGadget {
    pub fn from_constant(block: &Header) -> Script {
        script! {
            { VersionGadget::from_constant(&block.version) }
            { BlockHashGadget::from_constant(&block.prev_blockhash) }
            { MerkleHashGadget::from_constant(&block.merkle_root) }
            { TimeGadget::from_constant(block.time) }
        }
    }
}
