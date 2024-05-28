use crate::treepp::Script;
use crate::utils::push_u32;
use bitcoin::block::Version;

pub struct VersionGadget;

impl VersionGadget {
    pub fn from_constant(version: &Version) -> Script {
        let v = version.to_consensus() as u32;
        push_u32(v)
    }
}
