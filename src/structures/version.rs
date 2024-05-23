use bitcoin::block::Version;
use bitcoin::opcodes::all::OP_PUSHBYTES_4;
use bitvm::treepp::Script;

pub struct VersionGadget;

impl VersionGadget {
    pub fn from_constant(version: &Version) -> Script {
        let v = version.to_consensus() as u32;
        Script::from_bytes(vec![
            OP_PUSHBYTES_4.to_u8(),
            (v & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            ((v >> 16) & 0xff) as u8,
            ((v >> 24) & 0xff) as u8,
        ])
    }
}
