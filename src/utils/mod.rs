use crate::treepp::*;
use bitcoin::opcodes::all::OP_PUSHBYTES_4;

pub fn push_u32(v: u32) -> Script {
    Script::from_bytes(vec![
        OP_PUSHBYTES_4.to_u8(),
        (v & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
    ])
}
