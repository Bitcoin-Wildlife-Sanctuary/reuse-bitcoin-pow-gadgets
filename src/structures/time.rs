use bitcoin::absolute::Time;
use bitcoin::opcodes::all::OP_PUSHBYTES_4;
use bitvm::treepp::*;
use covenants_gadgets::utils::pseudo::OP_CAT4;

pub struct TimeGadget;

impl TimeGadget {
    pub fn from_constant(v: u32) -> Script {
        Script::from_bytes(vec![
            OP_PUSHBYTES_4.to_u8(),
            (v & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            ((v >> 16) & 0xff) as u8,
            ((v >> 24) & 0xff) as u8,
        ])
    }

    pub fn from_bitvm_u32() -> Script {
        // stack: MSB, xx, xx, LSB
        script! {
            OP_SWAP OP_2SWAP OP_SWAP
            OP_CAT4
        }
    }
}
