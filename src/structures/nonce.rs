use crate::treepp::*;
use crate::utils::push_u32;

pub struct NonceGadget;

impl NonceGadget {
    pub fn from_constant(v: u32) -> Script {
        push_u32(v)
    }

    pub fn from_provided() -> Script {
        script! {
            OP_SIZE 4 OP_EQUALVERIFY
        }
    }
}
