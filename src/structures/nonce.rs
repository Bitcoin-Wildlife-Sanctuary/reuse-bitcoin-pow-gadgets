use crate::utils::push_u32;
use bitvm::treepp::*;

pub struct NonceGadget;

impl NonceGadget {
    pub fn from_constant(v: u32) -> Script {
        push_u32(v)
    }
}
