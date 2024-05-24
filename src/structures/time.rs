use crate::utils::push_u32;
use bitvm::treepp::*;
use covenants_gadgets::utils::pseudo::OP_CAT4;

pub struct TimeGadget;

impl TimeGadget {
    pub fn from_constant(v: u32) -> Script {
        push_u32(v)
    }

    pub fn from_bitvm_u32() -> Script {
        // stack: MSB, xx, xx, LSB
        script! {
            OP_SWAP OP_2SWAP OP_SWAP
            OP_CAT4
        }
    }
}

#[cfg(test)]
mod test {
    use crate::structures::time::TimeGadget;
    use bitvm::treepp::*;
    use bitvm::u32::u32_std::u32_push;

    #[test]
    fn test_bitvm_u32() {
        let v = 0x12345678;

        let script = script! {
            { u32_push(v) }
            { TimeGadget::from_bitvm_u32() }
            { TimeGadget::from_constant(v) }
            OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
