use crate::treepp::*;
use crate::utils::push_u32;
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

    pub fn from_provided() -> Script {
        script! {
            OP_SIZE 4 OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod test {
    use crate::structures::time::TimeGadget;
    use crate::treepp::*;

    #[test]
    fn test_bitvm_u32() {
        let v = 0x12345678;

        let script = script! {
            { ((v >> 24) & 0xff) as u8 }
            { ((v >> 16) & 0xff) as u8 }
            { ((v >> 8) & 0xff) as u8 }
            { (v & 0xff) as u8 }
            { TimeGadget::from_bitvm_u32() }
            { TimeGadget::from_constant(v) }
            OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
