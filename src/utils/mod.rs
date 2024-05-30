use std::cmp::min;
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

/// Convert a limb (u31 at most) to bits.
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
fn limb_to_be_bits_common(num_bits: u32) -> Script {
    let min_i = min(22, num_bits - 1);
    script! {
        OP_TOALTSTACK

        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i  {
            { 2 << i }
        }
        // Then, we double powers of 2 to generate the 4-byte numbers
        for _ in min_i..num_bits - 1 {
            OP_DUP
            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK

        for _ in 0..num_bits - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 1
            OP_ELSE
                OP_NIP 0
            OP_ENDIF
            OP_TOALTSTACK
        }

        OP_2DUP OP_LESSTHANOREQUAL
        OP_IF
            OP_SWAP OP_SUB 1
        OP_ELSE
            OP_NIP 0
        OP_ENDIF
    }
}

/// Convert a limb (u31 at most) to bits, to altstack, lower bits out first.
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
pub fn limb_to_be_bits_toaltstack(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_be_bits_common(num_bits) }
            OP_TOALTSTACK
            OP_TOALTSTACK
        }
    } else {
        script! {
            OP_TOALTSTACK
        }
    }
}