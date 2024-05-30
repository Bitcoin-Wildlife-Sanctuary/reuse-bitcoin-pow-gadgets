use crate::treepp::*;
use bitcoin::BlockHash;

pub struct BlockHashGadget;

impl BlockHashGadget {
    pub fn from_constant(hash: &BlockHash) -> Script {
        script! {
            { AsRef::<[u8]>::as_ref(&hash).to_vec() }
        }
    }

    pub fn compute_hash_from_stack() -> Script {
        script! {
            OP_SHA256 OP_SHA256
        }
    }

    pub fn from_provided() -> Script {
        script! {
            OP_SIZE 32 OP_EQUALVERIFY
        }
    }

    /// Push the hint for checking the bit of security
    ///
    /// This is adapted from `bitcoin-circle-stark`, @victorkstarkware
    /// https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/blob/main/src/pow/bitcoin_script.rs
    ///
    pub fn push_bit_security_hint(hash: &BlockHash) -> Script {
        let bytes = AsRef::<[u8]>::as_ref(&hash).to_vec();

        let mut leading_zeros = 0usize;
        for i in 0..32 {
            if bytes[31 - i] == 0u8 {
                leading_zeros += 8;
            } else {
                leading_zeros += bytes[31 - i].leading_zeros() as usize;
                break;
            }
        }

        script! {
            { leading_zeros / 8 }
            { leading_zeros % 8 }
            if leading_zeros % 8 == 0 {
                { bytes[..31 - (leading_zeros / 8) + 1].to_vec() }
            } else {
                { bytes[..31 - (leading_zeros + 8 - 1) / 8 + 1].to_vec() }
                { bytes[31 - leading_zeros / 8] }
            }
        }
    }

    /// Get the bits of security for the hash, using a hint.
    ///
    /// hint:
    ///   leading zeros // 8 (must be non-negative and smaller or equal to 32)
    ///   leading zeros % 8 (must be non-negative and smaller or equal to 7)
    ///   prefix
    ///   msb
    ///
    /// This is adapted from `bitcoin-circle-stark`, @victorkstarkware
    /// https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/blob/main/src/pow/bitcoin_script.rs
    ///
    pub fn get_bit_security() -> Script {
        script! {
            // pull the leading_zeros / 8
            OP_DEPTH OP_1SUB OP_ROLL

            // check its format
            OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY // enforce that it is nonnegative
            OP_DUP 32 OP_LESSTHANOREQUAL OP_VERIFY // enforce that it is smaller or equal to 32

            // pull the leading_zeros % 8
            OP_DEPTH OP_1SUB OP_ROLL

            // check its format
            OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY // enforce that it is nonnegative
            OP_DUP 7 OP_LESSTHANOREQUAL OP_VERIFY // enforce that it is smaller or equal to 7

            // stack: h, leading_zeros / 8, leading_zeros % 8

            // compute the expected length, which is (32 - ceil(leading_zeros / 8))
            OP_OVER 32 OP_SWAP OP_SUB OP_TOALTSTACK
            OP_DUP OP_0NOTEQUAL
            OP_IF
                OP_FROMALTSTACK OP_1SUB OP_TOALTSTACK
            OP_ENDIF

            // stack: h, leading_zeros / 8, leading_zeros % 8
            // altstack: expected length

            // pull the prefix
            OP_DEPTH OP_1SUB OP_ROLL

            // check the prefix length
            OP_SIZE OP_FROMALTSTACK OP_EQUALVERIFY

            // stack: h, leading_zeros / 8, leading_zeros % 8, prefix
            // check if msb is needed
            OP_OVER OP_0NOTEQUAL
            OP_IF
                OP_DEPTH OP_1SUB OP_ROLL

                // check its size to be 1 (it would not be 2 because its most significant bit must be zero)
                // and it is not 0 because in that case, it would have more leading zeros
                //
                // note: it includes an assumption that the number of leading zeros provided needs be to somewhat exact,
                // but this is not a strict requirement.
                OP_SIZE 1 OP_EQUALVERIFY

                OP_DUP
                0 OP_EQUAL OP_IF
                    OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_ELSE
                    OP_DUP
                OP_ENDIF
                OP_TOALTSTACK

                OP_ROT

                // stack: h, leading_zeros / 8, prefix, msb, leading_zeros % 8
                // altstack: msb (forcing 0 to be "0")

                OP_DUP OP_TOALTSTACK

                8 OP_SWAP OP_SUB

                OP_DUP
                4 OP_GREATERTHANOREQUAL OP_IF
                    4 OP_SUB
                    16
                OP_ELSE
                    1
                OP_ENDIF

                OP_SWAP

                // stack: h, leading_zeros / 8, prefix, msb, (2^4 or 2^0), leading_zeros % 4
                // altstack: msb, leading_zeros % 8

                OP_DUP
                2 OP_GREATERTHANOREQUAL OP_IF
                    2 OP_SUB
                    OP_SWAP OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP
                OP_ENDIF

                // stack: h, leading_zeros / 8, prefix, msb, (2^6, 2^4, 2^2 or 2^0), leading_zeros % 2
                // altstack: msb, leading_zeros % 8

                OP_IF
                    OP_DUP OP_ADD
                OP_ENDIF

                // stack: h, leading_zeros / 8, prefix, msb, 1 << (8 - leading_zeros % 8)
                // altstack: msb, leading_zeros % 8

                OP_LESSTHAN OP_VERIFY

                // stack: h, leading_zeros / 8, prefix
                // altstack: msb, leading_zeros % 8
            OP_ELSE
                OP_SWAP OP_TOALTSTACK
                OP_PUSHBYTES_0 OP_TOALTSTACK

                // stack: h, leading_zeros / 8, prefix
                // altstack: msb, leading_zeros % 8
            OP_ENDIF

            // generate the suffix
            OP_OVER
            // stack: h, leading_zeros / 8, prefix, leading_zeros / 8
            // altstack: msb, leading_zeros % 8

            OP_DUP
            16 OP_GREATERTHANOREQUAL OP_IF
                16 OP_SUB
                OP_PUSHBYTES_4 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
                OP_DUP OP_CAT
                OP_DUP OP_CAT
            OP_ELSE
                OP_PUSHBYTES_0
            OP_ENDIF

            OP_SWAP
            // stack: h, leading_zeros / 8, prefix, suffix (pending), (leading_zeros / 8) % 16
            // altstack: msb, leading_zeros % 8

            OP_DUP
            8 OP_GREATERTHANOREQUAL OP_IF
                8 OP_SUB

                OP_SWAP

                OP_PUSHBYTES_4 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
                OP_DUP OP_CAT

                OP_CAT OP_SWAP
            OP_ENDIF
            // stack: h, leading_zeros / 8, prefix, suffix (pending), (leading_zeros / 8) % 8
            // altstack: msb, leading_zeros % 8

            OP_DUP
            4 OP_GREATERTHANOREQUAL OP_IF
                4 OP_SUB

                OP_SWAP

                OP_PUSHBYTES_4 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0

                OP_CAT OP_SWAP
            OP_ENDIF
            // stack: h, leading_zeros / 8, prefix, suffix (pending), (leading_zeros / 8) % 4
            // altstack: msb, leading_zeros % 8

            OP_DUP
            2 OP_GREATERTHANOREQUAL OP_IF
                2 OP_SUB

                OP_SWAP

                OP_PUSHBYTES_2 OP_PUSHBYTES_0 OP_PUSHBYTES_0

                OP_CAT OP_SWAP
            OP_ENDIF
            // stack: h, leading_zeros / 8, prefix, suffix (pending), (leading_zeros / 8) % 2
            // altstack: msb, leading_zeros % 8

            OP_IF
                OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_CAT
            OP_ENDIF
            // stack: h, leading_zeros / 8, prefix, suffix
            // altstack: msb, leading_zeros % 8

            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_ROT OP_CAT

            // stack: h, leading_zeros / 8, prefix, leading_zeros % 8, msb+suffix

            OP_ROT OP_SWAP OP_CAT

            // stack: h, leading_zeros / 8, leading_zeros % 8, hash

            OP_2SWAP OP_TOALTSTACK
            OP_EQUALVERIFY OP_FROMALTSTACK

            // stack: leading_zeros % 8, leading_zeros / 8

            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_ADD

            // stack: leading zeros
        }
    }
}

#[cfg(test)]
mod test {
    use crate::structures::hash::BlockHashGadget;
    use crate::treepp::*;
    use bitcoin::consensus::Decodable;
    use bitcoin::BlockHash;

    #[test]
    fn test_pow() {
        // 845531 - 845536
        let block_hashes = [
            "0000000000000000000092a858c5bda11ee6e7c75664062afa6e219f30dfe8b6",
            "00000000000000000000c09b63c50b9e6dd0117978a885c3f74210d39a66b840",
            "000000000000000000006d167abb2ed76ce380d89aca3fcb5d90c9b067f22d8f",
            "0000000000000000000168b11d44c565f297d656e72aded5da384ba27a64cca4",
            "00000000000000000002a8e9af6089d7a2dfd7fca36403f0c6f30e7b712758bc",
            "0000000000000000000136d8350de77dc1e0bce70737a9966224398f5a246121",
        ]
        .iter()
        .map(|x| {
            let mut bytes = hex::decode(x).unwrap();
            bytes.reverse();
            BlockHash::consensus_decode(&mut bytes.as_slice()).unwrap()
        })
        .collect::<Vec<BlockHash>>();

        let bits_security = [80, 80, 81, 79, 78, 79];

        let script = script! {
            for block_hash in block_hashes.iter() {
                { BlockHashGadget::push_bit_security_hint(block_hash) }
            }
            for (block_hash, bit_security) in block_hashes.iter().zip(bits_security.iter()) {
                { BlockHashGadget::from_constant(block_hash) }
                { BlockHashGadget::get_bit_security() }
                { *bit_security }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        println!("{:8}", exec_result.final_stack);
        println!("{:?}", exec_result.error);
        assert!(exec_result.success);
    }
}
