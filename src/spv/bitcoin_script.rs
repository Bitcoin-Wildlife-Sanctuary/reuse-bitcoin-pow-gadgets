use bitcoin::hashes::Hash;
use crate::treepp::*;
use crate::spv::TxInclusionProof;
use crate::utils::limb_to_be_bits_toaltstack;

pub struct TxInclusionProofGadget;

impl TxInclusionProofGadget {
    pub fn push_tx_inclusion_proof_as_hint(proof: &TxInclusionProof) -> Script {
        script! {
            { proof.siblings.len() }
            { proof.idx }
            for sibling in proof.siblings.iter() {
                { sibling.as_byte_array().to_vec() }
            }
        }
    }

    /// Verify the inclusion proof.
    ///
    /// hint:
    ///     num of siblings
    ///     idx
    ///     [each sibling]
    ///
    /// input:
    ///     leaf hash
    ///
    ///
    /// output:
    ///     merkle root
    ///
    pub fn compute_merkle_root() -> Script {
        script! {
            // pull the number of siblings
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP 17 OP_LESSTHANOREQUAL OP_VERIFY

            // pull the idx
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DUP 131072 OP_LESSTHAN OP_VERIFY

            // bit decompose idx (to 17 bits, as there is no way to include more than 2^17 txs per block)
            { limb_to_be_bits_toaltstack(17) }

            // stack: leaf hash, number of siblings
            // alstack: <bits>

            // do 17 rounds
            for _ in 0..17 {
                OP_DUP OP_0NOTEQUAL OP_IF
                    OP_SWAP

                    // pull the sibling
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_SIZE 32 OP_EQUALVERIFY

                    // stack: number of siblings, leaf_hash, sibling

                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF

                    OP_CAT OP_SHA256 OP_SHA256

                    OP_SWAP OP_1SUB
                OP_ELSE
                    OP_FROMALTSTACK OP_DROP
                OP_ENDIF
            }

            // drop the number of siblings, which would be zero
            OP_DROP
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use bitcoin::{Block, Txid};
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;
    use crate::spv::{TxInclusionProof, TxInclusionProofGadget};
    use crate::treepp::*;

    #[test]
    fn test_spv() {
        let mut fs = std::fs::File::open("./src/spv/block_845531").unwrap();
        let mut bytes = vec![];
        fs.read_to_end(&mut bytes).unwrap();
        drop(fs);

        let encoded_block = hex::decode(&bytes).unwrap();

        let block = Block::consensus_decode(&mut encoded_block.as_slice()).unwrap();

        let computed_merkle_root = block.compute_merkle_root().unwrap();
        let expected_merkle_root = block.header.merkle_root;

        assert_eq!(computed_merkle_root, expected_merkle_root);

        let txids = block.txdata.iter().map(|obj| obj.compute_txid()).collect::<Vec<Txid>>();

        let spv = TxInclusionProof::construct_from_txids(&txids, 100);

        let script = script! {
            { TxInclusionProofGadget::push_tx_inclusion_proof_as_hint(&spv) }

            { block.txdata[100].compute_txid().as_byte_array().to_vec() }

            { TxInclusionProofGadget::compute_merkle_root() }
            { computed_merkle_root.as_byte_array().to_vec() }
            OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
