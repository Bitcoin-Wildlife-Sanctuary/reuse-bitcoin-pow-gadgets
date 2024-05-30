use crate::spv::TxInclusionProof;
use crate::treepp::*;
use crate::utils::limb_to_be_bits_toaltstack;
use bitcoin::hashes::Hash;

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
    ///     leaf, which is a txid
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
    use crate::spv::{TxInclusionProof, TxInclusionProofGadget};
    use crate::treepp::*;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_PUSHBYTES_32, OP_RETURN};
    use bitcoin::transaction::Version;
    use bitcoin::{Address, Amount, Block, Network, ScriptBuf, Transaction, Txid, WitnessProgram};
    use covenants_gadgets::utils::pseudo::{OP_CAT3, OP_CAT6};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::io::Read;

    #[test]
    fn test_spv() {
        let mut fs = std::fs::File::open("./src/spv/block_845797").unwrap();
        let mut bytes = vec![];
        fs.read_to_end(&mut bytes).unwrap();
        drop(fs);

        let encoded_block = hex::decode(&bytes).unwrap();

        let block = Block::consensus_decode(&mut encoded_block.as_slice()).unwrap();

        let computed_merkle_root = block.compute_merkle_root().unwrap();
        let expected_merkle_root = block.header.merkle_root;

        assert_eq!(computed_merkle_root, expected_merkle_root);

        let txids = block
            .txdata
            .iter()
            .map(|obj| obj.compute_txid())
            .collect::<Vec<Txid>>();

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

    #[test]
    fn test_actual_pow_spv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut pow_target = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_32.to_u8()];
        for _ in 0..32 {
            pow_target.push(prng.gen::<u8>());
        }

        let witness_program = WitnessProgram::p2wsh(&Script::from_bytes(pow_target));
        let script_pub_key = ScriptBuf::new_witness_program(&witness_program);

        let address = Address::from_script(&script_pub_key, Network::Bitcoin).unwrap();
        println!("Address on Bitcoin mainnet: {}", address);

        // tx hash: ac85e99fd914ccea8231f234541364ed6c2f4112905a6ed9c5b83479bf96008a
        let given_tx_bytes = hex::decode("0200000000010152c0ef39e255fbe3858282c59ed3a3747b71bc17632daf1029e5f86e19761f290000000000fdffffff02e803000000000000220020ba714b93459645d8c931819b567a75b304eb8a69a3f71432f6ad3be9780b639c0085070000000000160014ba3cde39438c04d6645b8c130d36bb0c7cbf2fbd0247304402203d99f19bb84c2c8b60f6495b0851ff68d42527600735a521efcffe9549bcaa4002203b6cf74de4a1d36a4eb3cf8dd3e61d359dedd708153862501f9b439ab1da49d9012102113f09ba5f346c77205630298995acbe1f95c77c882b2c0e1408277e5290db4f9de70c00").unwrap();
        let given_tx = Transaction::consensus_decode(&mut given_tx_bytes.as_slice()).unwrap();

        let mut fs = std::fs::File::open("./src/spv/block_845797").unwrap();
        let mut bytes = vec![];
        fs.read_to_end(&mut bytes).unwrap();
        drop(fs);

        let encoded_block = hex::decode(&bytes).unwrap();

        let block = Block::consensus_decode(&mut encoded_block.as_slice()).unwrap();

        let computed_merkle_root = block.compute_merkle_root().unwrap();
        let expected_merkle_root = block.header.merkle_root;

        assert_eq!(computed_merkle_root, expected_merkle_root);

        let txids = block
            .txdata
            .iter()
            .map(|obj| obj.compute_txid())
            .collect::<Vec<Txid>>();

        let mut tx_hash =
            hex::decode("ac85e99fd914ccea8231f234541364ed6c2f4112905a6ed9c5b83479bf96008a")
                .unwrap();
        tx_hash.reverse();

        let txid = Txid::from_slice(&tx_hash).unwrap();
        let idx = txids.iter().position(|&x| x == txid).unwrap();

        let spv = TxInclusionProof::construct_from_txids(&txids, idx);

        let witness = script! {
            { TxInclusionProofGadget::push_tx_inclusion_proof_as_hint(&spv) }
        };

        let script = script! {
            { covenants_gadgets::wizards::tx::Step1VersionGadget::from_constant(&Version::TWO) }
            { covenants_gadgets::wizards::tx::Step2InCounterGadget::from_constant(1) }
            { covenants_gadgets::wizards::tx::step3_input::TxInGadget::from_constant(&given_tx.input[0]) }
            { covenants_gadgets::wizards::tx::Step4OutCounterGadget::from_constant(2) }
            { covenants_gadgets::wizards::tx::step5_output::Step1AmountGadget::from_constant(&Amount::from_sat(1000)) }
            { covenants_gadgets::wizards::tx::step5_output::Step2ScriptPubKeyGadget::from_constant(&script_pub_key) }
            { covenants_gadgets::wizards::tx::Step5OutputGadget::from_constant(&given_tx.output[1]) }
            { covenants_gadgets::wizards::tx::Step6LockTimeGadget::from_constant_absolute(&given_tx.lock_time) }
            OP_CAT6
            OP_CAT3

            OP_SHA256 OP_SHA256

            { TxInclusionProofGadget::compute_merkle_root() }
            { block.header.merkle_root.as_byte_array().to_vec() }
            OP_EQUAL
        };
        let exec_result = execute_script_with_witness(script, convert_to_witness(witness).unwrap());
        assert!(exec_result.success);
    }
}
