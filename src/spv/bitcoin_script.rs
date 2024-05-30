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
    use crate::consensus_encode;
    use crate::spv::{TxInclusionProof, TxInclusionProofGadget};
    use crate::treepp::*;
    use bitcoin::block::Header;
    use bitcoin::consensus::{Decodable, Encodable};
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_PUSHBYTES_32, OP_RETURN};
    use bitcoin::opcodes::Ordinary::OP_GREATERTHANOREQUAL;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Address, Block, BlockHash, Network, ScriptBuf, Transaction, Txid, WitnessProgram,
    };
    use covenants_gadgets::utils::pseudo::{OP_CAT6, OP_HINT};
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

        let mut first_block_hash =
            hex::decode("00000000000000000001c29595560a2d6fb2dbf30d9f552c8549635acc8c9f42")
                .unwrap();
        first_block_hash.reverse();

        let second_block_header = {
            let bytes = hex::decode("00000028429f8ccc5a6349852c559f0df3dbb26f2d0a569595c2010000000000000000007ef4fd2b9a9520fba80a2d14f8b46d9878508489be73c03119555ac3b6c7673080a35866f055031778e193c2").unwrap();
            Header::consensus_decode(&mut bytes.as_slice()).unwrap()
        };
        let mut second_block_hash =
            hex::decode("00000000000000000002324267dfbf713e5ba54f4aa9a96c684f7e27a3178e6a")
                .unwrap();
        second_block_hash.reverse();

        let third_block_header = {
            let bytes = hex::decode("000000266a8e17a3277e4f686ca9a94a4fa55b3e71bfdf67423202000000000000000000e61ba13c3fdd44bb5d0460be891f86c083ada120103eb771bc8db4996368e0ceffa85866f055031765f48dc8").unwrap();
            Header::consensus_decode(&mut bytes.as_slice()).unwrap()
        };
        let mut third_block_hash =
            hex::decode("0000000000000000000287ff7f6590fe5e911d8462efa83f18e4b1e3663df1b0")
                .unwrap();
        third_block_hash.reverse();

        let fourth_block_header = {
            let bytes = hex::decode("00000020b0f13d66e3b1e4183fa8ef62841d915efe90657fff8702000000000000000000ad9bfd71cfa12ed9b56757bd9778bf253070c1c91e6b4558f34ac0fb8fb85cda41a95866f0550317af8e9959").unwrap();
            Header::consensus_decode(&mut bytes.as_slice()).unwrap()
        };
        let mut fourth_block_hash =
            hex::decode("000000000000000000004ecf6506bead9a6bd3f716e36d906a48934d3a8db8df")
                .unwrap();
        fourth_block_hash.reverse();

        let fifth_block_header = {
            let bytes = hex::decode("00000520dfb88d3a4d93486a906de316f7d36b9aadbe0665cf4e0000000000000000000051e75174de68a0846322c6807468a8d2e9d3ea3c06cc590d4e4bd4632acd1fbe70ae5866f0550317671357d4").unwrap();
            Header::consensus_decode(&mut bytes.as_slice()).unwrap()
        };
        let mut fifth_block_hash =
            hex::decode("00000000000000000001bc3ab109e0ae0854cac1415690dd5b171a83c3d5190f")
                .unwrap();
        fifth_block_hash.reverse();

        let sixth_block_header = {
            let bytes = hex::decode("0060cb220f19d5c3831a175bdd905641c1ca5408aee009b13abc01000000000000000000acc4cdc5bd0a3a3fe71f2c73d6365bd94ae7e6160aacdb8d1c0dd4a9b88edb2d5cb05866f05503172b8d180d").unwrap();
            Header::consensus_decode(&mut bytes.as_slice()).unwrap()
        };
        let mut sixth_block_hash =
            hex::decode("0000000000000000000166482add4467b0dda7617551c8cc5f8ff987451e2575")
                .unwrap();
        sixth_block_hash.reverse();

        let txid = Txid::from_slice(&tx_hash).unwrap();
        let idx = txids.iter().position(|&x| x == txid).unwrap();

        let spv = TxInclusionProof::construct_from_txids(&txids, idx);

        let witness = script! {
            // reconstructing the tx
            { consensus_encode!(given_tx.input[0].previous_output) }
            { consensus_encode!(given_tx.input[0].sequence) }
            { consensus_encode!(given_tx.output[0].value) }
            { consensus_encode!(given_tx.output[1].value) }
            { given_tx.output[1].script_pubkey.as_bytes().to_vec() }
            { consensus_encode!(given_tx.lock_time) }

            // spv proof
            { TxInclusionProofGadget::push_tx_inclusion_proof_as_hint(&spv) }

            // tx merkle root
            { block.header.merkle_root.as_byte_array().to_vec() }

            // 1st block header
            { consensus_encode!(block.header.version) }
            { consensus_encode!(block.header.prev_blockhash) }
            { consensus_encode!(block.header.time) }
            { consensus_encode!(block.header.bits) }
            { consensus_encode!(block.header.nonce) }

            // 1st block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&first_block_hash).unwrap()) }

            // 2st block header
            { consensus_encode!(second_block_header.version) }
            { consensus_encode!(second_block_header.merkle_root) }
            { consensus_encode!(second_block_header.time) }
            { consensus_encode!(second_block_header.bits) }
            { consensus_encode!(second_block_header.nonce) }

            // 2nd block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&second_block_hash).unwrap()) }

            // 3rd block header
            { consensus_encode!(third_block_header.version) }
            { consensus_encode!(third_block_header.merkle_root) }
            { consensus_encode!(third_block_header.time) }
            { consensus_encode!(third_block_header.bits) }
            { consensus_encode!(third_block_header.nonce) }

            // 3rd block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&third_block_hash).unwrap()) }

            // 4th block header
            { consensus_encode!(fourth_block_header.version) }
            { consensus_encode!(fourth_block_header.merkle_root) }
            { consensus_encode!(fourth_block_header.time) }
            { consensus_encode!(fourth_block_header.bits) }
            { consensus_encode!(fourth_block_header.nonce) }

            // 4th block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&fourth_block_hash).unwrap()) }

            // 5th block header
            { consensus_encode!(fifth_block_header.version) }
            { consensus_encode!(fifth_block_header.merkle_root) }
            { consensus_encode!(fifth_block_header.time) }
            { consensus_encode!(fifth_block_header.bits) }
            { consensus_encode!(fifth_block_header.nonce) }

            // 5th block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&fifth_block_hash).unwrap()) }

            // 6th block header
            { consensus_encode!(sixth_block_header.version) }
            { consensus_encode!(sixth_block_header.merkle_root) }
            { consensus_encode!(sixth_block_header.time) }
            { consensus_encode!(sixth_block_header.bits) }
            { consensus_encode!(sixth_block_header.nonce) }

            // 6th block's difficulty count
            { crate::structures::hash::BlockHashGadget::push_bit_security_hint(&BlockHash::from_slice(&sixth_block_hash).unwrap()) }
        };

        let script = script! {
            { covenants_gadgets::wizards::tx::Step1VersionGadget::from_constant(&Version::TWO) }
            { covenants_gadgets::wizards::tx::Step2InCounterGadget::from_constant(1) }
            OP_HINT { covenants_gadgets::wizards::tx::step3_input::Step1OutPointGadget::from_provided() }
            { covenants_gadgets::wizards::tx::step3_input::Step2ScriptSigGadget::segregated_witness() }
            OP_HINT { covenants_gadgets::wizards::tx::step3_input::Step3SequenceGadget::from_provided() }

            { covenants_gadgets::wizards::tx::Step4OutCounterGadget::from_constant(2) }
            OP_HINT { covenants_gadgets::wizards::tx::step5_output::Step1AmountGadget::from_provided() }
            { covenants_gadgets::wizards::tx::step5_output::Step2ScriptPubKeyGadget::from_constant(&script_pub_key) }
            OP_HINT { covenants_gadgets::wizards::tx::step5_output::Step1AmountGadget::from_provided() }
            OP_HINT { covenants_gadgets::wizards::tx::step5_output::Step2ScriptPubKeyGadget::from_provided() }

            OP_HINT { covenants_gadgets::wizards::tx::Step6LockTimeGadget::from_provided() }
            OP_CAT6
            OP_CAT6

            OP_SHA256 OP_SHA256

            { TxInclusionProofGadget::compute_merkle_root() }
            OP_HINT OP_DUP OP_TOALTSTACK // save a copy of tx merkle root to the altstack
            OP_EQUALVERIFY

            OP_HINT { crate::structures::version::VersionGadget::from_provided() }
            OP_HINT { crate::structures::hash::BlockHashGadget::from_provided() }
            OP_FROMALTSTACK { crate::structures::merkle_hash::MerkleHashGadget::from_provided() }
            OP_HINT { crate::structures::time::TimeGadget::from_provided() }
            OP_HINT { crate::structures::compact_target::CompactTargetGadget::from_provided() }
            OP_HINT { crate::structures::nonce::NonceGadget::from_provided() }

            { crate::structures::header::HeaderGadget::compute_hash_from_stack() }
            OP_DUP OP_TOALTSTACK
            { crate::structures::hash::BlockHashGadget::get_bit_security() }

            for _ in 0..5 {
                OP_HINT { crate::structures::version::VersionGadget::from_provided() }
                OP_FROMALTSTACK { crate::structures::hash::BlockHashGadget::from_provided() }
                OP_HINT { crate::structures::merkle_hash::MerkleHashGadget::from_provided() }
                OP_HINT { crate::structures::time::TimeGadget::from_provided() }
                OP_HINT { crate::structures::compact_target::CompactTargetGadget::from_provided() }
                OP_HINT { crate::structures::nonce::NonceGadget::from_provided() }

                { crate::structures::header::HeaderGadget::compute_hash_from_stack() }
                OP_DUP OP_TOALTSTACK
                { crate::structures::hash::BlockHashGadget::get_bit_security() }
            }

            for _ in 0..6 {
                78 OP_GREATERTHANOREQUAL OP_VERIFY
            }

            OP_TRUE
        };
        let exec_result = execute_script_with_witness(script, convert_to_witness(witness).unwrap());
        assert!(exec_result.success);
    }
}
