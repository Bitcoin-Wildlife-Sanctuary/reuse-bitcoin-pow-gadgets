use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, TxMerkleNode, Txid};
use sha2::Digest;

mod bitcoin_script;
pub use bitcoin_script::*;

pub struct TxInclusionProof {
    pub idx: usize,
    pub siblings: Vec<TxMerkleNode>,
}

impl TxInclusionProof {
    pub fn construct_from_txids(txids: &[Txid], idx: usize) -> Self {
        assert!(txids.len() > idx);

        let mut layers = vec![];

        let leaf_layer = txids
            .iter()
            .map(|x| TxMerkleNode::from_byte_array(x.to_byte_array()))
            .collect::<Vec<TxMerkleNode>>();
        layers.push(leaf_layer);

        let num_layers = (txids.len().next_power_of_two().ilog2() + 1) as usize;
        // if there are 2 txids, there would be 2 layers: one for the leaves, one for the root

        for i in 1..num_layers {
            let layer = layers[i - 1]
                .chunks(2)
                .map(|x| {
                    let mut sha256 = sha2::Sha256::new();
                    Digest::update(&mut sha256, x[0].as_byte_array());
                    if x.len() == 1 {
                        Digest::update(&mut sha256, x[0].as_byte_array());
                    } else {
                        Digest::update(&mut sha256, x[1].as_byte_array());
                    }
                    let first_hash = sha256.finalize().to_vec();

                    let mut sha256 = sha2::Sha256::new();
                    Digest::update(&mut sha256, first_hash);
                    let second_hash = TxMerkleNode::from_slice(&sha256.finalize()).unwrap();

                    second_hash
                })
                .collect::<Vec<TxMerkleNode>>();

            layers.push(layer);
        }

        let mut siblings = vec![];
        let mut cur = idx;
        for i in 0..num_layers - 1 {
            if layers[i].len() == (cur ^ 1) {
                siblings.push(layers[i][cur]);
            } else {
                siblings.push(layers[i][cur ^ 1]);
            }
            cur >>= 1;
        }

        Self { idx, siblings }
    }

    pub fn verify_hash_inclusion(
        &self,
        leaf_hash: &TxMerkleNode,
        root: &TxMerkleNode,
    ) -> Result<()> {
        let mut hash = leaf_hash.clone();

        let mut cur = self.idx;

        for sibling in self.siblings.iter() {
            let mut sha256 = sha2::Sha256::new();
            if cur % 2 == 1 {
                Digest::update(&mut sha256, sibling.as_byte_array());
                Digest::update(&mut sha256, hash.as_byte_array());
            } else {
                Digest::update(&mut sha256, hash.as_byte_array());
                Digest::update(&mut sha256, sibling.as_byte_array());
            }
            let first_hash = sha256.finalize().to_vec();

            let mut sha256 = sha2::Sha256::new();
            Digest::update(&mut sha256, first_hash.as_slice());
            let second_hash = sha256.finalize().to_vec();

            hash = TxMerkleNode::from_slice(&second_hash).unwrap();
            cur >>= 1;
        }

        if cur != 0 {
            return Err(anyhow::Error::msg(
                "The proof doesn't include the right number of siblings.",
            ));
        }

        if hash != *root {
            return Err(anyhow::Error::msg("The root does not match."));
        }

        Ok(())
    }

    pub fn verify_tx_inclusion(&self, tx: &Transaction, root: &TxMerkleNode) -> Result<()> {
        let hash = TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array());
        self.verify_hash_inclusion(&hash, root)
    }
}

#[cfg(test)]
mod test {
    use crate::spv::TxInclusionProof;
    use bitcoin::consensus::Decodable;
    use bitcoin::{Block, Txid};
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
        spv.verify_tx_inclusion(&block.txdata[100], &computed_merkle_root)
            .unwrap();
    }
}
