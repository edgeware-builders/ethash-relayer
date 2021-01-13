use std::io;
use std::path::PathBuf;

use byteorder::ByteOrder;
use ethash::mtree::MerkleTree;
use ethash::types::*;
use ethash::{EthereumPatch, LightDAG, Patch};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

/// Generates DAG (Cache, Dataset).
#[derive(Debug, PartialEq, Eq)]
pub struct DagGeneratorService {
    dataset: Vec<u8>,
    cache: Vec<u8>,
    epoch: usize,
}

impl Default for DagGeneratorService {
    fn default() -> Self {
        Self::new(0)
    }
}

impl DagGeneratorService {
    pub fn new(epoch: usize) -> Self {
        Self {
            dataset: Vec::new(),
            cache: Vec::new(),
            epoch,
        }
    }

    pub fn reload(&mut self) -> io::Result<()> {
        debug!("Reloading Dag Storage..");
        let dataset = std::fs::read(format!("data/{}/dataset.bin", self.epoch))?;
        let cache = std::fs::read(format!("data/{}/cache.bin", self.epoch))?;
        self.cache = cache;
        self.dataset = dataset;
        Ok(())
    }

    pub fn unload_dataset(&mut self) {
        self.dataset = Vec::new();
    }

    pub fn cache(&mut self) -> &[u8] {
        if self.cache.is_empty() {
            warn!("DAG Cache is not found for epoch: {}", self.epoch);
            debug!("Start Generating DAG Cache for epoch: {}", self.epoch);
            let dag = LightDAG::<EthereumPatch>::new(self.epoch.into());
            let cache_path = PathBuf::from(format!("data/{}/cache.bin", self.epoch));
            std::fs::create_dir_all(cache_path.parent().unwrap())
                .expect("failed to create cache path");
            std::fs::write(cache_path, &dag.cache).expect("failed to write cache to disk");
            info!("DAG Cache is ready for epoch: {}", self.epoch);
            self.cache = dag.cache;
            self.cache.as_slice()
        } else {
            self.cache.as_slice()
        }
    }

    pub fn dataset(&mut self) -> &[u8] {
        if self.dataset.is_empty() {
            let epoch = self.epoch;
            let cache = self.cache();
            warn!("DAG Dataset is not found for epoch: {}", epoch);
            debug!("Start Generating DAG Dataset for epoch: {}", epoch);
            let size = ethash::get_full_size(epoch);
            let mut output = vec![0u8; size];
            ethash::make_dataset(&mut output, cache);
            let dataset_path = PathBuf::from(format!("data/{}/dataset.bin", epoch));
            std::fs::create_dir_all(dataset_path.parent().unwrap())
                .expect("failed to create dataset path");
            std::fs::write(dataset_path, &output).expect("failed to write dataset to disk");
            warn!("DAG Dataset is ready for epoch: {}", self.epoch);
            self.dataset = output;
            self.dataset.as_slice()
        } else {
            self.dataset.as_slice()
        }
    }

    pub const fn epoch(&self) -> usize {
        self.epoch
    }
}

/// Generates Proof for a given Block header.
#[derive(Debug, PartialEq)]
pub struct ProofGeneratorService {
    dag_service: DagGeneratorService,
    loaded: bool,
    mt: ethash::mtree::MerkleTree,
}

impl Eq for ProofGeneratorService {}

impl ProofGeneratorService {
    pub fn new(dag_service: DagGeneratorService) -> Self {
        Self {
            dag_service,
            loaded: false,
            mt: MerkleTree::Zero(0),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn build_merkle_tree(&mut self) {
        let epoch = self.dag_service.epoch();
        let dataset = self.dag_service.dataset();
        let depth = ethash::calc_dataset_depth(epoch);
        debug!("Building up the MerkleTree with depth = {}.", depth);
        let mt = ethash::calc_dataset_merkle_proofs(epoch, dataset);
        self.dag_service.unload_dataset();
        self.mt = mt;
        self.loaded = true;
        debug!("MerkleTree is ready for epoch: #{}", epoch);
    }

    pub fn proofs(&mut self, header: BlockHeader) -> BlockWithProofs {
        debug!("Start calculating the proofs for block #{}", header.number);
        let hash = ethash::seal_header(&BlockHeaderSeal::from(header.clone()));
        let epoch = (header.number / EthereumPatch::epoch_length()).as_usize();
        let full_size = ethash::get_full_size(epoch);
        let cache = self.dag_service.cache();
        debug!("Calculating indices for #{} ..", header.number);
        let indices = ethash::get_indices(hash, header.nonce, full_size, |i| {
            let raw_data = ethash::calc_dataset_item(cache, i);
            let mut data = [0u32; 16];
            for (i, b) in data.iter_mut().enumerate() {
                *b = byteorder::LE::read_u32(&raw_data[(i * 4)..]);
            }
            data
        });
        let merkle_root = self.mt.hash();
        let depth = ethash::calc_dataset_depth(epoch);
        let mut output = BlockWithProofs {
            number: header.number.as_u64(),
            proof_length: depth as _,
            merkle_root: hex::encode(merkle_root.0),
            elements: Vec::with_capacity(depth * 4),
            merkle_proofs: Vec::with_capacity(depth * 2),
        };
        debug!(
            "Final Step generating proofs for {} indices ..",
            indices.len()
        );
        for index in &indices {
            let (element, _, proofs) = self.mt.generate_proof(*index as _, depth);
            let els = element.into_h256_array();
            let els = els.iter().map(|v| hex::encode(&v.0));
            output.elements.extend(els);
            let proofs = proofs.iter().map(|v| hex::encode(&v.0));
            output.merkle_proofs.extend(proofs);
        }
        output
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockWithProofs {
    pub number: u64,
    pub proof_length: u64,
    pub merkle_root: String,
    pub elements: Vec<String>,
    pub merkle_proofs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_2() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut dag_service = DagGeneratorService::default();
        let _ = dag_service.reload().is_ok();
        let mut proof_service = ProofGeneratorService::new(dag_service);
        proof_service.build_merkle_tree();
        let block_2_raw = hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap();
        let block_2: BlockHeader = rlp::decode(&block_2_raw).unwrap();
        let output = proof_service.proofs(block_2);
        assert_eq!(output.merkle_root, "f346b91a0469b7960a7b00d7812a5023");
    }
}
