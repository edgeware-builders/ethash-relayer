use std::io;
use std::path::PathBuf;

use byteorder::ByteOrder;
use ethash::{types::BlockHeader, EthereumPatch, Patch};
use log::{debug, info, warn};
use ouroboros::self_referencing;
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
        self.dataset = dataset;
        let cache = std::fs::read(format!("data/{}/cache.bin", self.epoch))?;
        self.cache = cache;
        Ok(())
    }

    pub fn unload_dataset(&mut self) {
        self.dataset = Vec::new();
    }

    pub fn cache(&mut self) -> &[u8] {
        if self.cache.is_empty() {
            warn!("DAG Cache is not found for epoch: {}", self.epoch);
            debug!("Start Generating DAG Cache for epoch: {}", self.epoch);
            let cache_size = ethash::get_cache_size(self.epoch);
            let seed = ethash::get_seedhash(self.epoch);
            let mut cache = vec![0u8; cache_size];
            ethash::make_cache(&mut cache, seed);
            let cache_path = PathBuf::from(format!("data/{}/cache.bin", self.epoch));
            std::fs::create_dir_all(cache_path.parent().unwrap())
                .expect("failed to create cache path");
            std::fs::write(cache_path, &cache).expect("failed to write cache to disk");
            info!("DAG Cache is ready for epoch: {}", self.epoch);
            self.cache = cache;
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
#[self_referencing]
#[derive(Debug, PartialEq)]
pub struct ProofGeneratorService {
    dag_service: DagGeneratorService,
    depth: usize,
    leaves: Vec<ethash::mtree::DobuleLeaf>,
    #[borrows(leaves)]
    mt: ethash::mtree::MerkleTree<'this>,
}

impl Eq for ProofGeneratorService {}

impl Default for ProofGeneratorService {
    fn default() -> Self {
        Self::empty()
    }
}

impl ProofGeneratorService {
    pub fn empty() -> Self {
        ProofGeneratorServiceBuilder {
            dag_service: DagGeneratorService::default(),
            depth: 0,
            leaves: Vec::new(),
            mt_builder: |_| ethash::mtree::MerkleTree::Zero(0),
        }
        .build()
    }
    pub fn with_service(mut dag_service: DagGeneratorService) -> Self {
        let _ = dag_service.reload().is_ok();
        let epoch = dag_service.epoch();
        let dataset = dag_service.dataset();
        let (depth, leaves) = ethash::calc_dataset_merkle_leaves(epoch, dataset);
        debug!("Merkle leaves is ready for epoch: #{}", epoch);
        dag_service.unload_dataset();
        ProofGeneratorServiceBuilder {
            dag_service,
            depth,
            leaves,
            mt_builder: |leaves| {
                let dl: Vec<_> = leaves.iter().collect();
                ethash::mtree::MerkleTree::create(&dl, depth)
            },
        }
        .build()
    }

    pub fn is_loaded(&self) -> bool {
        !self.borrow_leaves().is_empty()
    }

    pub fn proofs(&mut self, header: BlockHeader) -> BlockWithProofs {
        debug!("Start calculating the proofs for block #{}", header.number);
        let epoch = (header.number / EthereumPatch::epoch_length()).as_usize();
        let full_size = ethash::get_full_size(epoch);
        let cache = self.with_dag_service_mut(|s| s.cache());
        debug!("Check if the block header is correct ...");
        let (mix_hash, _) =
            ethash::hashimoto_light(header.seal_hash(), header.nonce, full_size, cache);
        if dbg!(mix_hash != header.mix_hash) {
            warn!("mix_hash mismatch for block #{}", header.number);
        }

        assert_eq!(mix_hash, header.mix_hash, "mix_hash mismatch!!");

        debug!("Calculating indices for #{} ..", header.number);
        let indices = ethash::get_indices(header.seal_hash(), header.nonce, full_size, |i| {
            let raw_data = ethash::calc_dataset_item(cache, i);
            let mut data = [0u32; 16];
            for (i, b) in data.iter_mut().enumerate() {
                *b = byteorder::LE::read_u32(&raw_data[(i * 4)..]);
            }
            data
        });

        self.with_mt(|mt| {
            let merkle_root = mt.hash();
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
                let (element, _, proofs) = mt.generate_proof(*index as _, depth);
                let els = element.into_h256_array();
                let els = els.iter().map(|v| hex::encode(&v.0));
                output.elements.extend(els);
                let proofs = proofs.iter().map(|v| hex::encode(&v.0));
                output.merkle_proofs.extend(proofs);
            }
            output
        })
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
        let mut proof_service = ProofGeneratorService::with_service(dag_service);
        let block_2_raw = hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap();
        let block_2: BlockHeader = rlp::decode(&block_2_raw).unwrap();
        let output = proof_service.proofs(block_2);
        assert_eq!(output.merkle_root, "f346b91a0469b7960a7b00d7812a5023");
    }

    #[test]
    fn block_10234011() {
        let block_raw = hex::decode("f90211a0c4c9a81c4ae18cfe758ccdb77e1a20f80c26e219aab3e51e3392037396f16c78a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347945a0b54d5dc17e0aadc383d2db43b0a0d3e029c4ca06831f40243a7b4ff98c6d1184aa6a0525ac710cdc46a33b868c0ed22d93ac219a032dc621f119727aebe4cc93bb54cf8bb8e38ddba99ffc85a301c87d16c1c7d6ca0e9c7998a4c7c955c56e73b056e184ca0d9ee358fe0349a8e86c7273c7014b0bfb901002a2205005240300012802101812110130418900001c0244b20537081280b6104047690410a4851442c01071c1021c54f034002000904a00032203908900d24c22a931948141c1012cd00501e2000012400022420214011a476210285c8503040c128800d4810700001005a20000890e438410026000544c130300ed00120282002104c118100e020045d421a062910075008414901448c084b002053201033060740200a584020e880ae08c18008883d601f545414004aa08004041aa84042a00ab82022664316c8260007a45110183624441c87c00c20115c743252382225100100250d02c47817a02408b004d026c4a460008400014042aa4208c001b24e2a87084e4f6c2a06f5839c289b8397532983974a2f845ee00166906574682d70726f2d687a682d74303032a0c65d22c9e5f5e5c801d97e120b8932f7a20387cb0426685afb49ead05b6565af8806d148e4044432ec").unwrap();
        let block: BlockHeader = rlp::decode(&block_raw).unwrap();
        dbg!(&block);
        let epoch = block.number / EthereumPatch::epoch_length();
        let _ = env_logger::builder().is_test(true).try_init();
        let mut dag_service = DagGeneratorService::new(epoch.as_usize());
        let _ = dag_service.reload().is_ok();
        let mut proof_service = ProofGeneratorService::with_service(dag_service);
        let _ = proof_service.proofs(block);
    }
}
