use byteorder::ByteOrder;
use ethash::types::*;
use ethash::{EthereumPatch, LightDAG, Patch};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

use crate::storage::*;

/// Generates DAG (Cache, Dataset).
#[derive(Clone)]
pub struct DagGeneratorService<S: Storage> {
    storage: S,
}

impl<S> Default for DagGeneratorService<S>
where
    S: Storage + Default,
{
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<S: Storage> DagGeneratorService<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn cache(&self, epoch: usize) -> impl AsRef<[u8]> {
        match self.storage.read_cache(epoch) {
            Ok(cache) => cache,
            Err(e) => {
                error!("Error: {}", e);
                warn!("DAG Cache is not found for epoch: {}", epoch);
                debug!("Start Generating DAG Cache for epoch: {}", epoch);
                let dag = LightDAG::<EthereumPatch>::new(epoch.into());
                let _ = self.storage.write_cache(epoch, dag.cache);
                warn!("DAG Cache is ready for epoch: {}", epoch);
                self.storage.read_cache(epoch).unwrap()
            }
        }
    }

    pub fn dataset(&self, epoch: usize) -> impl AsRef<[u8]> {
        match self.storage.read_dataset(epoch) {
            Ok(dataset) => dataset,
            Err(_) => {
                warn!("DAG Dataset is not found for epoch: {}", epoch);
                debug!("Start Generating DAG Dataset for epoch: {}", epoch);
                let cache = self.cache(epoch);
                let size = ethash::get_full_size(epoch);
                let mut dataset = vec![0u8; size];
                ethash::make_dataset(&mut dataset, cache.as_ref());
                let _ = self.storage.write_dataset(epoch, dataset);
                warn!("DAG Dataset is ready for epoch: {}", epoch);
                self.storage.read_dataset(epoch).unwrap()
            }
        }
    }
}

/// Generates Proof for a given Block header.
#[derive(Clone)]
pub struct ProofGeneratorService<S: Storage> {
    dag_service: DagGeneratorService<S>,
}

impl<S: Storage> ProofGeneratorService<S> {
    pub fn new(dag_service: DagGeneratorService<S>) -> Self {
        Self { dag_service }
    }

    pub fn proofs(&self, header: BlockHeader) -> BlockWithProofs {
        debug!("Start calculating the proofs for #{}", header.number);
        let hash = ethash::seal_header(&BlockHeaderSeal::from(header.clone()));
        let epoch = (header.number / EthereumPatch::epoch_length()).as_usize();
        let full_size = ethash::get_full_size(epoch);
        let cache = self.dag_service.cache(epoch);
        let dataset = self.dag_service.dataset(epoch);
        debug!("Calculating indices for #{} ..", header.number);
        let indices = ethash::get_indices(hash, header.nonce, full_size, |i| {
            let raw_data = ethash::calc_dataset_item(cache.as_ref(), i);
            let mut data = [0u32; 16];
            for (i, b) in data.iter_mut().enumerate() {
                *b = byteorder::LE::read_u32(&raw_data[(i * 4)..]);
            }
            data
        });

        let depth = ethash::calc_dataset_depth(epoch);
        debug!(
            "Building up the MerkleTree with depth = {} for #{}",
            depth, header.number
        );
        let tree = ethash::calc_dataset_merkle_proofs(epoch, dataset.as_ref());

        let mut output = BlockWithProofs {
            number: header.number.as_u64(),
            proof_length: depth as _,
            merkle_root: hex::encode(tree.hash().0),
            elements: Vec::with_capacity(depth * 4),
            merkle_proofs: Vec::with_capacity(depth * 2),
        };
        debug!(
            "Final Step generating proofs for {} indices ..",
            indices.len()
        );
        for index in &indices {
            let (element, _, proofs) = tree.generate_proof(*index as _, depth);
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
    use crate::storage::mock::MockStorage;

    #[test]
    fn block_2() {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .pretty()
            .init();
        let dag_service = DagGeneratorService::<MockStorage>::default();
        let proof_service = ProofGeneratorService::new(dag_service);
        let block_2_raw = hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap();
        let block_2: BlockHeader = rlp::decode(&block_2_raw).unwrap();
        let output = proof_service.proofs(block_2);
        assert_eq!(output.merkle_root, "f346b91a0469b7960a7b00d7812a5023");
    }
}
