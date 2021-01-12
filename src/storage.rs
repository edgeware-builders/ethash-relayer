use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

/// DAG Storage.
pub trait Storage {
    fn read_cache(&self, epoch: usize) -> io::Result<Vec<u8>>;
    fn read_dataset(&self, epoch: usize) -> io::Result<Vec<u8>>;

    fn write_cache(&self, epoch: usize, cache: Vec<u8>) -> io::Result<()>;
    fn write_dataset(&self, epoch: usize, dataset: Vec<u8>) -> io::Result<()>;
}

/// Holds the Dag for the current epoch.
#[derive(Clone)]
pub struct DagStorage {
    cache_path: PathBuf,
    dataset_path: PathBuf,
}

impl DagStorage {
    pub fn new(cache_path: PathBuf, dataset_path: PathBuf) -> Self {
        Self {
            cache_path,
            dataset_path,
        }
    }
}

impl Storage for DagStorage {
    fn read_cache(&self, _: usize) -> io::Result<Vec<u8>> {
        let mut f = File::open(&self.cache_path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn read_dataset(&self, _: usize) -> io::Result<Vec<u8>> {
        let mut f = File::open(&self.dataset_path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn write_cache(&self, _: usize, cache: Vec<u8>) -> io::Result<()> {
        if let Some(dir) = self.cache_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.cache_path)?;
        f.write_all(&cache)?;
        Ok(())
    }

    fn write_dataset(&self, _: usize, dataset: Vec<u8>) -> io::Result<()> {
        if let Some(dir) = self.dataset_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.dataset_path)?;
        f.write_all(&dataset)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;

    #[derive(Clone)]
    pub struct MockStorage {
        inner: DagStorage,
    }

    impl Default for MockStorage {
        fn default() -> Self {
            Self {
                inner: DagStorage::new(
                    PathBuf::from("target/cache.bin"),
                    PathBuf::from("target/dataset.bin"),
                ),
            }
        }
    }

    impl Storage for MockStorage {
        fn read_cache(&self, epoch: usize) -> io::Result<Vec<u8>> {
            self.inner.read_cache(epoch)
        }

        fn read_dataset(&self, epoch: usize) -> io::Result<Vec<u8>> {
            self.inner.read_dataset(epoch)
        }

        fn write_cache(&self, epoch: usize, cache: Vec<u8>) -> io::Result<()> {
            self.inner.write_cache(epoch, cache)
        }

        fn write_dataset(&self, epoch: usize, dataset: Vec<u8>) -> io::Result<()> {
            self.inner.write_dataset(epoch, dataset)
        }
    }
}
