mod cli;

use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::BufReader,
    os::unix::fs::MetadataExt,
    time::SystemTime,
};

use aes::cipher::KeyInit;
use bakup::chunking::{AesGearConfig, ChunkerConfig, StreamChunker};
use blake3::Hash;
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use humansize::format_size;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr, TimestampSecondsWithFrac};

use crate::cli::{Cli, Command};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    // TODO: hostname, username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde_as(as = "TimestampSecondsWithFrac<String>")]
    time: SystemTime,
    entries: BTreeMap<Utf8PathBuf, EntryManifest>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirectoryManifest {
    entries: BTreeMap<String, EntryManifest>,
}

#[serde_as]
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
struct EntryManifest {
    #[serde(flatten)]
    ty: EntryType,
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    #[serde(default)]
    mtime: Option<SystemTime>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    gid: Option<u32>,
    #[serde(default)]
    mode: Option<u32>,
}

impl EntryManifest {
    pub fn new(metadata: &Metadata, ty: EntryType) -> EntryManifest {
        EntryManifest {
            ty,
            mtime: metadata.modified().ok(),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            mode: Some(metadata.mode()),
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum EntryType {
    Directory {
        #[serde_as(as = "Vec<DisplayFromStr>")]
        content: Vec<Hash>,
    },
    File {
        #[serde_as(as = "Vec<DisplayFromStr>")]
        content: Vec<Hash>,
    },
    Symlink {
        target: Utf8PathBuf,
    },
}

struct SnapshotContext<'a> {
    out_dir: &'a Utf8Path,
    chunker_config: ChunkerConfig<'a>,
}

impl SnapshotContext<'_> {
    fn write_blob(&self, data: &[u8]) -> std::io::Result<Hash> {
        let hash = blake3::hash(data);
        let out_path = self.out_dir.join(hash.to_string());
        if !out_path.exists() {
            println!(
                "Writing new blob: {out_path} ({})",
                format_size(data.len(), humansize::BINARY)
            );
            std::fs::write(&out_path, data)?;
        } else {
            println!(
                "Skipping blob:    {out_path} ({})",
                format_size(data.len(), humansize::BINARY)
            );
        }
        Ok(hash)
    }

    fn process_path(&self, path: &Utf8Path) -> std::io::Result<EntryManifest> {
        let metadata = path.symlink_metadata()?;
        let ty = if metadata.is_file() {
            self.process_file(path)?
        } else if metadata.is_dir() {
            self.process_dir(path)?
        } else if metadata.is_symlink() {
            self.process_symlink(path)?
        } else {
            unreachable!("process_path should be called on either file or directory");
        };

        Ok(EntryManifest::new(&metadata, ty))
    }

    fn process_file(&self, path: &Utf8Path) -> std::io::Result<EntryType> {
        let hashes = StreamChunker::new(&self.chunker_config, BufReader::new(File::open(path)?))
            .map(|it| it.and_then(|chunk| self.write_blob(&chunk)))
            .collect::<std::io::Result<Vec<_>>>()?;

        Ok(EntryType::File { content: hashes })
    }

    fn process_dir(&self, path: &Utf8Path) -> std::io::Result<EntryType> {
        let mut manifest = DirectoryManifest {
            entries: BTreeMap::new(),
        };

        for entry in path.read_dir_utf8()? {
            let entry = entry?;

            let entry_manifest = self.process_path(entry.path())?;

            manifest
                .entries
                .insert(entry.file_name().to_owned(), entry_manifest);
        }

        let manifest_json =
            serde_json::to_vec(&manifest).expect("manifest should be convertible to JSON");
        let hash = self.write_blob(&manifest_json)?;

        Ok(EntryType::Directory {
            content: vec![hash],
        })
    }

    fn process_symlink(&self, path: &Utf8Path) -> Result<EntryType, std::io::Error> {
        let target = path.read_link_utf8()?;
        Ok(EntryType::Symlink { target })
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Snapshot(cmd) => {
            // TODO: preserve these parameters
            let aes = aes::Aes128Enc::new_from_slice(&[0u8; 16]).unwrap();
            let gear_config = AesGearConfig::new(aes);
            let chunker_config = ChunkerConfig::new(
                gear_config,
                1024 * 1024,
                4 * 1024 * 1024,
                16 * 1024 * 1024,
                3,
            );

            let ctx = SnapshotContext {
                out_dir: &cmd.remote,
                chunker_config,
            };

            std::fs::create_dir_all(&cmd.remote).expect("Failed to create output directory");
            let mut snapshot = SnapshotManifest {
                name: cmd.name,
                time: SystemTime::now(),
                entries: BTreeMap::new(),
            };
            for path in cmd.paths {
                let path = camino::absolute_utf8(path).expect("Failed to get absolute path");

                let entry = ctx.process_path(&path).expect("Failed to process path");

                snapshot.entries.insert(path, entry);
            }

            let snapshots_dir = cmd.remote.join("snapshots");
            std::fs::create_dir_all(&snapshots_dir).expect("Failed to create snapshots directory");
            let snapshot_json = serde_json::to_string_pretty(&snapshot)
                .expect("snapshot should be JSON-serializable");
            println!("snapshot: {}", snapshot_json);
            // let hash = write_blob(&snapshots_dir, &snapshot_json).unwrap();

            // println!("snapshot: {hash}");
        }
    }
}
