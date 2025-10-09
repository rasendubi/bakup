mod cli;

use std::{fs::File, io::BufReader, os::unix::fs::MetadataExt, time::SystemTime};

use aes::cipher::KeyInit;
use anyhow::bail;
use bakup::{
    cas::{ContentAddressableStorage, DirectoryCas},
    chunking::{AesGearConfig, ChunkerConfig, StreamChunker},
};
use bytes::Bytes;
use camino::Utf8PathBuf;
use clap::Parser;
use const_hex::ToHexExt;
use digest::Output;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::{
    serde_as, serde_conv, TimestampSecondsWithFrac,
};

use crate::cli::{Cli, Command};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    // TODO: hostname, username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde_as(as = "TimestampSecondsWithFrac<String>")]
    time: SystemTime,
    entries: Vec<EntryManifest>,
}

#[serde_as]
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
struct EntryManifest {
    path: Utf8PathBuf,
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

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum EntryType {
    Directory,
    File {
        #[serde_as(as = "Vec<HexHash>")]
        content: Vec<Output<blake3::Hasher>>,
    },
    Symlink {
        target: Utf8PathBuf,
    },
}

serde_conv!(
    HexHash,
    Output<blake3::Hasher>,
    |hash: &Output<blake3::Hasher>| hash.encode_hex(),
    |s: &str| -> Result<_, const_hex::FromHexError> {
        let mut hash = Output::<blake3::Hasher>::default();
        const_hex::decode_to_slice(s, &mut hash)?;
        Ok(hash)
    }
);

struct SnapshotContext<'a> {
    out_dir: DirectoryCas<blake3::Hasher>,
    chunker_config: ChunkerConfig<'a>,
}

impl SnapshotContext<'_> {
    fn write_blob(&self, data: Bytes) -> std::io::Result<Output<blake3::Hasher>> {
        self.out_dir.store(data)
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
                out_dir: DirectoryCas::new(&cmd.remote),
                chunker_config,
            };

            std::fs::create_dir_all(&cmd.remote).expect("Failed to create output directory");

            let progress = MultiProgress::new();
            let global_progress = progress
                .add(ProgressBar::no_length().with_style(
                    ProgressStyle::with_template("{bytes} ({bytes_per_sec})").unwrap(),
                ));

            let mut entries = cmd
                .paths
                .par_iter()
                .filter_map(|it| camino::absolute_utf8(it).ok())
                .flat_map(|it| walkdir::WalkDir::new(it).into_iter().par_bridge())
                .map(
                    |entry| {
                        let entry = entry?;

                        let Ok(path) = Utf8PathBuf::try_from(entry.path().to_path_buf()) else {
                            bail!("path should be valid UTF-8");
                        };
                        let metadata = entry.metadata()?;
                        let mtime = metadata.modified().ok();
                        let _dev = metadata.dev();
                        let _inode = metadata.ino();
                        let size = metadata.size();

                        let file_type = entry.file_type();
                        let ty = if file_type.is_dir() {
                            EntryType::Directory
                        } else if file_type.is_file() {
                            let my_progress = progress.add(
                                ProgressBar::new(size)
                                    .with_style(
                                        ProgressStyle::with_template(
                                            "{prefix} {wide_bar} {bytes}/{total_bytes} ({bytes_per_sec})",
                                        )
                                        .unwrap(),
                                    )
                                    .with_message(entry.file_name().to_str().unwrap().to_owned())
                                    .with_prefix(entry.file_name().to_str().unwrap().to_owned()),
                            );

                            let hashes = StreamChunker::new(
                                &ctx.chunker_config,
                                BufReader::new(File::open(&path)?),
                            )
                            .map(|it| {
                                it.and_then(|chunk| {
                                    let len = chunk.len() as u64;
                                    let chunk = Bytes::from(chunk);
                                    let hash = ctx.write_blob(chunk);
                                    my_progress.inc(len);
                                    global_progress.inc(len);

                                    hash
                                })
                            })
                            .collect::<std::io::Result<Vec<_>>>()?;

                            my_progress.finish();
                            progress.remove(&my_progress);

                            EntryType::File { content: hashes }
                        } else if file_type.is_symlink() {
                            let target = path.read_link()?;
                            EntryType::Symlink {
                                target: target.try_into()?,
                            }
                        } else {
                            unreachable!();
                        };

                        Ok::<_, anyhow::Error>(EntryManifest {
                            path,
                            ty,
                            mtime,
                            uid: Some(metadata.uid()),
                            gid: Some(metadata.gid()),
                            mode: Some(metadata.mode()),
                        })
                    },
                )
                .collect::<anyhow::Result<Vec<_>>>()
                .unwrap();

            entries.par_sort_unstable_by(|a, b| a.path.cmp(&b.path));

            let snapshot = SnapshotManifest {
                name: cmd.name,
                time: SystemTime::now(),
                entries,
            };

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
