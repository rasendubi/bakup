use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::SystemTime,
};

use blake3::Hash;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    // TODO: hostname, username
    time: SystemTime,
    entries: BTreeMap<String, EntryManifest>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirectoryManifest {
    entries: BTreeMap<String, EntryManifest>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct EntryManifest {
    #[serde(rename = "type")]
    ty: EntryType,
    #[serde_as(as = "DisplayFromStr")]
    content: Hash,
    // TODO:
    // owner uid, gid
    // mode
    // mtime
}

#[derive(Debug, Serialize, Deserialize)]
enum EntryType {
    Directory,
    File,
}

fn write_blob(out_dir: &Path, data: &[u8]) -> std::io::Result<Hash> {
    let hash = blake3::hash(data);
    let out_path = out_dir.join(&hash.to_string());
    if out_path.exists() {
        println!("Skipping non-modified blob: {out_path:?}");
    } else {
        std::fs::write(&out_path, data)?;
    }
    Ok(hash)
}

fn process_file(path: &Path, out_dir: &Path) -> std::io::Result<EntryManifest> {
    let content = std::fs::read(path)?;
    let hash = write_blob(out_dir, &content)?;
    Ok(EntryManifest {
        ty: EntryType::File,
        content: hash,
    })
}

fn process_dir(path: &Path, out_dir: &Path) -> std::io::Result<EntryManifest> {
    let mut manifest = DirectoryManifest {
        entries: BTreeMap::new(),
    };

    for entry in path.read_dir()? {
        let entry = entry?;

        let entry_manifest = process_path(&entry.path(), out_dir)?;

        manifest.entries.insert(
            entry
                .file_name()
                .into_string()
                .expect("name should be a valid UTF-8"),
            entry_manifest,
        );
    }

    let manifest_json =
        serde_json::to_vec(&manifest).expect("manifest should be convertible to JSON");
    let hash = write_blob(out_dir, &manifest_json)?;

    Ok(EntryManifest {
        ty: EntryType::Directory,
        content: hash,
    })
}

fn process_path(path: &Path, out_dir: &Path) -> std::io::Result<EntryManifest> {
    let metadata = path.symlink_metadata()?;
    if metadata.is_file() {
        process_file(path, out_dir)
    } else if metadata.is_dir() {
        process_dir(path, out_dir)
    } else {
        unreachable!("process_path should be called on either file or directory");
    }
}

fn main() {
    let mut args = std::env::args_os();
    let out_dir = PathBuf::from(args.nth(1).expect("No output directory provided"));
    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");

    let mut snapshot = SnapshotManifest {
        time: SystemTime::now(),
        entries: BTreeMap::new(),
    };
    for path in args {
        let path = std::path::absolute(PathBuf::from(path)).expect("Failed to get absolute path");

        let entry = process_path(&path, &out_dir).expect("Failed to process path");

        snapshot.entries.insert(
            path.to_str()
                .expect("path should be valid UTF-8")
                .to_owned(),
            entry,
        );
    }

    let snapshots_dir = out_dir.join("snapshots");
    std::fs::create_dir_all(&snapshots_dir).expect("Failed to create snapshots directory");
    let snapshot_json =
        serde_json::to_vec(&snapshot).expect("snapshot should be JSON-serializable");
    let hash = write_blob(&snapshots_dir, &snapshot_json);

    println!("snapshot: {hash:?}");
}
