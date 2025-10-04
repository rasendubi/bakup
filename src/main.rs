use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use blake3::Hash;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

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

fn process_file(path: &Path, out_dir: &Path) -> std::io::Result<EntryManifest> {
    let content = std::fs::read(path)?;
    let hash = blake3::hash(&content);

    let out_path = out_dir.join(&hash.to_string());
    if out_path.exists() {
        println!("Skipping non-modified file: {path:?}");
    } else {
        std::fs::write(&out_path, content)?;
    }

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
    let hash = blake3::hash(&manifest_json);
    let out_path = out_dir.join(hash.to_string());

    if out_path.exists() {
        println!("Skipping non-modified directory: {path:?}");
    } else {
        std::fs::write(&out_path, manifest_json)?;
    }

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
    let path = PathBuf::from(args.nth(1).expect("No path provided"));
    let out_dir = PathBuf::from(args.next().expect("No output directory provided"));

    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");
    let entry = process_path(&path, &out_dir).expect("Failed to process path");
    println!("bakup root: {:?}", entry.content);
}
