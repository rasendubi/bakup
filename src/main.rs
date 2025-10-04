use std::path::{Path, PathBuf};

fn process_path(path: &Path, out_dir: &Path) -> Result<(), std::io::Error> {
    let metadata = path.symlink_metadata()?;

    if metadata.is_file() {
        let content = std::fs::read(path)?;
        let hash = blake3::hash(&content);

        let out_path = out_dir.join(&hash.to_string());
        if out_path.exists() {
            println!("Skipping non-modified file: {path:?}");
            return Ok(());
        }

        std::fs::write(&out_path, content)?;
    } else if metadata.is_dir() {
        for entry in path.read_dir()? {
            let entry = entry?;
            process_path(&entry.path(), out_dir)?;
        }
    }

    Ok(())
}

fn main() {
    let mut args = std::env::args_os();
    let path = PathBuf::from(args.nth(1).expect("No path provided"));
    let out_dir = PathBuf::from(args.next().expect("No output directory provided"));

    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");
    process_path(&path, &out_dir).expect("Failed to process path");
}
