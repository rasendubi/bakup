use camino::Utf8PathBuf;

#[derive(clap::Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Backup one or more paths.
    Snapshot(Snapshot),
}

#[derive(clap::Args)]
pub struct Snapshot {
    /// Snapshot name.
    #[arg(short, long)]
    pub name: Option<String>,
    /// Path to save backup snapshot to.
    #[arg(short, long)]
    pub remote: Utf8PathBuf,
    /// Paths to backup.
    #[arg(required = true)]
    pub paths: Vec<Utf8PathBuf>,
}
