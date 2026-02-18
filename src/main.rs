use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, Subcommand};
use decure::{
    decrypt_file_auto, encrypt_file_streaming, reconstruct_master_key, split_master_key,
    DEFAULT_CHUNK_SIZE, MASTER_KEY_LEN,
};

#[derive(Parser)]
#[command(author, version, about = "Decure - local encryption with XOR shares")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(group(
        ArgGroup::new("share_target")
            .required(true)
            .args(["shares_dir", "servers_root"])
    ))]
    Encrypt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        shares_dir: Option<PathBuf>,
        #[arg(long)]
        servers_root: Option<PathBuf>,
        #[arg(long, default_value_t = 15)]
        shares: usize,
        #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
        chunk_size: usize,
        #[arg(long, default_value_t = 3)]
        servers: usize,
    },
    #[command(group(
        ArgGroup::new("share_source")
            .required(true)
            .args(["shares_dir", "servers_root"])
    ))]
    Decrypt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        shares_dir: Option<PathBuf>,
        #[arg(long)]
        servers_root: Option<PathBuf>,
    },
    #[command(group(
        ArgGroup::new("old_share_source")
            .required(true)
            .args(["old_shares_dir", "old_servers_root"])
    ))]
    #[command(group(
        ArgGroup::new("new_share_target")
            .required(true)
            .args(["new_shares_dir", "new_servers_root"])
    ))]
    Rotate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        old_shares_dir: Option<PathBuf>,
        #[arg(long)]
        old_servers_root: Option<PathBuf>,
        #[arg(long)]
        new_shares_dir: Option<PathBuf>,
        #[arg(long)]
        new_servers_root: Option<PathBuf>,
        #[arg(long, default_value_t = 15)]
        shares: usize,
        #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
        chunk_size: usize,
        #[arg(long, default_value_t = 3)]
        servers: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            shares_dir,
            shares,
            chunk_size,
            servers_root,
            servers,
        } => encrypt_flow(
            &input,
            &output,
            shares_dir,
            servers_root,
            shares,
            chunk_size,
            servers,
        ),
        Commands::Decrypt {
            input,
            output,
            shares_dir,
            servers_root,
        } => decrypt_flow(&input, &output, shares_dir, servers_root),
        Commands::Rotate {
            input,
            output,
            old_shares_dir,
            new_shares_dir,
            shares,
            chunk_size,
            old_servers_root,
            new_servers_root,
            servers,
        } => rotate_flow(
            &input,
            &output,
            old_shares_dir,
            old_servers_root,
            new_shares_dir,
            new_servers_root,
            shares,
            chunk_size,
            servers,
        ),
    }
}

fn encrypt_flow(
    input: &PathBuf,
    output: &PathBuf,
    shares_dir: Option<PathBuf>,
    servers_root: Option<PathBuf>,
    shares: usize,
    chunk_size: usize,
    servers: usize,
) -> Result<()> {
    let master_key = decure::generate_master_key();
    encrypt_file_streaming(input, output, &master_key, chunk_size)
        .with_context(|| format!("encrypt input {input:?}"))?;

    let share_dirs = resolve_share_dirs_for_write(shares_dir, servers_root, servers)?;
    write_shares(&master_key, shares, &share_dirs)?;

    println!("Encrypted. Wrote {} shares.", shares);
    Ok(())
}

fn decrypt_flow(
    input: &PathBuf,
    output: &PathBuf,
    shares_dir: Option<PathBuf>,
    servers_root: Option<PathBuf>,
) -> Result<()> {
    let share_dirs = resolve_share_dirs_for_read(shares_dir, servers_root)?;
    let shares = load_shares(&share_dirs)?;
    let master_key = reconstruct_master_key(&shares)?;

    decrypt_file_auto(input, output, &master_key)
        .with_context(|| format!("decrypt input {input:?}"))?;
    println!("Decrypted.");
    Ok(())
}

fn rotate_flow(
    input: &PathBuf,
    output: &PathBuf,
    old_shares_dir: Option<PathBuf>,
    old_servers_root: Option<PathBuf>,
    new_shares_dir: Option<PathBuf>,
    new_servers_root: Option<PathBuf>,
    shares: usize,
    chunk_size: usize,
    servers: usize,
) -> Result<()> {
    let old_dirs = resolve_share_dirs_for_read(old_shares_dir, old_servers_root)?;
    let old_shares = load_shares(&old_dirs)?;
    let old_master = reconstruct_master_key(&old_shares)?;

    let temp_dir = tempfile::tempdir()?;
    let temp_plain = temp_dir.path().join("rotate_plain.bin");
    decrypt_file_auto(input, &temp_plain, &old_master)
        .with_context(|| format!("decrypt input {input:?}"))?;

    let new_master = decure::generate_master_key();
    encrypt_file_streaming(&temp_plain, output, &new_master, chunk_size)
        .with_context(|| format!("encrypt output {output:?}"))?;

    let new_dirs = resolve_share_dirs_for_write(new_shares_dir, new_servers_root, servers)?;
    write_shares(&new_master, shares, &new_dirs)?;
    println!("Rotated. Wrote {} new shares.", shares);
    Ok(())
}

fn write_shares(
    master_key: &[u8; MASTER_KEY_LEN],
    shares: usize,
    share_dirs: &[PathBuf],
) -> Result<()> {
    let share_list = split_master_key(master_key, shares)?;
    for (idx, share) in share_list.iter().enumerate() {
        let dir = &share_dirs[idx % share_dirs.len()];
        fs::create_dir_all(dir).with_context(|| format!("create shares dir {dir:?}"))?;
        let share_path = dir.join(format!("share_{idx:02}.bin"));
        fs::write(share_path, share).context("write share")?;
    }

    Ok(())
}

fn load_shares(share_dirs: &[PathBuf]) -> Result<Vec<[u8; MASTER_KEY_LEN]>> {
    let mut shares = Vec::new();

    for dir in share_dirs {
        let entries = fs::read_dir(dir).with_context(|| format!("read shares dir {dir:?}"))?;
        for entry in entries {
            let entry = entry?;
            if entry.path().is_file() {
                let data = fs::read(entry.path())?;
                if data.len() == MASTER_KEY_LEN {
                    let share: [u8; MASTER_KEY_LEN] = data
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid share length"))?;
                    shares.push(share);
                }
            }
        }
    }

    if shares.is_empty() {
        return Err(anyhow::anyhow!("no shares found"));
    }

    Ok(shares)
}

fn resolve_share_dirs_for_write(
    shares_dir: Option<PathBuf>,
    servers_root: Option<PathBuf>,
    servers: usize,
) -> Result<Vec<PathBuf>> {
    match (shares_dir, servers_root) {
        (Some(dir), None) => Ok(vec![dir]),
        (None, Some(root)) => {
            if servers == 0 {
                return Err(anyhow::anyhow!("servers must be > 0"));
            }
            let mut dirs = Vec::new();
            for idx in 0..servers {
                dirs.push(root.join(format!("server_{idx:02}")));
            }
            Ok(dirs)
        }
        _ => Err(anyhow::anyhow!(
            "provide either --shares-dir or --servers-root"
        )),
    }
}

fn resolve_share_dirs_for_read(
    shares_dir: Option<PathBuf>,
    servers_root: Option<PathBuf>,
) -> Result<Vec<PathBuf>> {
    match (shares_dir, servers_root) {
        (Some(dir), None) => Ok(vec![dir]),
        (None, Some(root)) => {
            let mut dirs = Vec::new();
            let entries = fs::read_dir(&root).with_context(|| format!("read servers root {root:?}"))?;
            for entry in entries {
                let entry = entry?;
                if entry.path().is_dir() {
                    let name = entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    if name.starts_with("server_") {
                        dirs.push(entry.path());
                    }
                }
            }

            if dirs.is_empty() {
                return Err(anyhow::anyhow!("no server directories found"));
            }

            dirs.sort();
            Ok(dirs)
        }
        _ => Err(anyhow::anyhow!(
            "provide either --shares-dir or --servers-root"
        )),
    }
}
