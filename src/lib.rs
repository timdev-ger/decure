use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

pub const MASTER_KEY_LEN: usize = 32;
pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub const MAGIC: &[u8; 6] = b"DECURE";
pub const VERSION: u8 = 1;
pub const STREAM_VERSION: u8 = 2;
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Envelope {
    pub nonce_master: [u8; NONCE_LEN],
    pub enc_dek: Vec<u8>,
    pub nonce_data: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn split_master_key(master: &[u8; MASTER_KEY_LEN], shares: usize) -> Result<Vec<[u8; MASTER_KEY_LEN]>> {
    if shares < 2 {
        return Err(anyhow!("shares must be >= 2"));
    }

    let mut parts: Vec<[u8; MASTER_KEY_LEN]> = Vec::with_capacity(shares);
    let mut xor_acc = [0u8; MASTER_KEY_LEN];

    for _ in 0..(shares - 1) {
        let mut share = [0u8; MASTER_KEY_LEN];
        OsRng.fill_bytes(&mut share);
        for i in 0..MASTER_KEY_LEN {
            xor_acc[i] ^= share[i];
        }
        parts.push(share);
    }

    let mut last = [0u8; MASTER_KEY_LEN];
    for i in 0..MASTER_KEY_LEN {
        last[i] = master[i] ^ xor_acc[i];
    }
    parts.push(last);

    Ok(parts)
}

pub fn reconstruct_master_key(shares: &[[u8; MASTER_KEY_LEN]]) -> Result<[u8; MASTER_KEY_LEN]> {
    if shares.len() < 2 {
        return Err(anyhow!("need at least 2 shares"));
    }

    let mut master = [0u8; MASTER_KEY_LEN];
    for share in shares {
        for i in 0..MASTER_KEY_LEN {
            master[i] ^= share[i];
        }
    }
    Ok(master)
}

pub fn encrypt_bytes(plaintext: &[u8], master_key: &[u8; MASTER_KEY_LEN]) -> Result<Envelope> {
    let dek = generate_dek();

    let (kek, nonce_master) = derive_kek(master_key)?;
    let kek_cipher = XChaCha20Poly1305::new(&kek.into());
    let enc_dek = kek_cipher
        .encrypt(XNonce::from_slice(&nonce_master), dek.as_slice())
        .map_err(|_| anyhow!("failed to encrypt DEK"))?;

    let (data_key, nonce_data) = derive_data_key(&dek)?;
    let data_cipher = XChaCha20Poly1305::new(&data_key.into());
    let ciphertext = data_cipher
        .encrypt(XNonce::from_slice(&nonce_data), plaintext)
        .map_err(|_| anyhow!("failed to encrypt data"))?;

    Ok(Envelope {
        nonce_master,
        enc_dek,
        nonce_data,
        ciphertext,
    })
}

pub fn encrypt_file_streaming(
    input: &Path,
    output: &Path,
    master_key: &[u8; MASTER_KEY_LEN],
    chunk_size: usize,
) -> Result<()> {
    if chunk_size == 0 {
        return Err(anyhow!("chunk_size must be > 0"));
    }

    let dek = generate_dek();
    let (kek, nonce_master) = derive_kek(master_key)?;
    let kek_cipher = XChaCha20Poly1305::new(&kek.into());
    let enc_dek = kek_cipher
        .encrypt(XNonce::from_slice(&nonce_master), dek.as_slice())
        .map_err(|_| anyhow!("failed to encrypt DEK"))?;

    let data_key = derive_data_key_only(&dek)?;
    let data_cipher = XChaCha20Poly1305::new(&data_key.into());

    let input_file = File::open(input)?;
    let output_file = File::create(output)?;
    let mut reader = BufReader::new(input_file);
    let mut writer = BufWriter::new(output_file);

    write_stream_header(&mut writer, &nonce_master, &enc_dek, chunk_size as u32)?;

    let mut buffer = vec![0u8; chunk_size];
    loop {
        let read_len = reader.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = data_cipher
            .encrypt(XNonce::from_slice(&nonce), &buffer[..read_len])
            .map_err(|_| anyhow!("failed to encrypt chunk"))?;

        writer.write_all(&nonce)?;
        writer.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        writer.write_all(&ciphertext)?;
    }

    writer.flush()?;
    Ok(())
}

pub fn decrypt_bytes(envelope: &Envelope, master_key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>> {
    let (kek, _) = derive_kek(master_key)?;
    let kek_cipher = XChaCha20Poly1305::new(&kek.into());
    let dek = kek_cipher
        .decrypt(XNonce::from_slice(&envelope.nonce_master), envelope.enc_dek.as_slice())
        .map_err(|_| anyhow!("failed to decrypt DEK"))?;

    let (data_key, _) = derive_data_key(&dek)?;
    let data_cipher = XChaCha20Poly1305::new(&data_key.into());
    let plaintext = data_cipher
        .decrypt(XNonce::from_slice(&envelope.nonce_data), envelope.ciphertext.as_slice())
        .map_err(|_| anyhow!("failed to decrypt data"))?;

    Ok(plaintext)
}

pub fn decrypt_file_streaming(
    input: &Path,
    output: &Path,
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<()> {
    let input_file = File::open(input)?;
    let output_file = File::create(output)?;
    let mut reader = BufReader::new(input_file);
    let mut writer = BufWriter::new(output_file);

    let header = read_stream_header(&mut reader)?;
    if header.version != STREAM_VERSION {
        return Err(anyhow!("unsupported stream version"));
    }

    let (kek, _) = derive_kek(master_key)?;
    let kek_cipher = XChaCha20Poly1305::new(&kek.into());
    let dek = kek_cipher
        .decrypt(XNonce::from_slice(&header.nonce_master), header.enc_dek.as_slice())
        .map_err(|_| anyhow!("failed to decrypt DEK"))?;

    let data_key = derive_data_key_only(&dek)?;
    let data_cipher = XChaCha20Poly1305::new(&data_key.into());

    while let Some(nonce) = read_nonce_or_eof(&mut reader)? {
        let ct_len = read_u32(&mut reader)? as usize;
        let mut ciphertext = vec![0u8; ct_len];
        reader.read_exact(&mut ciphertext)?;
        let plaintext = data_cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| anyhow!("failed to decrypt chunk"))?;
        writer.write_all(&plaintext)?;
    }

    writer.flush()?;
    Ok(())
}

pub fn decrypt_file_auto(
    input: &Path,
    output: &Path,
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<()> {
    let version = read_version_from_file(input)?;
    if version == STREAM_VERSION {
        decrypt_file_streaming(input, output, master_key)
    } else if version == VERSION {
        let encrypted = std::fs::read(input)?;
        let envelope = decode_envelope(&encrypted)?;
        let plaintext = decrypt_bytes(&envelope, master_key)?;
        std::fs::write(output, plaintext)?;
        Ok(())
    } else {
        Err(anyhow!("unsupported file version"))
    }
}

pub fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&envelope.nonce_master);
    out.extend_from_slice(&(envelope.enc_dek.len() as u32).to_be_bytes());
    out.extend_from_slice(&envelope.enc_dek);
    out.extend_from_slice(&envelope.nonce_data);
    out.extend_from_slice(&(envelope.ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(&envelope.ciphertext);
    out
}

pub fn decode_envelope(data: &[u8]) -> Result<Envelope> {
    if data.len() < MAGIC.len() + 1 + NONCE_LEN + 4 + NONCE_LEN + 8 {
        return Err(anyhow!("envelope too short"));
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("invalid magic"));
    }

    let version = data[MAGIC.len()];
    if version != VERSION {
        return Err(anyhow!("unsupported version"));
    }

    let mut idx = MAGIC.len() + 1;
    let nonce_master: [u8; NONCE_LEN] = data[idx..idx + NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("invalid master nonce"))?;
    idx += NONCE_LEN;

    let enc_dek_len = u32::from_be_bytes(
        data[idx..idx + 4]
            .try_into()
            .map_err(|_| anyhow!("invalid DEK length"))?,
    ) as usize;
    idx += 4;

    if data.len() < idx + enc_dek_len + NONCE_LEN + 8 {
        return Err(anyhow!("invalid envelope size"));
    }

    let enc_dek = data[idx..idx + enc_dek_len].to_vec();
    idx += enc_dek_len;

    let nonce_data: [u8; NONCE_LEN] = data[idx..idx + NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("invalid data nonce"))?;
    idx += NONCE_LEN;

    let ciphertext_len = u64::from_be_bytes(
        data[idx..idx + 8]
            .try_into()
            .map_err(|_| anyhow!("invalid ciphertext length"))?,
    ) as usize;
    idx += 8;

    if data.len() < idx + ciphertext_len {
        return Err(anyhow!("invalid ciphertext length"));
    }

    let ciphertext = data[idx..idx + ciphertext_len].to_vec();

    Ok(Envelope {
        nonce_master,
        enc_dek,
        nonce_data,
        ciphertext,
    })
}

fn generate_dek() -> [u8; DEK_LEN] {
    let mut dek = [0u8; DEK_LEN];
    OsRng.fill_bytes(&mut dek);
    dek
}

fn derive_kek(master: &[u8; MASTER_KEY_LEN]) -> Result<([u8; DEK_LEN], [u8; NONCE_LEN])> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut key = [0u8; DEK_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(b"decure-kek", &mut key)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    hk.expand(b"decure-kek-nonce", &mut nonce)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok((key, nonce))
}

fn derive_data_key(dek: &[u8]) -> Result<([u8; DEK_LEN], [u8; NONCE_LEN])> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut key = [0u8; DEK_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(b"decure-data", &mut key)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    hk.expand(b"decure-data-nonce", &mut nonce)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok((key, nonce))
}

fn derive_data_key_only(dek: &[u8]) -> Result<[u8; DEK_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut key = [0u8; DEK_LEN];
    hk.expand(b"decure-data", &mut key)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(key)
}

struct StreamHeader {
    version: u8,
    nonce_master: [u8; NONCE_LEN],
    enc_dek: Vec<u8>,
    _chunk_size: u32,
}

fn write_stream_header(
    writer: &mut impl Write,
    nonce_master: &[u8; NONCE_LEN],
    enc_dek: &[u8],
    chunk_size: u32,
) -> Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[STREAM_VERSION])?;
    writer.write_all(nonce_master)?;
    writer.write_all(&(enc_dek.len() as u32).to_be_bytes())?;
    writer.write_all(enc_dek)?;
    writer.write_all(&chunk_size.to_be_bytes())?;
    Ok(())
}

fn read_stream_header(reader: &mut impl Read) -> Result<StreamHeader> {
    let mut magic = [0u8; 6];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("invalid magic"));
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;

    let mut nonce_master = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce_master)?;

    let enc_dek_len = read_u32(reader)? as usize;
    let mut enc_dek = vec![0u8; enc_dek_len];
    reader.read_exact(&mut enc_dek)?;

    let chunk_size = read_u32(reader)?;

    Ok(StreamHeader {
        version: version[0],
        nonce_master,
        enc_dek,
        _chunk_size: chunk_size,
    })
}

fn read_version_from_file(path: &Path) -> Result<u8> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 6];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("invalid magic"));
    }
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;
    Ok(version[0])
}

fn read_nonce_or_eof(reader: &mut impl Read) -> Result<Option<[u8; NONCE_LEN]>> {
    let mut first = [0u8; 1];
    let read = reader.read(&mut first)?;
    if read == 0 {
        return Ok(None);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0] = first[0];
    reader.read_exact(&mut nonce[1..])?;
    Ok(Some(nonce))
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn split_and_reconstruct() {
        let master = generate_master_key();
        let shares = split_master_key(&master, 5).expect("split");
        let recovered = reconstruct_master_key(&shares).expect("reconstruct");
        assert_eq!(master, recovered);
    }

    #[test]
    fn encrypt_roundtrip() {
        let master = generate_master_key();
        let msg = b"hello secure world";
        let env = encrypt_bytes(msg, &master).expect("encrypt");
        let plaintext = decrypt_bytes(&env, &master).expect("decrypt");
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn streaming_roundtrip() {
        let master = generate_master_key();
        let dir = tempdir().expect("tempdir");
        let input_path = dir.path().join("input.bin");
        let output_path = dir.path().join("output.bin");
        let decrypted_path = dir.path().join("decrypted.bin");

        let mut input_file = File::create(&input_path).expect("create input");
        input_file
            .write_all(b"streaming data block")
            .expect("write input");

        encrypt_file_streaming(&input_path, &output_path, &master, 8).expect("encrypt streaming");
        decrypt_file_streaming(&output_path, &decrypted_path, &master)
            .expect("decrypt streaming");

        let decrypted = std::fs::read(&decrypted_path).expect("read decrypted");
        assert_eq!(decrypted, b"streaming data block");
    }
}
