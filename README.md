# Decure (local MVP)

Local MVP for secure encryption with XOR shares. All shares are required to reconstruct the master key.

## Features
- XChaCha20‑Poly1305 (AEAD)
- HKDF‑SHA256 for key derivation
- XOR split for shares (no threshold)
- Chunked streaming for large files
- Server simulation for share storage
- CLI: encrypt / decrypt / rotate

## Requirements
- Rust + Cargo (https://www.rust-lang.org/tools/install)

## Quick start

### Encrypt
Writes the encrypted file and generates shares in a folder.

```powershell
cargo run -- encrypt --input .\plain.txt --output .\sealed.bin --shares-dir .\shares --shares 15
```

With custom chunk size (bytes):

```powershell
cargo run -- encrypt --input .\plain.txt --output .\sealed.bin --shares-dir .\shares --shares 15 --chunk-size 1048576
```

### Decrypt
Reconstructs the master key from all shares and decrypts the file.

```powershell
cargo run -- decrypt --input .\sealed.bin --output .\plain.out.txt --shares-dir .\shares
```

### Rotate (key rotation)
Re-encrypts the data with a new master key and writes new shares.

```powershell
cargo run -- rotate --input .\sealed.bin --output .\sealed.new.bin --old-shares-dir .\shares --new-shares-dir .\shares_new --shares 15

## Server simulation for shares
Instead of a single shares directory, you can distribute shares across multiple
local “server” folders under a root path.

### Encrypt with servers

```powershell
cargo run -- encrypt --input .\plain.txt --output .\sealed.bin --servers-root .\servers --servers 5 --shares 15
```

This creates folders like `servers\server_00`, `servers\server_01`, etc.

### Decrypt with servers

```powershell
cargo run -- decrypt --input .\sealed.bin --output .\plain.out.txt --servers-root .\servers
```

### Rotate with servers

```powershell
cargo run -- rotate --input .\sealed.bin --output .\sealed.new.bin --old-servers-root .\servers --new-servers-root .\servers_new --servers 5 --shares 15
```
```

## Tests

```powershell
cargo test
```

## Notes
- Without all shares, decryption is impossible.
- Shares are sensitive, store them securely. :P
- This repo is an **MVP for file/blob encryption**.
- The MVP uses chunked streaming to avoid loading full files into memory.
