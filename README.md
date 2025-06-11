# VaultCommandier

A minimal Rust CLI utility for logging in to a Bitwarden/Vaultwarden server and decrypting your vault items.

## Features

- Logs in using email and password (client-side KDF, Vaultwarden compatible)
- Only retrieves vault items (no vault editing or sharing)
- Decrypts login passwords using the Bitwarden crypto protocol

## Usage

1. **Edit Credentials:**  
   Edit `src/main.rs` and replace `email`, `password`, and `server` variables at the top of `main()` with your credentials and Vaultwarden server URL.

2. **Build and Run:**

    ```sh
    cargo build --release
    ./target/release/vaultcommander
    ```

3. The decrypted logins will be printed to stdout.

## Security Notice

- **Never share your password or decrypted vault data.**
- This is for educational purposes. Use at your own risk, which is part of
  the education.

## Contributing

See `CONTRIBUTING.md`.

## Code of Conduct

See `CODE_OF_CONDUCT.md`.

## Security Policy

See `SECURITY.md`.

## License

GPLv3+
