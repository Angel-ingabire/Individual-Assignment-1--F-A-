# Library Lending Blockchain Tracker

A C implementation of an append-only library lending ledger. Each borrow and return event is a block linked with SHA-256 and authenticated with an ECDSA P-256 signature.

## Features

- Loads `books.txt` and `members.txt` into validated in-memory registries at startup.
- Reads librarian credentials from `users.txt` as SHA-256 password hashes.
- Rejects unknown book and member IDs before creating a transaction.
- Creates and persists a genesis block followed by signed `BORROWED` and `RETURNED` blocks.
- Prevents a second borrow while a book has an active loan.
- Verifies block hashes, previous-hash links, and ECDSA signatures.
- Provides a `tamper` command that changes block data in memory and demonstrates validation failure.
- Uses a librarian login for CLI access.

## Dependencies

- GCC with C11 support
- OpenSSL 3 development headers and library (`libcrypto`)

On MSYS2 MinGW64:

```sh
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

Use the **MSYS2 MinGW 64-bit** terminal so `gcc` can find OpenSSL.

## Build and run

```sh
make
./library_tracker
```

Alternatively, with CMake:

```sh
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
./build/library_tracker
```

On Windows, run `library_tracker.exe` from PowerShell or the MinGW terminal. Run it from the project directory so the registry and ledger files are found.

The first run creates `signing_key.pem` and `blockchain.dat`. Keep the private key confidential; replacing it makes existing signatures unverifiable.

Demo credentials: `librarian` / `library2026`.

`users.txt` stores `username,password_sha256`; replace the sample password outside a demonstration.

## CLI commands

```text
borrow BK001 ALU001
return BK001 ALU001
view
validate
tamper
help
quit
```

Suggested demonstration:

1. Log in and run `borrow BK001 ALU001`.
2. Run `borrow BK001 ALU002` to show the active-loan rejection.
3. Run `borrow BK999 ALU001` to show registry validation.
4. Run `view` and `validate`.
5. Run `tamper`, then `validate` to show the broken hash/link.
6. Restart the program and run `view` to show persistence.
7. Run `return BK001 ALU001`, then `validate` again.

## Persistence and integrity model

`blockchain.dat` stores a magic value, block count, and fixed-size `Block` records. A block hash is SHA-256 over its canonical fields and signature. A signature is created over the canonical transaction fields before the block hash is computed. The hash intentionally excludes the hash field itself to avoid a circular definition. The genesis block uses 64 zero characters as `previous_hash`.

This is an educational local ledger, not a distributed consensus network. In a production system, private keys would be protected by an HSM or OS keystore, credentials would not be hard-coded, and multiple peers would replicate and agree on the chain.

## Files

- `src/main.c`: implementation
- `books.txt`: sample book registry
- `members.txt`: sample member registry
- `users.txt`: sample hashed librarian credential
- `DESIGN.md`: system design diagram and data flow
- `REPORT.md`: technical report scaffold
- `Makefile`: build and clean targets
