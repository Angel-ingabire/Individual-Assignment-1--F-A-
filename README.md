# Library Lending Blockchain Tracker

A C11 library-lending ledger with ECDSA-signed lending events, a pending block pool, SHA-256 proof-of-work, and selectable UTXO or account-based token accounting.

## Features

- Loads `books.txt` and `members.txt` into validated in-memory registries at startup.
- Reads librarian credentials from `users.txt` as SHA-256 password hashes.
- Rejects unknown book and member IDs before creating a transaction.
- Queues borrowing and returning events. Lending records and reward balances are confirmed only after mining.
- Keeps the pending pool in memory; mine pending events before quitting or they will be discarded.
- Returns earn 10 gross tokens within 14 days of borrowing, or 5 gross tokens afterward. A 1-token transaction fee is deducted, so the member receives 9 or 4 tokens. No reward transaction is created for an unreturned overdue book.
- Signs lending fields with ECDSA P-256. Each mined block hash covers the signature, reward, reward transaction ID, difficulty, and nonce.
- Supports solo mining, simulated pooled mining, and multi-round cloud rental.
- Reconstructs confirmed member rewards from the persisted chain at startup. Manual token transfers/history are in-memory demonstrations and are not persisted.
- Migrates existing `LIBCHAIN1` ledgers to the expanded format at startup, re-signing and mining historical lending blocks at difficulty 2.
- Provides a `tamper` command that changes block data in memory and demonstrates validation failure.
- Uses a librarian login for CLI access.

## Dependencies

- GCC with C11 support
- OpenSSL 3 development headers and library (`libcrypto`)

On MSYS2 MinGW64:

```sh
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

For the current MSYS2 UCRT64 environment, use:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja make
```

Use the **MSYS2 UCRT64** terminal so `gcc` can find OpenSSL.

On Windows PowerShell, install the same prerequisites with an administrator-enabled package manager, or install MSYS2 and use its **MinGW 64-bit** terminal. The compiler alone is not sufficient: the OpenSSL development package must provide both `openssl/*.h` and `libcrypto`.

## Build and run

```sh
make
./library_tracker --model utxo --difficulty 2
```

Alternatively, with CMake:

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/library_tracker --model account --difficulty 2
```

On Windows, run `library_tracker.exe` from PowerShell or the MinGW terminal. Run it from the project directory so the registry and ledger files are found.

The first run creates `signing_key.pem` and `blockchain.dat`. Keep the private key confidential; replacing it makes existing signatures unverifiable. Difficulty accepts 1 through 4 leading zero hex characters; difficulty 2 is the default. Choose the token model at startup with `--model utxo` or `--model account`.

Demo credentials: `librarian` / `library2026`.

`users.txt` stores `username,password_sha256`; replace the sample password outside a demonstration.

## CLI commands

```text
borrow BK001 ALU001
return BK001 ALU001
pending
mine solo
mine pool
mine cloud 3
balances
utxos
transfer ALU001 ALU002 2 0
history ALU001
view
validate
tamper
help
quit
```

Solo and pool mine all currently pending events. Cloud mining requires a duration from 1 to 5 rounds. The simulated block mining reward is 2 coins; pool rewards are allocated by each miner's share of hash attempts after a 2% pool fee. Cloud simulation earns 2 coins and charges 2 rental coins plus 1 maintenance coin per round, so it demonstrates an unprofitable rental at these example rates.

The account model starts each member at balance zero and nonce zero. Supply the sender's next nonce on `transfer`; `balances` prints it. Every transfer has a 1-token fee and is rejected for insufficient funds, unknown IDs, or a reused/incorrect nonce. In the UTXO model, transfers consume enough sender outputs, pay the same fee, and return any excess as change. `utxos` displays all currently unspent outputs. `history MEMBER_ID` prints the selected member's in-memory transaction history.

Suggested demonstration:

1. Log in and run `borrow BK001 ALU001`.
2. Run `pending`, then try `borrow BK001 ALU002` to show the active-loan rejection.
3. Run `mine solo` and `view`; the borrow is now confirmed.
4. Run `return BK001 ALU001`, inspect `pending`, and verify `balances` is unchanged before mining.
5. Run `mine pool` (or `mine cloud 3`), then inspect `view`, `balances`, and `utxos`.
6. Use `borrow BK999 ALU001` to show registry validation, and `overdue BK001` to show that an unreturned overdue book creates no reward transaction.
7. For account validation, restart with `--model account`, test `transfer ALU001 ALU002 2 0` before and after a confirmed reward, then repeat the nonce to demonstrate rejection.
8. Run `validate`; use `tamper` followed by `validate` to demonstrate integrity failure.

The submitted [technical report](TECHNICAL_REPORT.docx) includes test results and five rendered CLI-output captures from isolated executable runs. They show pending/solo confirmation, pool rewards and UTXOs, account nonce/history behavior, cloud rental loss, and the late-return/migration path. These are captures of actual standard output, not desktop photographs. Edge cases include insufficient funds, reused nonce, spent UTXO reuse, an unreturned loan, and unprofitable cloud rental.

## Persistence and integrity model

`blockchain.dat` stores a magic value, block count, and fixed-size `Block` records. A pending event is signed when queued; when mined, its index and previous hash are assigned, it is re-signed, and its nonce is searched until the hash begins with the configured zero prefix. The confirmed chain is persisted before rewards are applied to the active ledger. A reward transaction ID is the SHA-256 hash of the member, book, action, gross reward, fixed fee, and event timestamp. The block hash excludes its own hash field to avoid a circular value. The genesis block uses 64 zero characters as `previous_hash`.

This is an educational local ledger, not a distributed consensus network. In a production system, private keys would be protected by an HSM or OS keystore, credentials would not be hard-coded, and multiple peers would replicate and agree on the chain.

## Files

- `src/main.c`: implementation
- `books.txt`: sample book registry
- `members.txt`: sample member registry
- `users.txt`: sample hashed librarian credential
- `DESIGN.md`: system design diagram and data flow
- `TECHNICAL_REPORT.docx`: implementation, model comparison, mining methodology, tests, and evidence captures
- `screenshots/`: rendered CLI-output evidence images embedded in the report
- `Makefile`: build and clean targets
