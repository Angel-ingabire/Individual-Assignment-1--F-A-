# Library Lending Blockchain Tracker

A C11 library-lending ledger with ECDSA-signed records, copy-level inventory, FIFO reservations, Merkle-rooted multi-record blocks, SHA-256 proof-of-work, and selectable UTXO or account-based token accounting.

## Features

- Loads `books.txt`, `copies.txt`, and `members.txt` into validated in-memory registries at startup.
- Reads librarian credentials from `users.txt` as SHA-256 password hashes.
- Rejects unknown or malformed book, copy, and member IDs before creating a record.
- Tracks each physical copy, its condition, state, holder, due date, and renewals.
- Queues borrowing, returning, renewing, reserving, overdue, lost-copy, and copy-condition records before confirmation.
- Queues signed token transfers and fine-settlement records for mining confirmation.
- Automatically assigns a returned copy to the earliest reservation; a reservation holder may then borrow that offered copy.
- Mines up to eight signed lending records per block, ordered by overdue priority and then request time.
- Computes a SHA-256 leaf hash for each record and builds each block's Merkle tree from scratch; validation recomputes every root.
- Persists the chain, copy states, reservation queue, and pending requests in `blockchain.dat` and `library_state.dat`.
- Persists mining difficulty and the configured block reward in `chain_metadata.dat`; a `--difficulty` argument overrides the stored difficulty for that run and updates it.
- Persists each selected token model's balances, account nonces, UTXOs, transaction sequence, and transaction history in its own model-specific token-state file.
- Revalidates the on-disk chain when `validate` is run; after a failed validation, the CLI blocks other commands until validation succeeds. Startup also checks persisted copy states against the latest confirmed and pending lending records.
- Returns earn 10 gross tokens when returned by the recorded due date, or 5 gross tokens late. A 1-token transaction fee is deducted. Overdue records accrue one fine coin per day; an unreturned loan earns no reward.
- Signs ordinary member lending and token-transfer records with member-specific ECDSA P-256 keys. The corresponding private keys are stored in `member_<ID>_key.pem` and public keys in `member_<ID>_public.pem`. `LOST` and `CONDITION` overrides are signed with the authenticated librarian key. Migrated records retain their legacy verification compatibility.
- Each mined block hash covers the signed-record Merkle root, reward metadata, proof-of-work data, and header.
- Supports solo mining, simulated pooled mining, and multi-round cloud rental, with payouts to explicit registered members.
- Credits solo and cloud mining rewards, and allocates pool rewards by measured proof-of-work attempts after the 2% pool fee. Fractional mining shares are persisted per member and become whole spendable coins when accumulated.
- Reconstructs confirmed lending rewards from the chain and restores saved transfers, mining payouts, balances, account nonces, UTXOs, and history on restart.
- Migrates existing `LIBCHAIN1`, `LIBCHAIN2`, and `LIBCHAIN3` ledgers to the current `LIBCHAIN4` format at startup, re-signing and mining historical records.
- Provides a `tamper` command that alters a temporary in-memory chain copy and demonstrates validation failure without corrupting the saved ledger.
- Flags excessive concurrent borrowing and re-borrowing the same title within 24 hours of a confirmed return. Suspicious requests remain out of mining until explicitly approved or rejected.
- Flags condition downgrades greater than one level unless the reason begins with `OVERRIDE:`; review decisions are persisted.
- Supports member/book registration, nonce queries, fine reports, and lending/member/book history views.
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

The first run creates `signing_key.pem`, member-specific signing keys, and `blockchain.dat`. Keep all private keys confidential; replacing a key makes its signatures unverifiable. Difficulty accepts 1 through 4 leading zero hex characters; difficulty 2 is the default. Choose the token model at startup with `--model utxo` or `--model account`.

Demo credentials: `librarian` / `library2026`.

`users.txt` stores `username,password_sha256`; replace the sample password outside a demonstration.

## CLI commands

```text
borrow BK001 ALU001 [BK001-C01]
return BK001 ALU001 [BK001-C01]
reserve BK001 ALU002
renew BK001-C01 ALU001
overdue
copies
copy BK001-C01
reservations
view_book BK001
add_copy BK001-C03 BK001 GOOD
mark_lost BK001-C01 ALU001 LOST-REPORT-01
set_condition BK001-C01 ALU001 WORN CONDITION-REPORT-01
register_member ALU004 New_Member CS1
register_book BK004 New_Title New_Author
pending
fraud_review
approve_suspicious REQUEST_ID
mine solo ALU001
mine pool ALU001 ALU002 [ALU003 [ALU004]]
mine cloud 3 ALU001
balances
utxos
transfer ALU001 ALU002 2 0
history ALU001
member_history ALU001
book_history BK001
view_fines
settle_fine ALU001 BK001-C01 2
view
validate
chain_save
chain_load
member_nonce ALU001
member_key ALU001
difficulty_status
set_difficulty 3
tamper
help
quit
```

Convenience aliases are `mine_solo MEMBER`, `mine_pool MINER1 MINER2`, and
`mine_cloud ROUNDS MEMBER`.

Solo and pool mine all currently pending events. Solo and cloud require one registered member ID to receive payouts; pool requires two to four distinct registered miner IDs. Each newly mined solo block credits its selected member 2 coins. Pool payouts are allocated by measured hash-attempt contribution from the 2-coin block reward after the 2% pool fee. Fractional shares are accumulated per recipient in the persisted token snapshot and become spendable as whole coins when they sum to at least one coin. Cloud mining requires a duration from 1 to 5 rounds, credits 2 gross coins per round to the selected member, and reports 2 rental plus 1 maintenance coin per round as operating costs; with these example rates the net is negative and a warning is displayed. Rental and maintenance costs are a simulation expense, not a token debit.

The account model starts each member at balance zero and nonce zero. Supply the sender's next account nonce on `transfer`; `balances` prints it. UTXO mode requires nonce `0`. Transfers are signed, enter the shared pending pool, and update balances only when mined. Every transfer has a 1-token fee and is rejected for insufficient available funds, unknown IDs, or a reused/incorrect account nonce. In the UTXO model, confirmation consumes enough sender outputs, pays the same fee, and returns any excess as change. `utxos` displays all currently unspent outputs. `history MEMBER_ID` prints the selected member's persisted transaction history. Model-specific token state is bound to the saved chain tip; startup stops on a corrupt or mismatched state file rather than silently discarding balances/history.

## Configuration and testing

Install GCC with C11 support and the OpenSSL 3 development headers and `libcrypto` library. For the Makefile build, install `make` as well. For the CMake build, install CMake 3.20 or newer and Ninja if using the commands below. The MSYS2 UCRT64 installation command is listed under [Dependencies](#dependencies).

Build with either supported method:

```sh
make
```

or:

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

Choose the transaction model and proof-of-work difficulty when starting the program. The model remains active for that process; difficulty is the required number of leading zero hexadecimal characters in a block hash and must be from 1 to 4.

```sh
./library_tracker --model utxo --difficulty 2
./library_tracker --model account --difficulty 4
```

`set_difficulty 1-4` changes and persists difficulty during a session. `difficulty_status` displays the active difficulty and block reward. Fine settlement is entered as `settle_fine MEMBER_ID COPY_ID AMOUNT`; the signed payment is pending until a block is mined. Amounts are limited to the oldest unsettled fine for that copy; submit additional settlements for later fine periods separately. `set_condition COPY_ID MEMBER_ID NEW|GOOD|WORN REASON_CODE` queues a signed condition change. A multi-level downgrade is held as suspicious unless the reason starts with `OVERRIDE:`.

To test mining, log in and queue at least one lending event before running a mining command. Replace the example IDs with an available book and registered member if the example book is already on loan:

```text
borrow BK001 ALU001
pending
mine solo ALU001
view
```

`mine solo ALU001` confirms ordinary pending records, prints hash attempts and credits ALU001 with the solo mining reward after the chain is persisted. A block contains up to eight records. To test the other mining simulations, queue another valid event before each command:

```text
return BK001 ALU001
mine pool ALU001 ALU002
borrow BK002 ALU002
mine cloud 3 ALU003
```

Pool mode requires two to four distinct registered members and displays each member's attempts, contribution percentage, and credited share after the 2% pool fee. Cloud mode accepts 1 to 5 rounds plus a registered payout member; it credits gross earnings and displays rental and maintenance costs, cumulative net earnings, and any unprofitable-round warnings. Finish by checking `balances`, `utxos` (UTXO mode), `history MEMBER_ID`, and `validate`.

To compare transaction models, exit and restart with the other `--model` value. Each model restores its own saved balances, mined transfers, UTXO/account nonce state, and transaction histories; confirmed return rewards and transfers for that model are reconstructed from the chain when its model-specific snapshot is missing. Run the application from the project directory so it can find registry and ledger/key files.

Mining payout recipients and pool contribution details are stored in the model-specific token snapshot, not in block headers. If a token snapshot is deleted, return rewards and transfers can be replayed from the chain, but mining payouts cannot be reconstructed from the chain alone.

`copies.txt` uses `copy_id,book_id,condition`, with condition `NEW`, `GOOD`, `WORN`, or `LOST`. The sample data includes multiple copies for some titles. `library_state.dat` preserves runtime copy changes, reservations, and pending requests across restarts. The fixed renewal period is 14 days and the maximum is two renewals per loan; adjust `RENEWAL_PERIOD_SECONDS` and `MAX_RENEWALS` in `src/main.c` to configure those policy values.

Suggested demonstration:

1. Log in and run `borrow BK001 ALU001`.
2. Run `pending`, then try `borrow BK001 ALU002` to show the active-loan rejection.
3. Run `mine_solo ALU001` (or `mine solo ALU001`) and `view`; the borrow is now confirmed.
4. Run `return BK001 ALU001`, inspect `pending`, and verify `balances` is unchanged before mining.
5. Run `mine_pool ALU001 ALU002` (or `mine_cloud 3 ALU003`), then inspect `view`, `balances`, and `utxos`.
6. Use `borrow BK999 ALU001` to show registry validation, and `overdue BK001` to show that an unreturned overdue book creates no reward transaction.
7. For account validation, restart with `--model account`, test `transfer ALU001 ALU002 2 0` before and after a confirmed reward, inspect that balances remain unchanged while it is pending, mine it, then repeat the nonce to demonstrate rejection.
8. Run `tamper` to demonstrate integrity failure on a temporary chain copy, then run `validate` to confirm the saved chain remains valid.

See [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for architecture, implementation scope, security design, and tested scenarios. Screenshots in `screenshots/` provide CLI-output evidence. A demo video must be recorded separately.

## Persistence and integrity model

`blockchain.dat` stores a magic value, block count, and fixed-size block headers with up to eight signed records. A record's ID is the SHA-256 hash of its identity fields; its signature covers its full canonical fields. The block Merkle root hashes record leaves pairwise, duplicating the final leaf at odd tree levels. Validation recomputes each signature, record ID, Merkle root, block hash, proof-of-work prefix, timestamp ordering, and previous-hash link. `library_state.dat` stores copy state, reservations, and the signed pending pool. Writes use a temporary file followed by rename. The genesis block uses 64 zero characters as `previous_hash`.

This is an educational local ledger, not a distributed consensus network. In a production system, private keys would be protected by an HSM or OS keystore, credentials would not be hard-coded, and multiple peers would replicate and agree on the chain.

## Files

- `src/main.c`: implementation
- `books.txt`: sample book registry
- `copies.txt`: sample copy inventory
- `members.txt`: sample member registry
- `users.txt`: sample hashed librarian credential
- `member_<ID>_key.pem`: generated member private key (ignored by git)
- `member_<ID>_public.pem`: generated member public key (ignored by git)
- `token_state_*.dat`: model-specific persistent token ledger snapshots (ignored by git)
- `DESIGN.md`: system design diagram and data flow
- `TECHNICAL_REPORT.docx`: implementation, model comparison, mining methodology, tests, and evidence captures
- `screenshots/`: rendered CLI-output evidence images embedded in the report
- `Makefile`: build and clean targets
