# Technical Report: Blockchain-Based Library Book Lending Tracker

## 1. Introduction

The Library Book Lending Tracker is a command-line C application that records book loans as an append-only chain of signed events. It replaces a mutable lending table with an ordered history containing both the current transaction and the cryptographic evidence needed to detect later modification.

The system has three kinds of input data:

- `books.txt` is the book registry, containing a book ID, title, and author.
- `members.txt` is the member registry, containing a member ID, name, and course code.
- `users.txt` contains librarian usernames and SHA-256 password hashes.

The application loads and validates the registries, authenticates a librarian, loads or creates the ledger, validates the existing chain, and then accepts lending commands. A successful borrow or return becomes one new block. The project is intentionally a single-node educational implementation: it demonstrates hashing, digital signatures, chaining, persistence, and validation without claiming to provide distributed consensus.

## 2. Requirements and scope

The implemented scope is:

1. Load a non-empty book and member registry at startup.
2. Authenticate a librarian before opening the command loop.
3. Accept only registered book and member IDs.
4. Prevent a second active loan for the same book.
5. Prevent a return when the book has no active loan.
6. Sign and hash each accepted transaction.
7. Persist the chain and reload it on a later execution.
8. Detect modified block data, broken links, and invalid signatures.
9. Provide `view`, `validate`, and `tamper` commands for inspection and demonstration.

The command interface is:

```text
borrow BOOK_ID MEMBER_ID
return BOOK_ID MEMBER_ID
view
validate
tamper
help
quit
```

## 3. System design diagram

The diagram below shows how the registries connect to the authenticated attendance/lending flow. In this project, “attendance flow” is represented by the member participation in a borrow or return event; each event records a member snapshot inside the ledger block.

```mermaid
flowchart LR
	B[books.txt] --> BR[BookRegistry array]
	M[members.txt] --> MR[MemberRegistry array]
	U[users.txt] --> AU[SHA-256 credential lookup]
	AU --> CLI[Authenticated CLI loop]
	BR --> LOOKUP[Book and member validation]
	MR --> LOOKUP
	CLI --> LOOKUP
	LOOKUP --> STATE{Loan state check}
	STATE -->|borrow: available| TX[Create transaction block]
	STATE -->|return: active loan| TX
	TX --> SIG[ECDSA P-256 signature]
	SIG --> HASH[SHA-256 current hash]
	HASH --> APPEND[Append to Chain array]
	APPEND --> SAVE[Atomic save: blockchain.dat.tmp -> blockchain.dat]
	SAVE --> LINK[Next block reads previous hash]
	CLI --> VIEW[view: records and signature status]
	CLI --> VALIDATE[validate: hash, link, signature checks]
	CLI --> TAMPER[tamper: alter memory for demonstration]
	VALIDATE --> RESULT[VALID or INVALID result]

	subgraph Chain[Linked blockchain]
		G[Genesis block\nindex 0, previous hash = 64 zeros]
		C1[Transaction block n\nprevious_hash = hash(n-1)]
		C2[Transaction block n+1\nprevious_hash = hash(n)]
		G --> C1 --> C2
	end
	APPEND --> C1
```

### 3.1 Block structure

Each block is stored as a fixed-size C structure:

| Field | Type | Purpose |
|---|---|---|
| `index` | `int` | Position in the chain; genesis is 0. |
| `timestamp` | `time_t` | Time at which the event block was created. |
| `book_id` | `char[20]` | Stable identifier from the book registry. |
| `book_title` | `char[80]` | Snapshot of the title at transaction time. |
| `member_id` | `char[20]` | Stable identifier from the member registry. |
| `member_name` | `char[50]` | Snapshot of the member name at transaction time. |
| `action` | `char[10]` | `BORROWED`, `RETURNED`, or `GENESIS`. |
| `previous_hash` | `char[65]` | Lowercase hexadecimal SHA-256 hash of the preceding block. |
| `signature` | `unsigned char[72]` | DER-encoded ECDSA signature. |
| `signature_len` | `unsigned int` | Number of valid signature bytes. |
| `hash` | `char[65]` | Current block hash in hexadecimal form. |

The genesis block is created when no ledger exists. Its index is 0 and its `previous_hash` contains 64 zero characters. Transaction blocks are appended at the next index, copy the previous block hash, and retain book/member details as historical snapshots. This means later changes to registry display text do not rewrite historical events.

### 3.2 Transaction algorithm

For `borrow BOOK_ID MEMBER_ID`, the application:

1. Searches the in-memory book and member arrays.
2. Examines the latest transaction for that book. A borrow is rejected if the latest state is `BORROWED`.
3. Builds a new block with action `BORROWED`.
4. Signs the canonical transaction fields with the ECDSA private key.
5. Computes the block hash, including the signature.
6. Appends the block to the in-memory chain and saves it.

The return path is equivalent, except it requires the latest state to be `BORROWED` and writes `RETURNED`. The latest-event rule allows a book to be borrowed again after it has been returned while preserving the complete history.

## 4. Security mechanisms

### 4.1 SHA-256 integrity

The implementation creates a deterministic text representation using the fields in this order:

```text
index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signature_hex
```

SHA-256 is applied to this representation and encoded as 64 lowercase hexadecimal characters. The `hash` field itself is excluded to avoid a circular definition. Because `previous_hash` and the signature are included, changing a transaction changes its own hash and also invalidates every later link.

Validation recomputes each block hash and compares it with the stored value. It also checks that each block index equals its array position and that each transaction block points to the exact hash of the preceding block.

### 4.2 ECDSA authentication of transactions

On first execution, OpenSSL generates an elliptic-curve key using the NIST P-256 curve and writes the private key to `signing_key.pem`. The transaction fields up to `previous_hash` are signed using SHA-256 with ECDSA. On validation, OpenSSL verifies the signature using the public component loaded from the same PEM key.

The signature protects the event content from undetected alteration. The block hash and the signature provide different checks: the hash detects changes to persisted bytes, while the signature tests whether the transaction was produced with the configured signing key.

### 4.3 Librarian authentication

The command loop is unavailable until `authenticate()` accepts a username and password. The entered password is hashed with SHA-256 and compared with the hash stored beside the username in `users.txt`. The demonstration credential is `librarian` / `library2026`.

This is suitable only for coursework demonstration. A fast unsalted SHA-256 password hash is vulnerable to offline guessing, and the PEM private key is currently unencrypted. A production version should use Argon2id or bcrypt with a unique salt, an operating-system secret store or HSM for the signing key, rate limiting, and role-based authorization.

## 5. Data persistence approach

### 5.1 Registry files

At startup, `books.txt` and `members.txt` are read line by line. Blank lines and comments are ignored. Each remaining row must contain exactly three non-empty comma-separated fields. The records are copied into bounded arrays with capacities of 500 books and 500 members. Missing, empty, oversized, or malformed registries stop startup.

### 5.2 Ledger file

`blockchain.dat` is a binary file with this layout:

```text
9-byte magic value: LIBCHAIN1
size_t block count
block count fixed-size Block records
```

If the file is missing, the program creates a genesis block and saves it. On load, the magic value, block count, maximum count, and complete block reads are checked before the chain is accepted.

### 5.3 Atomic write behavior

The chain is first written to `blockchain.dat.tmp`. The file is flushed and closed, the old ledger is removed, and the temporary file is renamed to `blockchain.dat`. If writing fails, the temporary file is removed and the in-memory transaction is rolled back. This reduces the chance of leaving a partially written record after a normal write failure, although a power loss between remove and rename remains a limitation of this simple implementation.

## 6. Error handling and validation strategy

The program fails closed at startup when required registries, the signing key, the ledger, or cryptographic operations cannot be used. User-facing validation covers:

| Situation | Result |
|---|---|
| Missing or empty registry | Startup error and exit. |
| Malformed registry row | Startup error and exit. |
| Wrong librarian credentials | Authentication error and exit. |
| Unknown book/member ID | Transaction rejected; no block is created. |
| Borrowing an already-loaned book | Transaction rejected. |
| Returning a book without an active loan | Transaction rejected. |
| Invalid command or argument count | Command error; loop continues. |
| Corrupt ledger header or incomplete read | Ledger error and exit. |
| Hash, link, or signature mismatch | Chain reported as invalid; startup refuses to continue. |
| Failed persistence | Transaction removed from memory and error shown. |

`validate_chain()` checks every block in order. For block 0 it checks the index, hash, and zero previous hash. For every later block it checks the index, recalculated hash, previous-hash link, and ECDSA signature. The `tamper` command changes a member name in block 1 in memory and immediately runs validation, providing a repeatable integrity demonstration without intentionally damaging the saved ledger.

## 7. Screenshots and execution evidence

The following figures should be captured from the running application and inserted into the final Word/PDF version. Each caption identifies the claim demonstrated by the screenshot.

### Figure 1: Startup and authentication

Show the output beginning with `Loaded ... books and ... members.`, the username/password prompts, `Authenticated as librarian.`, and the command list. This demonstrates registry loading and access control.

### Figure 2: Registry and state validation errors

Run `borrow BK999 ALU001` and show `ERROR: Book or Member not found.`. Then run `borrow BK001 ALU002` while BK001 is already active and show `ERROR: book is already on loan.`.

### Figure 3: Successful lending events

Show a successful `borrow BK001 ALU001`, the resulting block number, `return BK001 ALU001`, and the resulting return block. This demonstrates append-only event creation and the state transition from active loan to available.

### Figure 4: Records and cryptographic evidence

Run `view` and capture the block index, timestamp, book title, member name, action, and `signature: VALID` output. Follow it with `validate` showing `Chain validation: VALID`.

### Figure 5: Tamper detection

Run `tamper` and capture `Tampered with block 1 in memory.` followed by the invalid block message and `Chain validation: INVALID`. This demonstrates that changing a signed block is detected by the hash/signature checks.

### Figure 6: Persistence after restart

Exit and restart the application, authenticate again, and run `view`. The earlier records should be present, followed by a valid startup-chain check. This demonstrates that the chain is loaded from `blockchain.dat` rather than held only in memory.

For reproducibility, reset the demonstration by removing `blockchain.dat` and `signing_key.pem` only when a fresh genesis/key pair is required. Do not include the private key in submitted evidence.

## 8. Challenges encountered and solutions

### Avoiding a circular hash

A block cannot include its own final hash as an input to that same hash. The solution is to hash every persisted block field except `hash`. The signature is included, so a changed signature also changes the block hash.

### Preserving historical meaning

A transaction stores both IDs and readable book/member snapshots. This avoids making old records dependent on a future registry lookup and keeps the audit history understandable if display names change later.

### Enforcing loan state without a mutable loan table

The system derives the current loan state by scanning backwards for the latest event for a book. This keeps the ledger append-only: a return is another event, not an update to the original borrow row.

### Demonstrating tamper detection safely

The `tamper` command edits a block only in memory and does not save it. It therefore demonstrates detection without permanently destroying the demonstration ledger or requiring manual binary-file editing.

### Handling persistence failures

Transactions are added in memory only after cryptographic creation succeeds. If the subsequent save fails, the chain count is decremented so the failed transaction is not treated as committed by the current process. Temporary-file writing and rename further reduce partial-write risk.

## 9. Testing and expected results

The following manual test matrix covers the principal behavior:

| Test | Command or condition | Expected result |
|---|---|---|
| First run | Start with no `blockchain.dat` | Genesis is created and chain is valid. |
| Login success | `librarian` / `library2026` | Command loop opens. |
| Login failure | Incorrect password | Startup exits with authentication error. |
| Unknown IDs | `borrow BK999 ALU001` | No block is added. |
| Duplicate borrow | Borrow BK001 twice | Second command is rejected. |
| Invalid return | Return available BK002 | Command is rejected. |
| Normal lifecycle | Borrow BK001, return BK001, borrow BK001 | Three valid transaction events are appended. |
| Integrity check | `validate` | Valid chain is reported. |
| Tamper check | `tamper`, then `validate` | Invalid chain is reported in memory. |
| Reload check | Restart and run `view` | Previously saved events remain available. |

## 10. Limitations and future work

This is a local, single-process ledger, not a distributed blockchain. Anyone who can replace both `blockchain.dat` and `signing_key.pem` can create a new internally consistent history, and the current key file is not encrypted. The binary format is platform-dependent because it writes native C structure layout and `size_t`; it is not a portable interchange format. The implementation also has fixed array limits, no concurrent-writer protection, no backup rotation, and no replicated consensus.

Recommended production improvements are:

- Store credentials using Argon2id/bcrypt and protect the signing key with an HSM or OS keystore.
- Add key rotation and a trusted public-key distribution mechanism.
- Use a versioned, explicitly serialized file format with fixed-width integer types and checksums.
- Add authenticated roles, audit logs, backups, and recovery procedures.
- Use file locking or a database transaction for concurrent writers.
- Replicate the ledger between trusted library nodes and use an agreed consensus protocol.

## 11. Conclusion

The project demonstrates the essential mechanics of a tamper-evident lending ledger. Registry validation establishes which books and members may participate, authentication gates the command interface, ECDSA authenticates each event, SHA-256 links the events, and binary persistence preserves the chain across executions. The `validate` and `tamper` commands make the integrity model observable. Its deliberate limitations also define the boundary between a clear educational prototype and a production library system.
