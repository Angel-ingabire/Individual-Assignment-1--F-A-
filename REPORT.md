# Technical Report: Blockchain-Based Library Book Lending Tracker

## Introduction

This project replaces mutable paper lending records with a locally persisted, tamper-evident chain of borrow and return events. It is intentionally small enough to demonstrate the core blockchain concepts in C.

## Blockchain implementation

The chain contains a genesis block at index 0 and transaction blocks after it. Each block stores the book and member snapshot, action, timestamp, previous hash, ECDSA signature, and current hash. The previous hash links blocks in order. The current hash is computed from a canonical representation of the block data and its signature.

## Security mechanisms

SHA-256 detects changes to block contents and broken links. ECDSA using the NIST P-256 curve authenticates transaction data with a locally generated PEM private key. The CLI requires librarian authentication before commands are accepted. The sample credential is stored in `users.txt` as a SHA-256 password hash and is only suitable for demonstration; production should use a slow password hash such as Argon2id or bcrypt.

## Data persistence

Books and members are loaded from `books.txt` and `members.txt` at startup. The chain is stored in `blockchain.dat` as fixed-size binary records. The signing key is stored in `signing_key.pem`. Missing or empty registry files stop startup with an error.

## Error handling and validation

The program rejects malformed registry rows, unknown IDs, duplicate active loans, returns without an active loan, corrupt ledger files, invalid commands, and failed cryptographic operations. Validation checks every stored block hash, every previous-hash link, and every non-genesis signature.

## Screenshots and demonstration evidence

Insert screenshots from the demo video showing:

- Successful registry loading and librarian login.
- Unknown book/member rejection.
- Successful borrow, duplicate-borrow rejection, and return.
- `view` output with signature validity.
- A valid `validate` result.
- `tamper` followed by an invalid chain result.

## Challenges and solutions

The main design challenge is avoiding a circular hash: a block cannot hash its own hash. The implementation hashes all persisted content except the hash field, while including the signature so both transaction authenticity and block integrity are covered.

## Limitations and future work

This is a single-node educational ledger. A production version should use a secure credential store, key rotation, role-based permissions, encrypted backups, audit logging, and replicated consensus between trusted library nodes.
