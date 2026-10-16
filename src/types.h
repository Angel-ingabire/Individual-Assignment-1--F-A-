#ifndef LIBRARY_TRACKER_TYPES_H
#define LIBRARY_TRACKER_TYPES_H

#define _CRT_SECURE_NO_WARNINGS
#if defined(__MINGW32__)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

#define MAX_BOOKS 500
#define MAX_MEMBERS 500
#define MAX_BLOCKS 5000
#define MAX_COPIES 2000
#define MAX_RESERVATIONS 2000
#define MAX_RECORDS_PER_BLOCK 8
#define MAX_PENDING_REQUESTS MAX_BLOCKS
#define MAX_UTXOS 10000
#define MAX_LINE 256
#define HASH_HEX_LENGTH 65
#define SIGNATURE_MAX_LENGTH 72
#define ACTION_LENGTH 10
#define LEDGER_MAGIC "LIBCHAIN5"
#define STATE_MAGIC "LIBSTATE2"
#define METADATA_MAGIC "LIBMETA2"
#define LOAN_PERIOD_SECONDS (14 * 24 * 60 * 60)
#define FINE_PER_DAY 1
#define MAX_RENEWALS 2
#define RENEWAL_PERIOD_SECONDS ((time_t)renewal_period_days * 24 * 60 * 60)
#define REWARD_FEE 1
#define MINING_REWARD 2
#define CLOUD_RENTAL_FEE 2
#define CLOUD_MAINTENANCE_FEE 1
#define MINERS_IN_POOL 4
#define MAX_CONCURRENT_BORROWS 5
#define RAPID_REBORROW_WINDOW_SECONDS (24 * 60 * 60)
#define MAX_TRANSFER_INPUTS 16
#define MAX_TRANSFER_OUTPUTS 2
#define MAX_BLOCK_PAYOUTS MINERS_IN_POOL
#define MINING_REWARD_SCALE 10000

static int replace_file_atomically(const char *temporary_path,
                                   const char *destination_path)
{
#if defined(_WIN32)
    return MoveFileExA(temporary_path, destination_path,
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(temporary_path, destination_path) == 0;
#endif
}

typedef struct
{
    char transaction_id[HASH_HEX_LENGTH];
    unsigned int output_index;
} UTXOInput;

typedef struct
{
    char owner[20];
    int amount;
} UTXOOutput;

typedef struct
{
    unsigned int version;
    size_t input_count;
    UTXOInput inputs[MAX_TRANSFER_INPUTS];
    size_t output_count;
    UTXOOutput outputs[MAX_TRANSFER_OUTPUTS];
} UTXOTransactionProof;

typedef struct
{
    char record_id[HASH_HEX_LENGTH];
    char book_id[20];
    char copy_id[24];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_LENGTH];
    char reason_code[64];
    time_t due_date;
    int fine_amount;
    unsigned long long nonce;
    int token_reward;
    char signing_key_fingerprint[HASH_HEX_LENGTH];
    UTXOTransactionProof utxo_proof;
    unsigned char signature[SIGNATURE_MAX_LENGTH];
    unsigned int signature_len;
} LendingRecord;

typedef struct
{
    char member_id[20];
    unsigned long long attempts;
    int64_t reward_units;
    size_t cost_input_count;
    UTXOInput cost_inputs[MAX_TRANSFER_INPUTS];
    int cost_change;
} MiningPayout;

/* A block hash covers its header, Merkle root, and every signed record. */
typedef struct
{
    int index;
    time_t timestamp;
    size_t record_count;
    LendingRecord records[MAX_RECORDS_PER_BLOCK];
    char previous_hash[HASH_HEX_LENGTH];
    char merkle_root[HASH_HEX_LENGTH];
    char sealed_by[32];
    int token_reward;
    char transaction_id[HASH_HEX_LENGTH];
    int difficulty;
    unsigned long long nonce;
    char hash[HASH_HEX_LENGTH];
    char legacy_source_tip[HASH_HEX_LENGTH];
    size_t legacy_block_count;
    char mining_mode[8];
    char token_model[8];
    unsigned int cloud_rounds;
    size_t payout_count;
    int cloud_cost;
    MiningPayout payouts[MAX_BLOCK_PAYOUTS];
} Block;

typedef struct
{
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_LENGTH];
    char previous_hash[HASH_HEX_LENGTH];
    unsigned char signature[SIGNATURE_MAX_LENGTH];
    unsigned int signature_len;
    char hash[HASH_HEX_LENGTH];
} LegacyV1Block;

typedef struct
{
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_LENGTH];
    char previous_hash[HASH_HEX_LENGTH];
    int token_reward;
    char transaction_id[HASH_HEX_LENGTH];
    int difficulty;
    unsigned long long nonce;
    unsigned char signature[SIGNATURE_MAX_LENGTH];
    unsigned int signature_len;
    char hash[HASH_HEX_LENGTH];
} LegacyV2Block;

typedef struct
{
    char record_id[HASH_HEX_LENGTH];
    char book_id[20];
    char copy_id[24];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_LENGTH];
    char reason_code[64];
    time_t due_date;
    int fine_amount;
    unsigned long long nonce;
    int token_reward;
    unsigned char signature[SIGNATURE_MAX_LENGTH];
    unsigned int signature_len;
} LegacyV3LendingRecord;

typedef struct
{
    int index;
    time_t timestamp;
    size_t record_count;
    LegacyV3LendingRecord records[MAX_RECORDS_PER_BLOCK];
    char previous_hash[HASH_HEX_LENGTH];
    char merkle_root[HASH_HEX_LENGTH];
    char sealed_by[32];
    int token_reward;
    char transaction_id[HASH_HEX_LENGTH];
    int difficulty;
    unsigned long long nonce;
    char hash[HASH_HEX_LENGTH];
} LegacyV3Block;

typedef LegacyV3LendingRecord LegacyV4LendingRecord;
typedef LegacyV3Block LegacyV4Block;

typedef struct
{
    char book_id[20];
    char title[80];
    char author[50];
} Book;

typedef struct
{
    char member_id[20];
    char full_name[50];
    char course_code[10];
} Member;

typedef struct
{
    Book items[MAX_BOOKS];
    size_t count;
} BookRegistry;

typedef struct
{
    Member items[MAX_MEMBERS];
    size_t count;
} MemberRegistry;

typedef enum
{
    COPY_NEW,
    COPY_GOOD,
    COPY_WORN,
    COPY_LOST
} CopyCondition;

typedef enum
{
    COPY_AVAILABLE,
    COPY_BORROWED,
    COPY_RESERVED,
    COPY_STATE_LOST
} CopyState;

typedef struct
{
    char copy_id[24];
    char book_id[20];
    CopyCondition condition;
    CopyState state;
    char current_holder_id[20];
    time_t due_date;
    unsigned int renewal_count;
} BookCopy;

typedef struct
{
    BookCopy items[MAX_COPIES];
    size_t count;
} CopyRegistry;

typedef struct
{
    char member_id[20];
    char book_id[20];
    time_t reservation_date;
} Reservation;

typedef struct
{
    Reservation items[MAX_RESERVATIONS];
    size_t count;
} ReservationQueue;

typedef struct
{
    Block items[MAX_BLOCKS];
    size_t count;
} Chain;

typedef enum
{
    REQUEST_PENDING,
    REQUEST_CONFIRMED,
    REQUEST_SUSPICIOUS
} RequestStatus;

typedef struct
{
    LendingRecord record;
    int priority;
    time_t reservation_date;
    RequestStatus status;
} PendingRequest;

typedef struct
{
    PendingRequest items[MAX_PENDING_REQUESTS];
    size_t count;
} PendingPool;

typedef enum
{
    MODEL_UTXO,
    MODEL_ACCOUNT
} LedgerModel;

typedef struct
{
    char transaction_id[HASH_HEX_LENGTH];
    unsigned int output_index;
    char owner[20];
    int amount;
    int spent;
} UTXO;

typedef struct TransactionRecord
{
    char sender[20];
    char recipient[20];
    int amount;
    int fee;
    unsigned long long nonce;
    double exact_amount;
    struct TransactionRecord *next;
} TransactionRecord;

typedef struct
{
    char member_id[20];
    int balance;
    unsigned long long nonce;
    double reward_remainder;
    TransactionRecord *history_head;
    TransactionRecord *history_tail;
} Account;

typedef struct
{
    Account accounts[MAX_MEMBERS];
    size_t account_count;
    UTXO utxos[MAX_UTXOS];
    size_t utxo_count;
    unsigned long long transaction_sequence;
    LedgerModel model;
} TokenLedger;

typedef struct
{
    CopyRegistry copies;
    ReservationQueue reservations;
    PendingPool pending;
} LibraryState;

static MemberRegistry *active_member_registry;
static EVP_PKEY *member_signing_keys[MAX_MEMBERS];
static EVP_PKEY *member_verification_keys[MAX_MEMBERS];
static int renewal_period_days = 14;

static EVP_PKEY *member_signing_key(const char *member_id);
static EVP_PKEY *member_verification_key(const char *member_id);
static int make_record_id(LendingRecord *record);
static int transfer_tokens(TokenLedger *ledger, const char *sender_id,
                           const char *recipient_id, int amount,
                           unsigned long long nonce, const char *transaction_id,
                           const UTXOTransactionProof *proof);
static Account *find_account(TokenLedger *ledger, const char *member_id);
static int ledger_balance(const TokenLedger *ledger, const char *member_id);
static int initialize_ledger(TokenLedger *ledger, const MemberRegistry *members,
                             const Chain *chain, LedgerModel model);
static void free_ledger(TokenLedger *ledger);
static unsigned long long next_record_nonce(const Chain *chain,
                                            const PendingPool *pending,
                                            const char *member_id);

#endif
