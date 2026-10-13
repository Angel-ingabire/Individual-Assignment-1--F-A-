#define _CRT_SECURE_NO_WARNINGS
#if defined(__MINGW32__)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#define LEDGER_MAGIC "LIBCHAIN4"
#define STATE_MAGIC "LIBSTATE1"
#define METADATA_MAGIC "LIBMETA1"
#define LOAN_PERIOD_SECONDS (14 * 24 * 60 * 60)
#define FINE_PER_DAY 1
#define MAX_RENEWALS 2
#define RENEWAL_PERIOD_SECONDS (14 * 24 * 60 * 60)
#define REWARD_FEE 1
#define MINING_REWARD 2
#define CLOUD_RENTAL_FEE 2
#define CLOUD_MAINTENANCE_FEE 1
#define MINERS_IN_POOL 4
#define MAX_CONCURRENT_BORROWS 5
#define RAPID_REBORROW_WINDOW_SECONDS (24 * 60 * 60)

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
} LendingRecord;

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

static EVP_PKEY *member_signing_key(const char *member_id);
static EVP_PKEY *member_verification_key(const char *member_id);
static int make_record_id(LendingRecord *record);
static int transfer_tokens(TokenLedger *ledger, const char *sender_id,
                           const char *recipient_id, int amount,
                           unsigned long long nonce, const char *transaction_id);
static Account *find_account(TokenLedger *ledger, const char *member_id);
static unsigned long long next_record_nonce(const Chain *chain,
                                            const PendingPool *pending,
                                            const char *member_id);

static void trim(char *text)
{
    char *start = text;
    size_t length;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
        start++;
    if (start != text)
        memmove(text, start, strlen(start) + 1);
    length = strlen(text);
    while (length > 0 && (text[length - 1] == ' ' || text[length - 1] == '\t' || text[length - 1] == '\r' || text[length - 1] == '\n'))
    {
        text[--length] = '\0';
    }
}

static int valid_identifier(const char *text, size_t maximum_length)
{
    size_t length = strlen(text);
    if (length == 0 || length >= maximum_length)
        return 0;
    for (size_t i = 0; i < length; i++)
    {
        unsigned char character = (unsigned char)text[i];
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '-'))
            return 0;
    }
    return 1;
}

static int valid_record_text(const char *text)
{
    return strchr(text, '|') == NULL;
}

static int split_csv(char *line, char **fields, size_t expected)
{
    size_t count = 0;
    char *cursor = line;
    while (count < expected)
    {
        fields[count++] = cursor;
        cursor = strchr(cursor, ',');
        if (!cursor)
            break;
        *cursor++ = '\0';
    }
    if (count != expected || strchr(fields[expected - 1], ','))
        return 0;
    for (size_t i = 0; i < expected; i++)
        trim(fields[i]);
    return 1;
}

static int load_books(const char *path, BookRegistry *registry)
{
    FILE *file = fopen(path, "r");
    char line[MAX_LINE];
    registry->count = 0;
    if (!file)
    {
        fprintf(stderr, "ERROR: books.txt is missing or cannot be opened.\n");
        return 0;
    }
    while (fgets(line, sizeof(line), file))
    {
        char *fields[3];
        trim(line);
        if (!line[0] || line[0] == '#')
            continue;
        if (line[0] >= '0' && line[0] <= '9' && line[1] == '.')
            memmove(line, line + 2, strlen(line) - 1);
        if (registry->count >= MAX_BOOKS || !split_csv(line, fields, 3) ||
            !valid_identifier(fields[0], sizeof(registry->items[0].book_id)) ||
            !fields[1][0] || strlen(fields[1]) >= sizeof(registry->items[0].title) ||
            !fields[2][0] || strlen(fields[2]) >= sizeof(registry->items[0].author) ||
            !valid_record_text(fields[1]) || !valid_record_text(fields[2]))
        {
            fprintf(stderr, "ERROR: invalid book registry row.\n");
            fclose(file);
            return 0;
        }
        for (size_t i = 0; i < registry->count; i++)
            if (strcmp(registry->items[i].book_id, fields[0]) == 0)
            {
                fprintf(stderr, "ERROR: duplicate book ID.\n");
                fclose(file);
                return 0;
            }
        snprintf(registry->items[registry->count].book_id, sizeof(registry->items[0].book_id), "%s", fields[0]);
        snprintf(registry->items[registry->count].title, sizeof(registry->items[0].title), "%s", fields[1]);
        snprintf(registry->items[registry->count].author, sizeof(registry->items[0].author), "%s", fields[2]);
        registry->count++;
    }
    fclose(file);
    if (registry->count == 0)
        fprintf(stderr, "ERROR: books.txt is empty.\n");
    return registry->count > 0;
}

static int load_members(const char *path, MemberRegistry *registry)
{
    FILE *file = fopen(path, "r");
    char line[MAX_LINE];
    registry->count = 0;
    if (!file)
    {
        fprintf(stderr, "ERROR: members.txt is missing or cannot be opened.\n");
        return 0;
    }
    while (fgets(line, sizeof(line), file))
    {
        char *fields[3];
        trim(line);
        if (!line[0] || line[0] == '#')
            continue;
        if (line[0] == '-')
            memmove(line, line + 1, strlen(line));
        if (registry->count >= MAX_MEMBERS || !split_csv(line, fields, 3) ||
            !valid_identifier(fields[0], sizeof(registry->items[0].member_id)) ||
            !fields[1][0] || strlen(fields[1]) >= sizeof(registry->items[0].full_name) ||
            !fields[2][0] || strlen(fields[2]) >= sizeof(registry->items[0].course_code) ||
            !valid_record_text(fields[1]) || !valid_record_text(fields[2]))
        {
            fprintf(stderr, "ERROR: invalid member registry row.\n");
            fclose(file);
            return 0;
        }
        for (size_t i = 0; i < registry->count; i++)
            if (strcmp(registry->items[i].member_id, fields[0]) == 0)
            {
                fprintf(stderr, "ERROR: duplicate member ID.\n");
                fclose(file);
                return 0;
            }
        snprintf(registry->items[registry->count].member_id, sizeof(registry->items[0].member_id), "%s", fields[0]);
        snprintf(registry->items[registry->count].full_name, sizeof(registry->items[0].full_name), "%s", fields[1]);
        snprintf(registry->items[registry->count].course_code, sizeof(registry->items[0].course_code), "%s", fields[2]);
        registry->count++;
    }
    fclose(file);
    if (registry->count == 0)
        fprintf(stderr, "ERROR: members.txt is empty.\n");
    return registry->count > 0;
}

static Book *find_book(BookRegistry *registry, const char *id);

static int load_copies(const char *path, const BookRegistry *books, CopyRegistry *registry)
{
    FILE *file = fopen(path, "r");
    char line[MAX_LINE];
    registry->count = 0;
    if (!file)
    {
        fprintf(stderr, "ERROR: copies.txt is missing or cannot be opened.\n");
        return 0;
    }
    while (fgets(line, sizeof(line), file))
    {
        char *fields[3];
        BookCopy *copy;
        int duplicate = 0;
        int known_book = 0;
        trim(line);
        if (!line[0] || line[0] == '#')
            continue;
        if (!split_csv(line, fields, 3) ||
            !valid_identifier(fields[0], sizeof(registry->items[0].copy_id)) ||
            !valid_identifier(fields[1], sizeof(registry->items[0].book_id)) ||
            registry->count >= MAX_COPIES)
        {
            fprintf(stderr, "ERROR: invalid copies.txt row or unknown book ID.\n");
            fclose(file);
            return 0;
        }
        for (size_t i = 0; i < books->count; i++)
            if (strcmp(books->items[i].book_id, fields[1]) == 0)
                known_book = 1;
        if (!known_book)
        {
            fprintf(stderr, "ERROR: copies.txt references an unknown book ID.\n");
            fclose(file);
            return 0;
        }
        for (size_t i = 0; i < registry->count; i++)
            if (strcmp(registry->items[i].copy_id, fields[0]) == 0)
                duplicate = 1;
        if (duplicate)
        {
            fprintf(stderr, "ERROR: duplicate copy ID in copies.txt.\n");
            fclose(file);
            return 0;
        }
        copy = &registry->items[registry->count];
        memset(copy, 0, sizeof(*copy));
        snprintf(copy->copy_id, sizeof(copy->copy_id), "%s", fields[0]);
        snprintf(copy->book_id, sizeof(copy->book_id), "%s", fields[1]);
        if (strcmp(fields[2], "NEW") == 0)
            copy->condition = COPY_NEW;
        else if (strcmp(fields[2], "GOOD") == 0)
            copy->condition = COPY_GOOD;
        else if (strcmp(fields[2], "WORN") == 0)
            copy->condition = COPY_WORN;
        else if (strcmp(fields[2], "LOST") == 0)
        {
            copy->condition = COPY_LOST;
            copy->state = COPY_STATE_LOST;
        }
        else
        {
            fprintf(stderr, "ERROR: copy condition must be NEW, GOOD, WORN, or LOST.\n");
            fclose(file);
            return 0;
        }
        registry->count++;
    }
    fclose(file);
    if (registry->count == 0)
        fprintf(stderr, "ERROR: copies.txt is empty.\n");
    return registry->count > 0;
}

static Book *find_book(BookRegistry *registry, const char *id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].book_id, id) == 0)
            return &registry->items[i];
    return NULL;
}

static BookCopy *find_copy(CopyRegistry *registry, const char *copy_id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].copy_id, copy_id) == 0)
            return &registry->items[i];
    return NULL;
}

static Member *find_member(MemberRegistry *registry, const char *id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].member_id, id) == 0)
            return &registry->items[i];
    return NULL;
}

static const Book *find_book_const(const BookRegistry *registry, const char *id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].book_id, id) == 0)
            return &registry->items[i];
    return NULL;
}

static const Member *find_member_const(const MemberRegistry *registry, const char *id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].member_id, id) == 0)
            return &registry->items[i];
    return NULL;
}

static void hex_encode(const unsigned char *bytes, size_t length, char *output, size_t output_size)
{
    static const char digits[] = "0123456789abcdef";
    if (output_size < length * 2 + 1)
        return;
    for (size_t i = 0; i < length; i++)
    {
        output[i * 2] = digits[bytes[i] >> 4];
        output[i * 2 + 1] = digits[bytes[i] & 15];
    }
    output[length * 2] = '\0';
}

static int sha256_text(const char *text, char output[HASH_HEX_LENGTH])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int result = context && EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(context, text, strlen(text)) == 1 &&
                 EVP_DigestFinal_ex(context, digest, &digest_length) == 1;
    if (result)
        hex_encode(digest, digest_length, output, HASH_HEX_LENGTH);
    EVP_MD_CTX_free(context);
    return result;
}

static int has_pow_prefix(const char *hash, int difficulty);

static int record_unsigned_data(const LendingRecord *record, char *output, size_t output_size)
{
    int length = snprintf(output, output_size, "%s|%s|%s|%s|%s|%s|%s|%s|%lld|%d|%llu|%d",
                          record->record_id, record->book_id, record->copy_id, record->book_title,
                          record->member_id, record->member_name, record->action,
                          record->reason_code, (long long)record->due_date,
                          record->fine_amount, record->nonce, record->token_reward);
    return length >= 0 && (size_t)length < output_size;
}

static int legacy_record_unsigned_data(const LendingRecord *record, char *output, size_t output_size)
{
    int length = snprintf(output, output_size, "%s|%s|%s|%s|%s|%s|%s|%lld|%d|%llu|%d",
                          record->record_id, record->book_id, record->copy_id, record->book_title,
                          record->member_id, record->member_name, record->reason_code,
                          (long long)record->due_date, record->fine_amount, record->nonce,
                          record->token_reward);
    return length >= 0 && (size_t)length < output_size;
}

static int legacy_make_record_id(LendingRecord *record)
{
    char data[512];
    record->record_id[0] = '\0';
    return legacy_record_unsigned_data(record, data, sizeof(data)) &&
           sha256_text(data, record->record_id);
}

static int hash_record(const LendingRecord *record, char output[HASH_HEX_LENGTH])
{
    char data[512];
    char signature_hex[SIGNATURE_MAX_LENGTH * 2 + 1];
    char complete[1200];
    if (record->signature_len > SIGNATURE_MAX_LENGTH ||
        !record_unsigned_data(record, data, sizeof(data)))
        return 0;
    hex_encode(record->signature, record->signature_len, signature_hex, sizeof(signature_hex));
    if (snprintf(complete, sizeof(complete), "%s|%s", data, signature_hex) >= (int)sizeof(complete))
        return 0;
    return sha256_text(complete, output);
}

static int merkle_root(const LendingRecord *records, size_t record_count, char output[HASH_HEX_LENGTH])
{
    char level[MAX_RECORDS_PER_BLOCK][HASH_HEX_LENGTH];
    size_t count = record_count;
    if (record_count == 0 || record_count > MAX_RECORDS_PER_BLOCK)
        return 0;
    for (size_t i = 0; i < record_count; i++)
        if (!hash_record(&records[i], level[i]))
            return 0;
    while (count > 1)
    {
        size_t next_count = (count + 1) / 2;
        for (size_t i = 0; i < count; i += 2)
        {
            char pair[HASH_HEX_LENGTH * 2 - 1];
            const char *right = i + 1 < count ? level[i + 1] : level[i];
            memcpy(pair, level[i], HASH_HEX_LENGTH - 1);
            memcpy(pair + HASH_HEX_LENGTH - 1, right, HASH_HEX_LENGTH - 1);
            pair[sizeof(pair) - 1] = '\0';
            if (!sha256_text(pair, level[i / 2]))
                return 0;
        }
        count = next_count;
    }
    snprintf(output, HASH_HEX_LENGTH, "%s", level[0]);
    return 1;
}

static int hash_block(const Block *block, char output[HASH_HEX_LENGTH])
{
    char data[8192];
    size_t used;
    int length;
    if (block->record_count > MAX_RECORDS_PER_BLOCK)
        return 0;
    length = snprintf(data, sizeof(data), "%d|%lld|%zu|%s|%s|%s|%d|%s|%d|%llu",
                      block->index, (long long)block->timestamp, block->record_count,
                      block->previous_hash, block->merkle_root, block->sealed_by,
                      block->token_reward, block->transaction_id, block->difficulty, block->nonce);
    if (length < 0 || (size_t)length >= sizeof(data))
        return 0;
    used = (size_t)length;
    for (size_t i = 0; i < block->record_count; i++)
    {
        char record_hash[HASH_HEX_LENGTH];
        length = hash_record(&block->records[i], record_hash) ? snprintf(data + used, sizeof(data) - used, "|%s", record_hash) : -1;
        if (length < 0 || (size_t)length >= sizeof(data) - used)
            return 0;
        used += (size_t)length;
    }
    return sha256_text(data, output);
}

static int sign_record(LendingRecord *record, EVP_PKEY *key)
{
    char data[512];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signature_length = sizeof(record->signature);
    EVP_PKEY *signing_key = (strcmp(record->action, "LOST") == 0 ||
                             strcmp(record->action, "CONDITION") == 0)
                                ? key
                                : member_signing_key(record->member_id);
    if (!record_unsigned_data(record, data, sizeof(data)))
    {
        EVP_MD_CTX_free(context);
        return 0;
    }
    if (!context || !signing_key || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, signing_key) != 1 ||
        EVP_DigestSignUpdate(context, data, strlen(data)) != 1 ||
        EVP_DigestSignFinal(context, record->signature, &signature_length) != 1 ||
        signature_length == 0 || signature_length > SIGNATURE_MAX_LENGTH)
    {
        EVP_MD_CTX_free(context);
        return 0;
    }
    record->signature_len = (unsigned int)signature_length;
    EVP_MD_CTX_free(context);
    return 1;
}

static int verify_record_signature(const LendingRecord *record, EVP_PKEY *key)
{
    char data[512];
    EVP_PKEY *member_key = (strcmp(record->action, "LOST") == 0 ||
                            strcmp(record->action, "CONDITION") == 0)
                               ? NULL
                               : member_verification_key(record->member_id);
    EVP_MD_CTX *context;
    int result = 0;
    if (!record->signature_len || record->signature_len > SIGNATURE_MAX_LENGTH ||
        !record_unsigned_data(record, data, sizeof(data)))
        return 0;
    if (member_key)
    {
        context = EVP_MD_CTX_new();
        result = context && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, member_key) == 1 &&
                 EVP_DigestVerifyUpdate(context, data, strlen(data)) == 1 &&
                 EVP_DigestVerifyFinal(context, record->signature, record->signature_len) == 1;
        EVP_MD_CTX_free(context);
    }
    if (!result && key)
    {
        context = EVP_MD_CTX_new();
        result = context && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) == 1 &&
                 EVP_DigestVerifyUpdate(context, data, strlen(data)) == 1 &&
                 EVP_DigestVerifyFinal(context, record->signature, record->signature_len) == 1;
        EVP_MD_CTX_free(context);
    }
    return result;
}

static int verify_legacy_record_signature(const LendingRecord *record, EVP_PKEY *key)
{
    char data[512];
    EVP_MD_CTX *context;
    int result;
    if (!key || !record->signature_len || record->signature_len > SIGNATURE_MAX_LENGTH ||
        !legacy_record_unsigned_data(record, data, sizeof(data)))
        return 0;
    context = EVP_MD_CTX_new();
    result = context && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) == 1 &&
             EVP_DigestVerifyUpdate(context, data, strlen(data)) == 1 &&
             EVP_DigestVerifyFinal(context, record->signature, record->signature_len) == 1;
    EVP_MD_CTX_free(context);
    return result;
}

static int validate_or_upgrade_pending_signature(LendingRecord *record, EVP_PKEY *librarian_key)
{
    char stored_id[HASH_HEX_LENGTH];
    LendingRecord identity = *record;
    snprintf(stored_id, sizeof(stored_id), "%s", record->record_id);
    if (make_record_id(&identity) &&
        strcmp(identity.record_id, stored_id) == 0 &&
        verify_record_signature(record, librarian_key))
        return 1;
    identity = *record;
    if (!legacy_make_record_id(&identity) ||
        strcmp(identity.record_id, stored_id) != 0 ||
        !verify_legacy_record_signature(record, librarian_key))
        return 0;
    record->record_id[0] = '\0';
    return make_record_id(record) && sign_record(record, librarian_key);
}

static EVP_PKEY *load_or_create_key(const char *path)
{
    BIO *file = BIO_new_file(path, "rb");
    EVP_PKEY *key = NULL;
    if (file)
    {
        key = PEM_read_bio_PrivateKey(file, NULL, NULL, NULL);
        BIO_free(file);
        return key;
    }
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) != 1 || EVP_PKEY_keygen(context, &key) != 1)
    {
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    file = BIO_new_file(path, "wb");
    if (!file || PEM_write_bio_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) != 1)
    {
        BIO_free(file);
        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    BIO_free(file);
    EVP_PKEY_CTX_free(context);
    printf("Created signing key at %s. Protect this file in production.\n", path);
    return key;
}

static EVP_PKEY *member_signing_key(const char *member_id)
{
    if (!active_member_registry)
        return NULL;
    for (size_t i = 0; i < active_member_registry->count; i++)
        if (strcmp(active_member_registry->items[i].member_id, member_id) == 0)
            return member_signing_keys[i];
    return NULL;
}

static EVP_PKEY *member_verification_key(const char *member_id)
{
    if (!active_member_registry)
        return NULL;
    for (size_t i = 0; i < active_member_registry->count; i++)
        if (strcmp(active_member_registry->items[i].member_id, member_id) == 0)
            return member_verification_keys[i];
    return NULL;
}

static int save_member_public_key(EVP_PKEY *key, const char *member_id)
{
    char path[96];
    BIO *file;
    if (snprintf(path, sizeof(path), "member_%s_public.pem", member_id) >= (int)sizeof(path))
        return 0;
    file = BIO_new_file(path, "wb");
    if (!file)
        return 0;
    int success = PEM_write_bio_PUBKEY(file, key) == 1;
    if (BIO_free(file) != 1)
        success = 0;
    return success;
}

static int ensure_member_signing_key(MemberRegistry *members, const char *member_id)
{
    char path[96];
    active_member_registry = members;
    for (size_t i = 0; i < members->count; i++)
        if (strcmp(members->items[i].member_id, member_id) == 0)
        {
            if (member_signing_keys[i] && member_verification_keys[i])
                return 1;
            if (!member_signing_keys[i])
            {
                if (snprintf(path, sizeof(path), "member_%s_key.pem", member_id) >= (int)sizeof(path))
                    return 0;
                member_signing_keys[i] = load_or_create_key(path);
            }
            if (!member_signing_keys[i] ||
                !save_member_public_key(member_signing_keys[i], member_id))
                return 0;
            char public_path[96];
            if (snprintf(public_path, sizeof(public_path), "member_%s_public.pem", member_id) >= (int)sizeof(public_path))
                return 0;
            BIO *public_file = BIO_new_file(public_path, "rb");
            if (!public_file)
                return 0;
            EVP_PKEY_free(member_verification_keys[i]);
            member_verification_keys[i] = PEM_read_bio_PUBKEY(public_file, NULL, NULL, NULL);
            BIO_free(public_file);
            return member_verification_keys[i] != NULL;
        }
    return 0;
}

static int initialize_member_signing_keys(MemberRegistry *members)
{
    active_member_registry = members;
    for (size_t i = 0; i < members->count; i++)
        if (!ensure_member_signing_key(members, members->items[i].member_id))
        {
            fprintf(stderr, "ERROR: could not load or create ECDSA key for member %s.\n",
                    members->items[i].member_id);
            return 0;
        }
    return 1;
}

static void free_member_signing_keys(void)
{
    for (size_t i = 0; i < MAX_MEMBERS; i++)
    {
        EVP_PKEY_free(member_signing_keys[i]);
        member_signing_keys[i] = NULL;
        EVP_PKEY_free(member_verification_keys[i]);
        member_verification_keys[i] = NULL;
    }
    active_member_registry = NULL;
}

static void create_genesis(Chain *chain)
{
    Block *genesis = &chain->items[0];
    char empty_root[HASH_HEX_LENGTH];
    memset(genesis, 0, sizeof(*genesis));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';
    snprintf(genesis->sealed_by, sizeof(genesis->sealed_by), "genesis");
    sha256_text("", empty_root);
    snprintf(genesis->merkle_root, sizeof(genesis->merkle_root), "%s", empty_root);
    if (!hash_block(genesis, genesis->hash))
        fprintf(stderr, "ERROR: unable to hash genesis block.\n");
    chain->count = 1;
}

static int make_record_id(LendingRecord *record)
{
    char data[512];
    record->record_id[0] = '\0';
    if (!record_unsigned_data(record, data, sizeof(data)) ||
        !sha256_text(data, record->record_id))
        return 0;
    return 1;
}

static int finalize_block(Block *block)
{
    char transaction_data[160];
    char computed[HASH_HEX_LENGTH];
    block->token_reward = 0;
    for (size_t i = 0; i < block->record_count; i++)
        if (strcmp(block->records[i].action, "RETURNED") == 0)
            block->token_reward += block->records[i].token_reward;
    if (!merkle_root(block->records, block->record_count, block->merkle_root))
        return 0;
    if (block->token_reward > 0)
    {
        if (snprintf(transaction_data, sizeof(transaction_data), "%s|%d", block->merkle_root, block->token_reward) >= (int)sizeof(transaction_data) ||
            !sha256_text(transaction_data, block->transaction_id))
            return 0;
    }
    else
        block->transaction_id[0] = '\0';
    if (!hash_block(block, computed))
        return 0;
    snprintf(block->hash, sizeof(block->hash), "%s", computed);
    return 1;
}

static int save_chain(const char *path, const Chain *chain)
{
    char temporary_path[512];
    FILE *file;
    int success;
    snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path);
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    success = fwrite(LEDGER_MAGIC, 1, 9, file) == 9 &&
              fwrite(&chain->count, sizeof(chain->count), 1, file) == 1 &&
              fwrite(chain->items, sizeof(Block), chain->count, file) == chain->count &&
              fflush(file) == 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success)
    {
        remove(temporary_path);
        return 0;
    }
    remove(path);
    return rename(temporary_path, path) == 0;
}

static int load_chain(const char *path, Chain *chain, EVP_PKEY *key)
{
    FILE *file = fopen(path, "rb");
    char magic[10] = {0};
    if (!file)
    {
        create_genesis(chain);
        return save_chain(path, chain);
    }
    if (fread(magic, 1, 9, file) != 9 || fread(&chain->count, sizeof(chain->count), 1, file) != 1 || chain->count == 0 || chain->count > MAX_BLOCKS)
    {
        fclose(file);
        fprintf(stderr, "ERROR: blockchain.dat is corrupt.\n");
        return 0;
    }
    if (strcmp(magic, LEDGER_MAGIC) == 0)
    {
        if (fread(chain->items, sizeof(Block), chain->count, file) != chain->count)
        {
            fclose(file);
            fprintf(stderr, "ERROR: blockchain.dat is corrupt.\n");
            return 0;
        }
    }
    else if (strcmp(magic, "LIBCHAIN3") == 0)
    {
        LegacyV3Block *legacy = (LegacyV3Block *)calloc(chain->count, sizeof(*legacy));
        if (!legacy || fread(legacy, sizeof(*legacy), chain->count, file) != chain->count)
        {
            free(legacy);
            fclose(file);
            fprintf(stderr, "ERROR: version-3 blockchain.dat is corrupt.\n");
            return 0;
        }
        for (size_t i = 0; i < chain->count; i++)
        {
            Block *block = &chain->items[i];
            const LegacyV3Block *old = &legacy[i];
            memset(block, 0, sizeof(*block));
            block->index = (int)i;
            block->timestamp = old->timestamp;
            if (i > 0 && block->timestamp <= chain->items[i - 1].timestamp)
                block->timestamp = chain->items[i - 1].timestamp + 1;
            if (i == 0)
            {
                char empty_root[HASH_HEX_LENGTH];
                memset(block->previous_hash, '0', 64);
                block->previous_hash[64] = '\0';
                block->difficulty = 0;
                snprintf(block->sealed_by, sizeof(block->sealed_by), "genesis");
                if (!sha256_text("", empty_root))
                {
                    free(legacy);
                    fclose(file);
                    return 0;
                }
                snprintf(block->merkle_root, sizeof(block->merkle_root), "%s", empty_root);
                if (!hash_block(block, block->hash))
                {
                    free(legacy);
                    fclose(file);
                    return 0;
                }
                continue;
            }
            if (old->record_count == 0 || old->record_count > MAX_RECORDS_PER_BLOCK)
            {
                free(legacy);
                fclose(file);
                fprintf(stderr, "ERROR: invalid record count in version-3 block.\n");
                return 0;
            }
            block->record_count = old->record_count;
            block->difficulty = old->difficulty >= 1 && old->difficulty <= 4 ? old->difficulty : 2;
            snprintf(block->sealed_by, sizeof(block->sealed_by), "%s",
                     old->sealed_by[0] ? old->sealed_by : "migration");
            snprintf(block->previous_hash, sizeof(block->previous_hash), "%s",
                     chain->items[i - 1].hash);
            for (size_t j = 0; j < block->record_count; j++)
            {
                const LegacyV3LendingRecord *old_record = &old->records[j];
                LendingRecord *record = &block->records[j];
                snprintf(record->book_id, sizeof(record->book_id), "%s", old_record->book_id);
                snprintf(record->copy_id, sizeof(record->copy_id), "%s", old_record->copy_id);
                snprintf(record->book_title, sizeof(record->book_title), "%s", old_record->book_title);
                snprintf(record->member_id, sizeof(record->member_id), "%s", old_record->member_id);
                snprintf(record->member_name, sizeof(record->member_name), "%s", old_record->member_name);
                snprintf(record->action, sizeof(record->action), "%s", old_record->action);
                snprintf(record->reason_code, sizeof(record->reason_code), "%s", old_record->reason_code);
                record->due_date = old_record->due_date;
                record->fine_amount = old_record->fine_amount;
                record->nonce = old_record->nonce;
                record->token_reward = old_record->token_reward;
                if (!make_record_id(record) || !sign_record(record, key))
                {
                    free(legacy);
                    fclose(file);
                    fprintf(stderr, "ERROR: could not migrate version-3 record signatures.\n");
                    return 0;
                }
            }
            if (!finalize_block(block))
            {
                free(legacy);
                fclose(file);
                return 0;
            }
            block->nonce = 0;
            while (!has_pow_prefix(block->hash, block->difficulty))
            {
                block->nonce++;
                if (!hash_block(block, block->hash))
                {
                    free(legacy);
                    fclose(file);
                    return 0;
                }
            }
        }
        free(legacy);
        fclose(file);
        printf("Migrated version-3 ledger to action-bound member signatures.\n");
        return save_chain(path, chain);
    }
    else if (strcmp(magic, "LIBCHAIN2") == 0 || strcmp(magic, "LIBCHAIN1") == 0)
    {
        int version_two = strcmp(magic, "LIBCHAIN2") == 0;
        LegacyV2Block *legacy_v2 = version_two ? (LegacyV2Block *)calloc(chain->count, sizeof(*legacy_v2)) : NULL;
        LegacyV1Block *legacy_v1 = version_two ? NULL : (LegacyV1Block *)calloc(chain->count, sizeof(*legacy_v1));
        if ((version_two && (!legacy_v2 || fread(legacy_v2, sizeof(*legacy_v2), chain->count, file) != chain->count)) ||
            (!version_two && (!legacy_v1 || fread(legacy_v1, sizeof(*legacy_v1), chain->count, file) != chain->count)))
        {
            free(legacy_v2);
            free(legacy_v1);
            fclose(file);
            fprintf(stderr, "ERROR: legacy blockchain.dat is corrupt.\n");
            return 0;
        }
        for (size_t i = 0; i < chain->count; i++)
        {
            Block *block = &chain->items[i];
            const LegacyV1Block *old_v1 = version_two ? NULL : &legacy_v1[i];
            const LegacyV2Block *old_v2 = version_two ? &legacy_v2[i] : NULL;
            const char *old_book_id = version_two ? old_v2->book_id : old_v1->book_id;
            const char *old_title = version_two ? old_v2->book_title : old_v1->book_title;
            const char *old_member_id = version_two ? old_v2->member_id : old_v1->member_id;
            const char *old_member_name = version_two ? old_v2->member_name : old_v1->member_name;
            const char *old_action = version_two ? old_v2->action : old_v1->action;
            time_t old_timestamp = version_two ? old_v2->timestamp : old_v1->timestamp;
            memset(block, 0, sizeof(*block));
            block->index = (int)i;
            block->timestamp = old_timestamp;
            if (i > 0 && block->timestamp <= chain->items[i - 1].timestamp)
                block->timestamp = chain->items[i - 1].timestamp + 1;
            block->difficulty = 2;
            snprintf(block->sealed_by, sizeof(block->sealed_by), "migration");
            if (i == 0)
            {
                block->timestamp = old_timestamp;
                memset(block->previous_hash, '0', 64);
                block->previous_hash[64] = '\0';
            }
            else
            {
                LendingRecord *record = &block->records[0];
                block->record_count = 1;
                snprintf(block->previous_hash, sizeof(block->previous_hash), "%s", chain->items[i - 1].hash);
                snprintf(record->book_id, sizeof(record->book_id), "%s", old_book_id);
                snprintf(record->copy_id, sizeof(record->copy_id), "%s-C01", old_book_id);
                snprintf(record->book_title, sizeof(record->book_title), "%s", old_title);
                snprintf(record->member_id, sizeof(record->member_id), "%s", old_member_id);
                snprintf(record->member_name, sizeof(record->member_name), "%s", old_member_name);
                snprintf(record->action, sizeof(record->action), "%s", old_action);
                if (strcmp(old_action, "BORROWED") == 0)
                    record->due_date = block->timestamp + LOAN_PERIOD_SECONDS;
                else if (strcmp(old_action, "RETURNED") == 0)
                {
                    for (size_t prior = i; prior-- > 1;)
                    {
                        const char *prior_book = version_two ? legacy_v2[prior].book_id : legacy_v1[prior].book_id;
                        const char *prior_member = version_two ? legacy_v2[prior].member_id : legacy_v1[prior].member_id;
                        const char *prior_action = version_two ? legacy_v2[prior].action : legacy_v1[prior].action;
                        time_t prior_time = chain->items[prior].timestamp;
                        if (strcmp(prior_book, old_book_id) == 0 &&
                            strcmp(prior_member, old_member_id) == 0 &&
                            strcmp(prior_action, "BORROWED") == 0)
                        {
                            record->due_date = prior_time + LOAN_PERIOD_SECONDS;
                            break;
                        }
                    }
                }
                record->nonce = 0;
                for (size_t prior = 1; prior < i; prior++)
                {
                    const char *prior_member_id = version_two ? legacy_v2[prior].member_id : legacy_v1[prior].member_id;
                    if (strcmp(prior_member_id, old_member_id) == 0)
                        record->nonce++;
                }
                record->token_reward = version_two ? old_v2->token_reward : 0;
                if (version_two && record->token_reward > 0 &&
                    strcmp(old_action, "RETURNED") == 0 &&
                    block->timestamp > record->due_date)
                {
                    time_t late_seconds = block->timestamp - record->due_date;
                    record->fine_amount = (int)((late_seconds + 86400 - 1) / 86400) * FINE_PER_DAY;
                }
                if (!make_record_id(record) || !sign_record(record, key))
                {
                    free(legacy_v2);
                    free(legacy_v1);
                    fclose(file);
                    return 0;
                }
                if (version_two)
                {
                    memcpy(block->transaction_id, old_v2->transaction_id, sizeof(block->transaction_id));
                    if (!record->token_reward)
                        block->transaction_id[0] = '\0';
                }
            }
            if (i == 0)
            {
                char empty_root[HASH_HEX_LENGTH];
                sha256_text("", empty_root);
                snprintf(block->merkle_root, sizeof(block->merkle_root), "%s", empty_root);
                if (!hash_block(block, block->hash))
                {
                    free(legacy_v2);
                    free(legacy_v1);
                    fclose(file);
                    return 0;
                }
                continue;
            }
            if (!finalize_block(block))
            {
                free(legacy_v2);
                free(legacy_v1);
                fclose(file);
                return 0;
            }
            block->nonce = 0;
            if (!hash_block(block, block->hash))
            {
                free(legacy_v2);
                free(legacy_v1);
                fclose(file);
                return 0;
            }
            while (i > 0 && !has_pow_prefix(block->hash, block->difficulty))
            {
                block->nonce++;
                if (!hash_block(block, block->hash))
                {
                    free(legacy_v2);
                    free(legacy_v1);
                    fclose(file);
                    return 0;
                }
            }
        }
        free(legacy_v2);
        free(legacy_v1);
        fclose(file);
        printf("Migrated legacy ledger to the extended block format.\n");
        return save_chain(path, chain);
    }
    else
    {
        fclose(file);
        fprintf(stderr, "ERROR: unsupported blockchain.dat format.\n");
        return 0;
    }
    fclose(file);
    return 1;
}

static int validate_chain(const Chain *chain, EVP_PKEY *key, const BookRegistry *books,
                          const MemberRegistry *members, const CopyRegistry *copies, int print_result)
{
    char computed[HASH_HEX_LENGTH];
    unsigned long long expected_nonces[MAX_MEMBERS] = {0};
    int valid = chain->count > 0;
    for (size_t i = 0; valid && i < chain->count; i++)
    {
        const Block *block = &chain->items[i];
        char computed_root[HASH_HEX_LENGTH];
        valid = block->index == (int)i && block->record_count <= MAX_RECORDS_PER_BLOCK &&
                hash_block(block, computed) && strcmp(computed, block->hash) == 0;
        if (i == 0)
        {
            char genesis_previous_hash[HASH_HEX_LENGTH];
            memset(genesis_previous_hash, '0', 64);
            genesis_previous_hash[64] = '\0';
            valid = valid && strcmp(block->previous_hash, genesis_previous_hash) == 0 &&
                    block->record_count == 0;
        }
        if (i > 0)
            valid = valid && block->record_count > 0 &&
                    strcmp(block->previous_hash, chain->items[i - 1].hash) == 0 &&
                    block->timestamp > chain->items[i - 1].timestamp &&
                    merkle_root(block->records, block->record_count, computed_root) &&
                    strcmp(computed_root, block->merkle_root) == 0;
        if (i > 0 && valid)
        {
            int total_reward = 0;
            valid = block->difficulty >= 1 && block->difficulty <= 4 &&
                    has_pow_prefix(block->hash, block->difficulty);
            for (size_t j = 0; valid && j < block->record_count; j++)
            {
                const LendingRecord *record = &block->records[j];
                int known_book = 0;
                int known_member = 0;
                int known_copy = 0;
                int token_transfer = strcmp(record->action, "TRANSFER") == 0;
                size_t member_index = members->count;
                for (size_t k = 0; k < books->count; k++)
                    if (strcmp(books->items[k].book_id, record->book_id) == 0)
                        known_book = 1;
                for (size_t k = 0; k < members->count; k++)
                    if (strcmp(members->items[k].member_id, record->member_id) == 0)
                    {
                        known_member = 1;
                        member_index = k;
                    }
                for (size_t k = 0; k < copies->count; k++)
                    if (strcmp(copies->items[k].copy_id, record->copy_id) == 0 &&
                        strcmp(copies->items[k].book_id, record->book_id) == 0)
                        known_copy = 1;
                if (strcmp(record->action, "RESERVED") == 0 && strcmp(record->copy_id, "QUEUE") == 0)
                    known_copy = 1;
                if (token_transfer)
                {
                    known_book = 0;
                    known_copy = 0;
                    for (size_t k = 0; k < members->count; k++)
                        if (strcmp(members->items[k].member_id, record->book_title) == 0)
                            known_book = known_copy = 1;
                }
                valid = (strcmp(record->action, "BORROWED") == 0 ||
                         strcmp(record->action, "RETURNED") == 0 ||
                         strcmp(record->action, "RESERVED") == 0 ||
                         strcmp(record->action, "RENEWED") == 0 ||
                         strcmp(record->action, "OVERDUE") == 0 ||
                         strcmp(record->action, "LOST") == 0 ||
                         strcmp(record->action, "CONDITION") == 0 ||
                         strcmp(record->action, "FINEPAID") == 0 ||
                         token_transfer) &&
                        record->record_id[0] != '\0' && record->book_id[0] != '\0' &&
                        record->copy_id[0] != '\0' && record->member_id[0] != '\0' &&
                        record->fine_amount >= 0 && known_book && known_member && known_copy &&
                        record->nonce == expected_nonces[member_index] &&
                        verify_record_signature(record, key);
                if (valid)
                    expected_nonces[member_index]++;
                if (valid)
                {
                    LendingRecord identity = *record;
                    char expected_id[HASH_HEX_LENGTH];
                    valid = make_record_id(&identity) &&
                            snprintf(expected_id, sizeof(expected_id), "%s", identity.record_id) > 0 &&
                            strcmp(expected_id, record->record_id) == 0;
                }
                if (strcmp(record->action, "RETURNED") == 0)
                    valid = valid && record->due_date > 0 &&
                            (record->token_reward == 0 ||
                             (record->fine_amount == 0 && record->token_reward == 10) ||
                             (record->fine_amount > 0 && record->token_reward == 5));
                else if (!token_transfer)
                    valid = valid && record->token_reward == 0;
                else
                    valid = valid && record->token_reward > 0 &&
                            record->fine_amount == REWARD_FEE &&
                            record->due_date >= 0 &&
                            strcmp(record->book_id, "TOKEN") == 0 &&
                            strcmp(record->copy_id, "TRANSFER") == 0 &&
                            (strcmp(record->reason_code, "ACCOUNT") == 0 ||
                             strcmp(record->reason_code, "UTXO") == 0) &&
                            (strcmp(record->reason_code, "ACCOUNT") == 0 ||
                             record->due_date == 0);
                if (strcmp(record->action, "BORROWED") == 0 ||
                    strcmp(record->action, "RENEWED") == 0)
                    valid = valid && record->due_date > 0 && record->fine_amount == 0;
                if (strcmp(record->action, "OVERDUE") == 0)
                    valid = valid && record->due_date > 0 && record->fine_amount > 0;
                if (strcmp(record->action, "FINEPAID") == 0)
                    valid = valid && record->due_date > 0 && record->fine_amount > 0;
                if (strcmp(record->action, "CONDITION") == 0)
                    valid = valid && record->fine_amount >= COPY_NEW &&
                            record->fine_amount <= COPY_WORN &&
                            record->reason_code[0] != '\0';
                if (strcmp(record->action, "RESERVED") == 0 ||
                    strcmp(record->action, "LOST") == 0)
                    valid = valid && record->fine_amount == 0;
                if (strcmp(record->action, "RETURNED") == 0)
                    total_reward += record->token_reward;
            }
            valid = valid && total_reward == block->token_reward;
            if (valid && total_reward > 0)
            {
                char transaction_data[160];
                char transaction_id[HASH_HEX_LENGTH];
                snprintf(transaction_data, sizeof(transaction_data), "%s|%d", block->merkle_root, total_reward);
                valid = sha256_text(transaction_data, transaction_id) &&
                        strcmp(transaction_id, block->transaction_id) == 0;
            }
            else if (valid)
                valid = block->transaction_id[0] == '\0';
        }
        if (!valid && print_result)
            fprintf(stderr, "INVALID: block %d failed integrity, proof-of-work, signature, or reward validation.\n", block->index);
    }
    if (print_result)
        printf("Chain validation: %s (%zu blocks)\n", valid ? "VALID" : "INVALID", chain->count);
    return valid;
}

static int validate_chain_file(const char *path, Chain *chain, EVP_PKEY *key,
                               const BookRegistry *books, const MemberRegistry *members,
                               const CopyRegistry *copies)
{
    static Chain disk_chain;
    FILE *file = fopen(path, "rb");
    char magic[10] = {0};
    size_t count;
    if (!file)
    {
        fprintf(stderr, "ERROR: cannot open saved blockchain for validation.\n");
        return 0;
    }
    if (fread(magic, 1, 9, file) != 9 || strcmp(magic, LEDGER_MAGIC) != 0 ||
        fread(&count, sizeof(count), 1, file) != 1 || count == 0 || count > MAX_BLOCKS ||
        fread(disk_chain.items, sizeof(Block), count, file) != count)
    {
        fclose(file);
        fprintf(stderr, "ERROR: saved blockchain is truncated, corrupt, or requires migration.\n");
        printf("Chain validation: INVALID (saved chain could not be loaded)\n");
        return 0;
    }
    if (fgetc(file) != EOF)
    {
        fclose(file);
        fprintf(stderr, "ERROR: saved blockchain has unexpected trailing data.\n");
        printf("Chain validation: INVALID (unexpected trailing data)\n");
        return 0;
    }
    fclose(file);
    disk_chain.count = count;
    if (!validate_chain(&disk_chain, key, books, members, copies, 1))
        return 0;
    memcpy(chain->items, disk_chain.items, count * sizeof(Block));
    chain->count = count;
    return 1;
}

static int has_pow_prefix(const char *hash, int difficulty)
{
    for (int i = 0; i < difficulty; i++)
        if (hash[i] != '0')
            return 0;
    return 1;
}

static int add_history(Account *account, const char *sender, const char *recipient, int amount, int fee, unsigned long long nonce)
{
    TransactionRecord *record = (TransactionRecord *)calloc(1, sizeof(*record));
    if (!record)
        return 0;
    snprintf(record->sender, sizeof(record->sender), "%s", sender);
    snprintf(record->recipient, sizeof(record->recipient), "%s", recipient);
    record->amount = amount;
    record->fee = fee;
    record->nonce = nonce;
    if (account->history_tail)
        account->history_tail->next = record;
    else
        account->history_head = record;
    account->history_tail = record;
    return 1;
}

static TransactionRecord *create_history_record(const char *sender, const char *recipient,
                                                int amount, int fee, unsigned long long nonce)
{
    TransactionRecord *record = (TransactionRecord *)calloc(1, sizeof(*record));
    if (!record)
        return NULL;
    snprintf(record->sender, sizeof(record->sender), "%s", sender);
    snprintf(record->recipient, sizeof(record->recipient), "%s", recipient);
    record->amount = amount;
    record->fee = fee;
    record->nonce = nonce;
    return record;
}

static void append_history_record(Account *account, TransactionRecord *record)
{
    if (account->history_tail)
        account->history_tail->next = record;
    else
        account->history_head = record;
    account->history_tail = record;
}

static int add_utxo(TokenLedger *ledger, const char *transaction_id, unsigned int output_index, const char *owner, int amount)
{
    UTXO *utxo;
    if (ledger->utxo_count >= MAX_UTXOS || amount <= 0)
        return amount <= 0;
    utxo = &ledger->utxos[ledger->utxo_count++];
    snprintf(utxo->transaction_id, sizeof(utxo->transaction_id), "%s", transaction_id);
    utxo->output_index = output_index;
    snprintf(utxo->owner, sizeof(utxo->owner), "%s", owner);
    utxo->amount = amount;
    return 1;
}

/* The fee is excluded from spendable balances in both accounting models. */
static void apply_record_reward(TokenLedger *ledger, const LendingRecord *record)
{
    Account *account = NULL;
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, record->member_id) == 0)
        {
            account = &ledger->accounts[i];
            break;
        }
    if (!account || record->token_reward <= REWARD_FEE)
        return;
    if (ledger->model == MODEL_ACCOUNT)
    {
        account->balance += record->token_reward - REWARD_FEE;
        add_history(account, "SYSTEM", account->member_id, record->token_reward, REWARD_FEE, 0);
    }
    else
    {
        add_utxo(ledger, record->record_id, 0, account->member_id, record->token_reward - REWARD_FEE);
        add_history(account, "SYSTEM", account->member_id, record->token_reward, REWARD_FEE, 0);
    }
}

static int apply_mining_reward(TokenLedger *ledger, const char *member_id,
                               double reward, const char *transaction_id,
                               unsigned int output_index)
{
    Account *account = find_account(ledger, member_id);
    double total;
    int whole_coins;
    if (!account || reward < 0.0 || !transaction_id ||
        strlen(transaction_id) != HASH_HEX_LENGTH - 1)
        return 0;
    total = account->reward_remainder + reward;
    if (total > (double)INT_MAX)
        return 0;
    whole_coins = (int)total;
    if (ledger->model == MODEL_ACCOUNT &&
        whole_coins > INT_MAX - account->balance)
        return 0;
    if (ledger->model == MODEL_UTXO && whole_coins > 0 &&
        ledger->utxo_count >= MAX_UTXOS)
        return 0;
    if (reward > 0.0 &&
        !add_history(account, "MINING", member_id, 0, 0, 0))
        return 0;
    if (reward > 0.0)
        account->history_tail->exact_amount = reward;
    if (ledger->model == MODEL_ACCOUNT)
        account->balance += whole_coins;
    else if (whole_coins > 0 &&
             !add_utxo(ledger, transaction_id, output_index, member_id, whole_coins))
    {
        fprintf(stderr, "ERROR: mining reward output could not be added after capacity validation.\n");
        return 0;
    }
    account->reward_remainder = total - whole_coins;
    return 1;
}

static int initialize_ledger(TokenLedger *ledger, const MemberRegistry *members,
                             const Chain *chain, LedgerModel model)
{
    memset(ledger, 0, sizeof(*ledger));
    ledger->model = model;
    ledger->account_count = members->count;
    for (size_t i = 0; i < members->count; i++)
        snprintf(ledger->accounts[i].member_id, sizeof(ledger->accounts[i].member_id), "%s", members->items[i].member_id);
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if (strcmp(record->action, "RETURNED") == 0 &&
                record->token_reward > 0)
                apply_record_reward(ledger, record);
            else if (strcmp(record->action, "TRANSFER") == 0 &&
                     strcmp(record->reason_code,
                            model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
                     !transfer_tokens(ledger, record->member_id, record->book_title,
                                      record->token_reward,
                                      (unsigned long long)record->due_date,
                                      record->record_id))
            {
                fprintf(stderr, "ERROR: confirmed token transaction cannot be replayed; selected model state conflicts with the chain.\n");
                return 0;
            }
        }
    return 1;
}

static Account *find_account(TokenLedger *ledger, const char *member_id)
{
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
            return &ledger->accounts[i];
    return NULL;
}

static int add_ledger_member(TokenLedger *ledger, const char *member_id)
{
    if (ledger->account_count >= MAX_MEMBERS || find_account(ledger, member_id))
        return 0;
    Account *account = &ledger->accounts[ledger->account_count++];
    memset(account, 0, sizeof(*account));
    snprintf(account->member_id, sizeof(account->member_id), "%s", member_id);
    return 1;
}

static int ledger_balance(const TokenLedger *ledger, const char *member_id)
{
    int balance = 0;
    if (ledger->model == MODEL_ACCOUNT)
    {
        for (size_t i = 0; i < ledger->account_count; i++)
            if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
                return ledger->accounts[i].balance;
        return 0;
    }
    for (size_t i = 0; i < ledger->utxo_count; i++)
        if (!ledger->utxos[i].spent && strcmp(ledger->utxos[i].owner, member_id) == 0)
            balance += ledger->utxos[i].amount;
    return balance;
}

static void print_balances(const TokenLedger *ledger)
{
    printf("Token balances (%s model):\n", ledger->model == MODEL_UTXO ? "UTXO" : "account");
    for (size_t i = 0; i < ledger->account_count; i++)
    {
        printf("  %s: %d coins", ledger->accounts[i].member_id, ledger_balance(ledger, ledger->accounts[i].member_id));
        if (ledger->model == MODEL_ACCOUNT)
            printf(" (next nonce=%llu)", ledger->accounts[i].nonce);
        if (ledger->accounts[i].reward_remainder > 0.0000001)
            printf(" + %.4f fractional mining reward", ledger->accounts[i].reward_remainder);
        printf("\n");
    }
}

static void print_utxos(const TokenLedger *ledger)
{
    if (ledger->model != MODEL_UTXO)
    {
        printf("UTXO set is available only in UTXO model.\n");
        return;
    }
    printf("Unspent outputs:\n");
    for (size_t i = 0; i < ledger->utxo_count; i++)
        if (!ledger->utxos[i].spent)
            printf("  %s:%u owner=%s amount=%d\n", ledger->utxos[i].transaction_id,
                   ledger->utxos[i].output_index, ledger->utxos[i].owner, ledger->utxos[i].amount);
    if (ledger->utxo_count == 0)
        printf("  (none)\n");
}

static int transfer_tokens(TokenLedger *ledger, const char *sender_id,
                           const char *recipient_id, int amount,
                           unsigned long long nonce, const char *confirmed_txid)
{
    Account *sender = find_account(ledger, sender_id);
    Account *recipient = find_account(ledger, recipient_id);
    const int fee = 1;
    if (!sender || !recipient || sender == recipient || amount <= 0 || sender->balance < 0)
        return 0;
    if (ledger->model == MODEL_ACCOUNT)
    {
        TransactionRecord *sender_history;
        TransactionRecord *recipient_history;
        if (nonce != sender->nonce || sender->nonce == ULLONG_MAX ||
            sender->balance < fee ||
            amount > sender->balance - fee || recipient->balance > 2147483647 - amount)
            return 0;
        sender_history = create_history_record(sender_id, recipient_id, amount, fee, nonce);
        recipient_history = create_history_record(sender_id, recipient_id, amount, fee, nonce);
        if (!sender_history || !recipient_history)
        {
            free(sender_history);
            free(recipient_history);
            return 0;
        }
        sender->balance -= amount + fee;
        recipient->balance += amount;
        append_history_record(sender, sender_history);
        append_history_record(recipient, recipient_history);
        sender->nonce++;
        return 1;
    }
    {
        long long total = 0;
        char data[160];
        char txid[HASH_HEX_LENGTH];
        unsigned int selected[MAX_UTXOS];
        size_t selected_count = 0;
        unsigned long long next_sequence;
        int change;
        TransactionRecord *sender_history;
        TransactionRecord *recipient_history;
        for (size_t i = 0; i < ledger->utxo_count && total < (long long)amount + fee; i++)
            if (!ledger->utxos[i].spent && strcmp(ledger->utxos[i].owner, sender_id) == 0)
            {
                total += ledger->utxos[i].amount;
                selected[selected_count++] = (unsigned int)i;
            }
        if (total < (long long)amount + fee || total > 2147483647 ||
            ledger->utxo_count >= MAX_UTXOS ||
            (total - amount - fee > 0 && ledger->utxo_count + 1 >= MAX_UTXOS) ||
            ledger->transaction_sequence == ULLONG_MAX)
            return 0;
        change = (int)(total - amount - fee);
        next_sequence = ledger->transaction_sequence + 1;
        if (confirmed_txid)
        {
            if (strlen(confirmed_txid) != HASH_HEX_LENGTH - 1)
                return 0;
            snprintf(txid, sizeof(txid), "%s", confirmed_txid);
        }
        else
        {
            snprintf(data, sizeof(data), "%s|%s|%d|%d|%lld|%llu", sender_id, recipient_id, amount, fee,
                     (long long)time(NULL), next_sequence);
            if (!sha256_text(data, txid))
                return 0;
        }
        sender_history = create_history_record(sender_id, recipient_id, amount, fee, 0);
        recipient_history = create_history_record(sender_id, recipient_id, amount, fee, 0);
        if (!sender_history || !recipient_history)
        {
            free(sender_history);
            free(recipient_history);
            return 0;
        }
        for (size_t i = 0; i < selected_count; i++)
            ledger->utxos[selected[i]].spent = 1;
        ledger->transaction_sequence = next_sequence;
        if (!add_utxo(ledger, txid, 0, recipient_id, amount) ||
            (change > 0 && !add_utxo(ledger, txid, 1, sender_id, change)))
        {
            ledger->utxo_count -= change > 0 ? 2 : 1;
            ledger->transaction_sequence--;
            for (size_t i = 0; i < selected_count; i++)
                ledger->utxos[selected[i]].spent = 0;
            free(sender_history);
            free(recipient_history);
            return 0;
        }
        append_history_record(sender, sender_history);
        append_history_record(recipient, recipient_history);
        return 1;
    }
}

static int queue_token_transfer(const Chain *chain, PendingPool *pending,
                                TokenLedger *ledger, const MemberRegistry *members,
                                const char *sender_id, const char *recipient_id,
                                int amount, unsigned long long nonce)
{
    Account *sender = find_account(ledger, sender_id);
    const Member *sender_member = find_member_const(members, sender_id);
    const Member *recipient_member = find_member_const(members, recipient_id);
    long long reserved = 0;
    unsigned long long pending_outgoing = 0;
    const int fee = REWARD_FEE;
    if (!sender || !sender_member || !recipient_member ||
        strcmp(sender_id, recipient_id) == 0 || amount <= 0 ||
        pending->count >= MAX_PENDING_REQUESTS)
        return 0;
    for (size_t i = 0; i < pending->count; i++)
    {
        const LendingRecord *record = &pending->items[i].record;
        if (pending->items[i].status == REQUEST_PENDING &&
            strcmp(record->action, "TRANSFER") == 0 &&
            strcmp(record->reason_code,
                   ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
            strcmp(record->member_id, sender_id) == 0)
        {
            reserved += (long long)record->token_reward + record->fine_amount;
            pending_outgoing++;
        }
    }
    if (ledger->model == MODEL_ACCOUNT)
    {
        if (nonce > (unsigned long long)LLONG_MAX ||
            sender->nonce > ULLONG_MAX - pending_outgoing ||
            nonce != sender->nonce + pending_outgoing)
            return 0;
    }
    else if (nonce != 0)
        return 0;
    if ((long long)ledger_balance(ledger, sender_id) - reserved <
        (long long)amount + fee)
        return 0;
    PendingRequest *request = &pending->items[pending->count];
    LendingRecord *record = &request->record;
    memset(request, 0, sizeof(*request));
    snprintf(record->book_id, sizeof(record->book_id), "TOKEN");
    snprintf(record->copy_id, sizeof(record->copy_id), "TRANSFER");
    snprintf(record->book_title, sizeof(record->book_title), "%s", recipient_id);
    snprintf(record->member_id, sizeof(record->member_id), "%s", sender_id);
    snprintf(record->member_name, sizeof(record->member_name), "%s",
             sender_member->full_name);
    snprintf(record->action, sizeof(record->action), "TRANSFER");
    record->due_date = ledger->model == MODEL_ACCOUNT ? (time_t)nonce : 0;
    record->fine_amount = fee;
    snprintf(record->reason_code, sizeof(record->reason_code), "%s",
             ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO");
    record->nonce = next_record_nonce(chain, pending, sender_id);
    record->token_reward = amount;
    if (!make_record_id(record) || !sign_record(record, member_signing_key(sender_id)))
    {
        memset(request, 0, sizeof(*request));
        return 0;
    }
    request->priority = 1;
    request->reservation_date = time(NULL);
    request->status = REQUEST_PENDING;
    pending->count++;
    return 1;
}

static void print_history(const TokenLedger *ledger, const char *member_id)
{
    Account *account = NULL;
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
            account = (Account *)&ledger->accounts[i];
    if (!account)
    {
        printf("ERROR: Member not found.\n");
        return;
    }
    printf("Transaction history for %s:\n", member_id);
    if (!account->history_head)
        printf("  (empty)\n");
    for (TransactionRecord *record = account->history_head; record; record = record->next)
    {
        if (record->exact_amount > 0.0)
            printf("  %s -> %s amount=%.4f fee=%d nonce=%llu\n", record->sender,
                   record->recipient, record->exact_amount, record->fee, record->nonce);
        else
            printf("  %s -> %s amount=%d fee=%d nonce=%llu\n", record->sender,
                   record->recipient, record->amount, record->fee, record->nonce);
    }
}

static void free_ledger(TokenLedger *ledger)
{
    for (size_t i = 0; i < ledger->account_count; i++)
    {
        TransactionRecord *record = ledger->accounts[i].history_head;
        while (record)
        {
            TransactionRecord *next = record->next;
            free(record);
            record = next;
        }
    }
}

static const char *token_state_path(LedgerModel model)
{
    return model == MODEL_UTXO ? "token_state_utxo.dat" : "token_state_account.dat";
}

static int save_token_ledger(const TokenLedger *ledger, const Chain *chain)
{
    typedef struct
    {
        char sender[20];
        char recipient[20];
        int amount;
        int fee;
        unsigned long long nonce;
        double exact_amount;
    } SavedHistory;
    const char *path = token_state_path(ledger->model);
    char temporary_path[128];
    FILE *file;
    unsigned int model = (unsigned int)ledger->model;
    size_t history_count;
    snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path);
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    int ok = fwrite("TOKSTATE3", 1, 9, file) == 9 &&
             fwrite(&model, sizeof(model), 1, file) == 1 &&
             fwrite(&chain->count, sizeof(chain->count), 1, file) == 1 &&
             fwrite(chain->items[chain->count - 1].hash, sizeof(chain->items[0].hash), 1, file) == 1 &&
             fwrite(&ledger->account_count, sizeof(ledger->account_count), 1, file) == 1 &&
             fwrite(&ledger->utxo_count, sizeof(ledger->utxo_count), 1, file) == 1 &&
             fwrite(&ledger->transaction_sequence, sizeof(ledger->transaction_sequence), 1, file) == 1;
    for (size_t i = 0; ok && i < ledger->account_count; i++)
    {
        const Account *account = &ledger->accounts[i];
        history_count = 0;
        for (const TransactionRecord *entry = account->history_head; entry; entry = entry->next)
            history_count++;
        ok = fwrite(account->member_id, sizeof(account->member_id), 1, file) == 1 &&
             fwrite(&account->balance, sizeof(account->balance), 1, file) == 1 &&
             fwrite(&account->nonce, sizeof(account->nonce), 1, file) == 1 &&
             fwrite(&account->reward_remainder, sizeof(account->reward_remainder), 1, file) == 1 &&
             fwrite(&history_count, sizeof(history_count), 1, file) == 1;
        for (const TransactionRecord *entry = account->history_head; ok && entry; entry = entry->next)
        {
            SavedHistory saved;
            memset(&saved, 0, sizeof(saved));
            snprintf(saved.sender, sizeof(saved.sender), "%s", entry->sender);
            snprintf(saved.recipient, sizeof(saved.recipient), "%s", entry->recipient);
            saved.amount = entry->amount;
            saved.fee = entry->fee;
            saved.nonce = entry->nonce;
            saved.exact_amount = entry->exact_amount;
            ok = fwrite(&saved, sizeof(saved), 1, file) == 1;
        }
    }
    if (ok && ledger->utxo_count > 0)
        ok = fwrite(ledger->utxos, sizeof(ledger->utxos[0]), ledger->utxo_count, file) == ledger->utxo_count;
    if (fflush(file) != 0)
        ok = 0;
    if (fclose(file) != 0)
        ok = 0;
    if (!ok)
    {
        remove(temporary_path);
        return 0;
    }
    remove(path);
    return rename(temporary_path, path) == 0;
}

static int load_token_ledger(TokenLedger *ledger, const MemberRegistry *members,
                             const Chain *chain)
{
    typedef struct
    {
        char sender[20];
        char recipient[20];
        int amount;
        int fee;
        unsigned long long nonce;
    } SavedHistory;
    typedef struct
    {
        char sender[20];
        char recipient[20];
        int amount;
        int fee;
        unsigned long long nonce;
        double exact_amount;
    } SavedHistoryV3;
    const char *path = token_state_path(ledger->model);
    FILE *file = fopen(path, "rb");
    char magic[10] = {0};
    char saved_tip[HASH_HEX_LENGTH];
    size_t saved_chain_count;
    size_t account_count;
    size_t utxo_count;
    unsigned long long transaction_sequence;
    unsigned int model;
    int has_reward_remainder;
    int has_exact_history;
    TokenLedger *loaded;
    if (!file)
        return 0;
    loaded = (TokenLedger *)calloc(1, sizeof(*loaded));
    if (!loaded)
    {
        fclose(file);
        return -1;
    }
    if (fread(magic, 1, 9, file) != 9 ||
        (strcmp(magic, "TOKSTATE1") != 0 && strcmp(magic, "TOKSTATE2") != 0 &&
         strcmp(magic, "TOKSTATE3") != 0) ||
        fread(&model, sizeof(model), 1, file) != 1 ||
        fread(&saved_chain_count, sizeof(saved_chain_count), 1, file) != 1 ||
        fread(saved_tip, sizeof(saved_tip), 1, file) != 1 ||
        fread(&account_count, sizeof(account_count), 1, file) != 1 ||
        fread(&utxo_count, sizeof(utxo_count), 1, file) != 1 ||
        fread(&transaction_sequence, sizeof(transaction_sequence), 1, file) != 1 ||
        model != (unsigned int)ledger->model || saved_chain_count != chain->count ||
        strcmp(saved_tip, chain->items[chain->count - 1].hash) != 0 ||
        account_count != members->count || account_count > MAX_MEMBERS ||
        utxo_count > MAX_UTXOS)
    {
        fclose(file);
        free(loaded);
        fprintf(stderr, "WARNING: saved token ledger is corrupt or belongs to a different chain; using chain-derived balances.\n");
        return -1;
    }
    has_reward_remainder = strcmp(magic, "TOKSTATE2") == 0 ||
                           strcmp(magic, "TOKSTATE3") == 0;
    has_exact_history = strcmp(magic, "TOKSTATE3") == 0;
    loaded->model = ledger->model;
    loaded->account_count = account_count;
    loaded->utxo_count = utxo_count;
    loaded->transaction_sequence = transaction_sequence;
    int valid = 1;
    for (size_t i = 0; valid && i < account_count; i++)
    {
        Account *account = &loaded->accounts[i];
        size_t history_count;
        valid = fread(account->member_id, sizeof(account->member_id), 1, file) == 1 &&
                fread(&account->balance, sizeof(account->balance), 1, file) == 1 &&
                fread(&account->nonce, sizeof(account->nonce), 1, file) == 1 &&
                (!has_reward_remainder ||
                 fread(&account->reward_remainder, sizeof(account->reward_remainder), 1, file) == 1) &&
                fread(&history_count, sizeof(history_count), 1, file) == 1 &&
                strcmp(account->member_id, members->items[i].member_id) == 0 &&
                account->balance >= 0 && account->reward_remainder >= 0.0 &&
                account->reward_remainder < 1.0 && history_count <= 100000;
        for (size_t j = 0; valid && j < history_count; j++)
        {
            SavedHistory saved;
            double exact_amount = 0.0;
            if (has_exact_history)
            {
                SavedHistoryV3 saved_v3;
                if (fread(&saved_v3, sizeof(saved_v3), 1, file) != 1)
                {
                    valid = 0;
                    break;
                }
                snprintf(saved.sender, sizeof(saved.sender), "%s", saved_v3.sender);
                snprintf(saved.recipient, sizeof(saved.recipient), "%s", saved_v3.recipient);
                saved.amount = saved_v3.amount;
                saved.fee = saved_v3.fee;
                saved.nonce = saved_v3.nonce;
                exact_amount = saved_v3.exact_amount;
            }
            else if (fread(&saved, sizeof(saved), 1, file) != 1)
            {
                valid = 0;
                break;
            }
            if (
                saved.amount < 0 || saved.fee < 0 ||
                !(exact_amount >= 0.0 && exact_amount <= (double)INT_MAX) ||
                (strcmp(saved.sender, "SYSTEM") != 0 &&
                 strcmp(saved.sender, "MINING") != 0 &&
                 !find_member((MemberRegistry *)members, saved.sender)) ||
                !find_member((MemberRegistry *)members, saved.recipient))
            {
                valid = 0;
                break;
            }
            TransactionRecord *entry = (TransactionRecord *)calloc(1, sizeof(*entry));
            if (!entry)
            {
                valid = 0;
                break;
            }
            snprintf(entry->sender, sizeof(entry->sender), "%s", saved.sender);
            snprintf(entry->recipient, sizeof(entry->recipient), "%s", saved.recipient);
            entry->amount = saved.amount;
            entry->fee = saved.fee;
            entry->nonce = saved.nonce;
            entry->exact_amount = exact_amount;
            if (account->history_tail)
                account->history_tail->next = entry;
            else
                account->history_head = entry;
            account->history_tail = entry;
        }
    }
    if (valid && utxo_count > 0)
        valid = fread(loaded->utxos, sizeof(loaded->utxos[0]), utxo_count, file) == utxo_count;
    if (valid && fgetc(file) != EOF)
        valid = 0;
    fclose(file);
    for (size_t i = 0; valid && i < utxo_count; i++)
        if (loaded->utxos[i].amount < 0 ||
            loaded->utxos[i].spent < 0 || loaded->utxos[i].spent > 1 ||
            !find_member((MemberRegistry *)members, loaded->utxos[i].owner))
            valid = 0;
    if (!valid)
    {
        free_ledger(loaded);
        free(loaded);
        fprintf(stderr, "ERROR: saved token ledger has invalid contents.\n");
        return -1;
    }
    free_ledger(ledger);
    *ledger = *loaded;
    free(loaded);
    return 1;
}

static int save_library_state(const char *path, const CopyRegistry *copies,
                              const ReservationQueue *reservations, const PendingPool *pending)
{
    char temporary_path[512];
    FILE *file;
    int success;
    snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path);
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    success = fwrite(STATE_MAGIC, 1, 9, file) == 9 &&
              fwrite(&copies->count, sizeof(copies->count), 1, file) == 1 &&
              fwrite(copies->items, sizeof(copies->items[0]), copies->count, file) == copies->count &&
              fwrite(&reservations->count, sizeof(reservations->count), 1, file) == 1 &&
              fwrite(reservations->items, sizeof(reservations->items[0]), reservations->count, file) == reservations->count &&
              fwrite(&pending->count, sizeof(pending->count), 1, file) == 1 &&
              fwrite(pending->items, sizeof(pending->items[0]), pending->count, file) == pending->count &&
              fflush(file) == 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success)
    {
        remove(temporary_path);
        return 0;
    }
    remove(path);
    return rename(temporary_path, path) == 0;
}

static int load_library_state(const char *path, CopyRegistry *copies,
                              ReservationQueue *reservations, PendingPool *pending,
                              const Chain *chain, const BookRegistry *books,
                              const MemberRegistry *members, EVP_PKEY *key)
{
    FILE *file = fopen(path, "rb");
    char magic[10] = {0};
    size_t count;
    CopyRegistry configured_copies = *copies;
    if (!file)
    {
        reservations->count = 0;
        pending->count = 0;
        for (size_t i = 1; i < chain->count; i++)
        {
            const Block *block = &chain->items[i];
            for (size_t j = 0; j < block->record_count; j++)
            {
                const LendingRecord *record = &block->records[j];
                BookCopy *copy = find_copy(copies, record->copy_id);
                if (copy && strcmp(record->action, "BORROWED") == 0)
                {
                    copy->state = COPY_BORROWED;
                    snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s", record->member_id);
                    copy->due_date = record->due_date;
                    copy->renewal_count = 0;
                }
                else if (copy && strcmp(record->action, "RETURNED") == 0)
                {
                    size_t oldest = reservations->count;
                    for (size_t r = 0; r < reservations->count; r++)
                        if (strcmp(reservations->items[r].book_id, record->book_id) == 0 &&
                            (oldest == reservations->count ||
                             reservations->items[r].reservation_date < reservations->items[oldest].reservation_date))
                            oldest = r;
                    if (oldest == reservations->count)
                    {
                        copy->state = COPY_AVAILABLE;
                        copy->current_holder_id[0] = '\0';
                        copy->due_date = 0;
                    }
                    else
                    {
                        copy->state = COPY_RESERVED;
                        snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s",
                                 reservations->items[oldest].member_id);
                        copy->due_date = 0;
                        for (size_t r = oldest + 1; r < reservations->count; r++)
                            reservations->items[r - 1] = reservations->items[r];
                        reservations->count--;
                    }
                    copy->renewal_count = 0;
                }
                else if (copy && strcmp(record->action, "RENEWED") == 0)
                {
                    copy->due_date = record->due_date;
                    copy->renewal_count++;
                }
                else if (strcmp(record->action, "RESERVED") == 0 &&
                         reservations->count < MAX_RESERVATIONS)
                {
                    Reservation *reservation = &reservations->items[reservations->count++];
                    snprintf(reservation->book_id, sizeof(reservation->book_id), "%s", record->book_id);
                    snprintf(reservation->member_id, sizeof(reservation->member_id), "%s", record->member_id);
                    reservation->reservation_date = block->timestamp;
                }
                else if (copy && strcmp(record->action, "LOST") == 0)
                {
                    copy->state = COPY_STATE_LOST;
                    copy->condition = COPY_LOST;
                    copy->current_holder_id[0] = '\0';
                    copy->due_date = 0;
                }
                else if (copy && strcmp(record->action, "CONDITION") == 0 &&
                         record->fine_amount >= COPY_NEW &&
                         record->fine_amount <= COPY_WORN)
                    copy->condition = (CopyCondition)record->fine_amount;
            }
        }
        return 1;
    }
    if (fread(magic, 1, 9, file) != 9 || strcmp(magic, STATE_MAGIC) != 0 ||
        fread(&count, sizeof(count), 1, file) != 1 || count == 0 || count > MAX_COPIES)
    {
        fclose(file);
        fprintf(stderr, "ERROR: library_state.dat is corrupt or unsupported.\n");
        return 0;
    }
    CopyRegistry saved_copies;
    memset(&saved_copies, 0, sizeof(saved_copies));
    saved_copies.count = count;
    if (fread(saved_copies.items, sizeof(saved_copies.items[0]), saved_copies.count, file) != saved_copies.count ||
        fread(&reservations->count, sizeof(reservations->count), 1, file) != 1 ||
        reservations->count > MAX_RESERVATIONS ||
        fread(reservations->items, sizeof(reservations->items[0]), reservations->count, file) != reservations->count ||
        fread(&pending->count, sizeof(pending->count), 1, file) != 1 ||
        pending->count > MAX_PENDING_REQUESTS ||
        fread(pending->items, sizeof(pending->items[0]), pending->count, file) != pending->count)
    {
        fclose(file);
        fprintf(stderr, "ERROR: library_state.dat is truncated or has invalid counts.\n");
        return 0;
    }
    if (fgetc(file) != EOF)
    {
        fclose(file);
        fprintf(stderr, "ERROR: library_state.dat contains unexpected trailing data.\n");
        return 0;
    }
    fclose(file);
    for (size_t i = 0; i < saved_copies.count; i++)
    {
        int known_book = 0;
        for (size_t j = 0; j < books->count; j++)
            if (strcmp(saved_copies.items[i].book_id, books->items[j].book_id) == 0)
                known_book = 1;
        int known_holder = saved_copies.items[i].current_holder_id[0] == '\0';
        for (size_t j = 0; j < members->count; j++)
            if (strcmp(saved_copies.items[i].current_holder_id, members->items[j].member_id) == 0)
                known_holder = 1;
        if (!known_book || saved_copies.items[i].state < COPY_AVAILABLE ||
            saved_copies.items[i].state > COPY_STATE_LOST ||
            saved_copies.items[i].condition < COPY_NEW ||
            saved_copies.items[i].condition > COPY_LOST ||
            saved_copies.items[i].renewal_count > MAX_RENEWALS ||
            !known_holder ||
            ((saved_copies.items[i].state == COPY_BORROWED) &&
             (!saved_copies.items[i].current_holder_id[0] || saved_copies.items[i].due_date <= 0)) ||
            ((saved_copies.items[i].state == COPY_RESERVED) &&
             (!saved_copies.items[i].current_holder_id[0] || saved_copies.items[i].due_date != 0)) ||
            ((saved_copies.items[i].state == COPY_AVAILABLE ||
              saved_copies.items[i].state == COPY_STATE_LOST) &&
             (saved_copies.items[i].current_holder_id[0] || saved_copies.items[i].due_date != 0)) ||
            ((saved_copies.items[i].state == COPY_STATE_LOST) !=
             (saved_copies.items[i].condition == COPY_LOST)))
        {
            fprintf(stderr, "ERROR: invalid copy data in library_state.dat.\n");
            return 0;
        }
        for (size_t j = i + 1; j < saved_copies.count; j++)
            if (strcmp(saved_copies.items[i].copy_id, saved_copies.items[j].copy_id) == 0)
            {
                fprintf(stderr, "ERROR: duplicate copy ID in library_state.dat.\n");
                return 0;
            }
    }
    for (size_t i = 0; i < configured_copies.count; i++)
    {
        int found = 0;
        for (size_t j = 0; j < saved_copies.count; j++)
            if (strcmp(configured_copies.items[i].copy_id, saved_copies.items[j].copy_id) == 0 &&
                strcmp(configured_copies.items[i].book_id, saved_copies.items[j].book_id) == 0)
                found = 1;
        if (!found)
        {
            fprintf(stderr, "ERROR: persisted state does not match copies.txt.\n");
            return 0;
        }
    }
    *copies = saved_copies;
    for (size_t i = 0; i < reservations->count; i++)
    {
        int known_book = 0;
        int known_member = 0;
        for (size_t j = 0; j < books->count; j++)
            if (strcmp(reservations->items[i].book_id, books->items[j].book_id) == 0)
                known_book = 1;
        for (size_t j = 0; j < members->count; j++)
            if (strcmp(reservations->items[i].member_id, members->items[j].member_id) == 0)
                known_member = 1;
        if (!known_book || !known_member || reservations->items[i].reservation_date <= 0)
        {
            fprintf(stderr, "ERROR: invalid reservation in library_state.dat.\n");
            return 0;
        }
    }
    for (size_t i = 0; i < pending->count; i++)
    {
        LendingRecord *identity = &pending->items[i].record;
        int known_member = 0;
        int known_book = 0;
        int known_copy = 0;
        for (size_t j = 0; j < members->count; j++)
            if (strcmp(members->items[j].member_id, identity->member_id) == 0)
                known_member = 1;
        for (size_t j = 0; j < books->count; j++)
            if (strcmp(books->items[j].book_id, identity->book_id) == 0)
                known_book = 1;
        for (size_t j = 0; j < copies->count; j++)
            if (strcmp(copies->items[j].copy_id, identity->copy_id) == 0 &&
                strcmp(copies->items[j].book_id, identity->book_id) == 0)
                known_copy = 1;
        if (strcmp(identity->action, "RESERVED") == 0 && strcmp(identity->copy_id, "QUEUE") == 0)
            known_copy = 1;
        if (strcmp(identity->action, "TRANSFER") == 0)
        {
            known_book = 0;
            known_copy = 0;
            for (size_t j = 0; j < members->count; j++)
                if (strcmp(members->items[j].member_id, identity->book_title) == 0)
                    known_book = known_copy = 1;
        }
        if (pending->items[i].status < REQUEST_PENDING ||
            pending->items[i].status > REQUEST_SUSPICIOUS ||
            !known_member || !known_book || !known_copy ||
            identity->fine_amount < 0 ||
            !validate_or_upgrade_pending_signature(identity, key))
        {
            fprintf(stderr, "ERROR: invalid or unsigned pending request in library_state.dat.\n");
            return 0;
        }
    }
    return 1;
}

static unsigned long long next_record_nonce(const Chain *chain, const PendingPool *pending, const char *member_id)
{
    unsigned long long next_nonce = 0;
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
            if (strcmp(chain->items[i].records[j].member_id, member_id) == 0 &&
                chain->items[i].records[j].nonce >= next_nonce)
                next_nonce = chain->items[i].records[j].nonce + 1;
    for (size_t i = 0; i < pending->count; i++)
        if (strcmp(pending->items[i].record.member_id, member_id) == 0 &&
            pending->items[i].record.nonce >= next_nonce)
            next_nonce = pending->items[i].record.nonce + 1;
    return next_nonce;
}

static int append_transaction(const Chain *chain, PendingPool *pending, const Book *book, const Member *member,
                              const BookCopy *copy, const char *action, time_t due_date,
                              int fine_amount, int token_reward, EVP_PKEY *key)
{
    PendingRequest *request;
    LendingRecord *record;
    if (pending->count >= MAX_PENDING_REQUESTS || fine_amount < 0 ||
        token_reward < 0 || token_reward > 10)
        return 0;
    request = &pending->items[pending->count];
    memset(request, 0, sizeof(*request));
    record = &request->record;
    snprintf(record->book_id, sizeof(record->book_id), "%s", book->book_id);
    snprintf(record->copy_id, sizeof(record->copy_id), "%s", copy ? copy->copy_id : "QUEUE");
    snprintf(record->book_title, sizeof(record->book_title), "%s", book->title);
    snprintf(record->member_id, sizeof(record->member_id), "%s", member->member_id);
    snprintf(record->member_name, sizeof(record->member_name), "%s", member->full_name);
    snprintf(record->action, sizeof(record->action), "%s", action);
    record->due_date = due_date;
    record->fine_amount = fine_amount;
    record->nonce = next_record_nonce(chain, pending, member->member_id);
    record->token_reward = token_reward;
    if (!make_record_id(record) || !sign_record(record, key))
        return 0;
    request->priority = (fine_amount > 0 || strcmp(action, "OVERDUE") == 0) ? 0 : 1;
    request->reservation_date = time(NULL);
    request->status = REQUEST_PENDING;
    pending->count++;
    return 1;
}

static int mark_request_suspicious(PendingRequest *request, const char *reason, EVP_PKEY *key)
{
    snprintf(request->record.reason_code, sizeof(request->record.reason_code), "SUSPICIOUS:%.52s", reason);
    request->status = REQUEST_SUSPICIOUS;
    return make_record_id(&request->record) && sign_record(&request->record, key);
}

static int detect_suspicious_borrow(const Chain *chain, const PendingPool *pending,
                                    const CopyRegistry *copies, const Book *book,
                                    const Member *member, const LendingRecord *candidate,
                                    char *reason, size_t reason_size)
{
    size_t held_copies = 0;
    time_t now = time(NULL);
    for (size_t i = 0; i < copies->count; i++)
        if (copies->items[i].state == COPY_BORROWED &&
            strcmp(copies->items[i].current_holder_id, member->member_id) == 0)
            held_copies++;
    if (held_copies >= MAX_CONCURRENT_BORROWS)
    {
        snprintf(reason, reason_size, "concurrent-borrow-limit");
        return 1;
    }
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *existing = &chain->items[i].records[j];
            if (strcmp(existing->member_id, member->member_id) == 0 &&
                strcmp(existing->book_id, book->book_id) == 0 &&
                strcmp(existing->action, "RETURNED") == 0 &&
                (now >= chain->items[i].timestamp
                     ? now - chain->items[i].timestamp
                     : chain->items[i].timestamp - now) <= RAPID_REBORROW_WINDOW_SECONDS)
            {
                snprintf(reason, reason_size, "rapid-reborrow-within-24h");
                return 1;
            }
            if (strcmp(existing->record_id, candidate->record_id) == 0)
            {
                snprintf(reason, reason_size, "duplicate-request-id");
                return 1;
            }
        }
    for (size_t i = 0; i < pending->count; i++)
    {
        const LendingRecord *existing = &pending->items[i].record;
        if (existing == candidate)
            continue;
        if (strcmp(existing->record_id, candidate->record_id) == 0 ||
            (strcmp(existing->member_id, member->member_id) == 0 &&
             strcmp(existing->book_id, book->book_id) == 0 &&
             strcmp(existing->copy_id, candidate->copy_id) == 0 &&
             strcmp(existing->action, candidate->action) == 0))
        {
            snprintf(reason, reason_size, "duplicate-request");
            return 1;
        }
    }
    return 0;
}

static int mine_one_block(Block *block, const Chain *chain, int difficulty, const char *sealed_by,
                          unsigned long long *attempts, unsigned long long miner_attempts[MINERS_IN_POOL],
                          const int miner_rates[MINERS_IN_POOL], size_t miner_count)
{
    int total_rate = 0;
    char previous_hash[HASH_HEX_LENGTH];
    block->index = (int)chain->count;
    snprintf(previous_hash, sizeof(previous_hash), "%s", chain->items[chain->count - 1].hash);
    memcpy(block->previous_hash, previous_hash, sizeof(block->previous_hash));
    block->difficulty = difficulty;
    block->nonce = 0;
    block->timestamp = time(NULL);
    if (block->timestamp <= chain->items[chain->count - 1].timestamp)
        block->timestamp = chain->items[chain->count - 1].timestamp + 1;
    snprintf(block->sealed_by, sizeof(block->sealed_by), "%s", sealed_by);
    if (!finalize_block(block))
        return 0;
    for (size_t i = 0; i < miner_count; i++)
        total_rate += miner_rates ? miner_rates[i] : 0;
    for (;;)
    {
        if (!hash_block(block, block->hash))
            return 0;
        (*attempts)++;
        if (miner_attempts && miner_rates)
        {
            int draw = rand() % total_rate;
            for (size_t i = 0; i < miner_count; i++)
            {
                if (draw < miner_rates[i])
                {
                    miner_attempts[i]++;
                    break;
                }
                draw -= miner_rates[i];
            }
        }
        if (has_pow_prefix(block->hash, difficulty))
            return 1;
        block->nonce++;
    }
}

static void print_pool_shares(const unsigned long long attempts[MINERS_IN_POOL],
                              const char *const member_ids[MINERS_IN_POOL],
                              size_t miner_count, int block_reward)
{
    unsigned long long total = 0;
    for (size_t i = 0; i < miner_count; i++)
        total += attempts[i];
    printf("Miner ID       Attempts   Share      Reward\n");
    for (size_t i = 0; i < miner_count; i++)
    {
        double share = total ? (double)attempts[i] / (double)total : 0.0;
        printf("%-14s %-10llu %6.2f%%    %.4f\n", member_ids[i], attempts[i],
               share * 100.0, share * block_reward * 0.98);
    }
    printf("Pool fee: %.2f coins (2%%)\n", block_reward * 0.02);
}

static int pending_request_precedes(const PendingRequest *left, const PendingRequest *right)
{
    if (left->priority != right->priority)
        return left->priority < right->priority;
    return left->reservation_date < right->reservation_date;
}

static int confirm_pending(Chain *chain, PendingPool *pending, CopyRegistry *copies,
                           ReservationQueue *reservations, TokenLedger *ledger,
                           const MemberRegistry *members, EVP_PKEY *key,
                           const char *ledger_path, const char *state_path,
                           int difficulty, const char *mode, int cloud_rounds,
                           const char *const payout_members[MINERS_IN_POOL],
                           size_t payout_count)
{
    unsigned long long attempts;
    int miner_rates[MINERS_IN_POOL];
    unsigned long long block_miner_attempts[MAX_BLOCKS][MINERS_IN_POOL] = {{0}};
    size_t eligible_count = 0;
    size_t order[MAX_PENDING_REQUESTS];
    int selected[MAX_PENDING_REQUESTS] = {0};
    unsigned long long next_nonces[MAX_MEMBERS] = {0};
    if ((strcmp(mode, "pool") == 0 && (payout_count < 2 || payout_count > MINERS_IN_POOL)) ||
        (strcmp(mode, "pool") != 0 && payout_count != 1))
    {
        printf("ERROR: supply one registered payout member for solo/cloud, or 2 to %d distinct members for pool mining.\n",
               MINERS_IN_POOL);
        return 0;
    }
    for (size_t i = 0; i < payout_count; i++)
    {
        if (!find_member_const(members, payout_members[i]))
        {
            printf("ERROR: mining payout recipient '%s' is not a registered member.\n",
                   payout_members[i]);
            return 0;
        }
        for (size_t j = 0; j < i; j++)
            if (strcmp(payout_members[i], payout_members[j]) == 0)
            {
                printf("ERROR: each pool miner must be a distinct registered member.\n");
                return 0;
            }
    }
    if (pending->count == 0)
    {
        printf("Pending pool is empty.\n");
        return 1;
    }
    for (size_t i = 0; i < pending->count; i++)
        if (pending->items[i].status == REQUEST_PENDING &&
            (strcmp(pending->items[i].record.action, "TRANSFER") != 0 ||
             strcmp(pending->items[i].record.reason_code,
                    ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0))
        {
            order[eligible_count++] = i;
            selected[i] = 1;
        }
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
            for (size_t k = 0; k < members->count; k++)
                if (strcmp(chain->items[i].records[j].member_id, members->items[k].member_id) == 0)
                    next_nonces[k] = chain->items[i].records[j].nonce + 1;
    for (size_t i = 1; i < eligible_count; i++)
    {
        size_t value = order[i];
        size_t j = i;
        while (j > 0 && pending_request_precedes(&pending->items[value], &pending->items[order[j - 1]]))
        {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = value;
    }
    if (eligible_count == 0)
    {
        printf("No mineable requests; suspicious requests require manual review.\n");
        return 1;
    }
    if (chain->count + (eligible_count + MAX_RECORDS_PER_BLOCK - 1) / MAX_RECORDS_PER_BLOCK > MAX_BLOCKS)
    {
        printf("ERROR: chain capacity exceeded.\n");
        return 0;
    }
    for (size_t i = 0; i < payout_count; i++)
        miner_rates[i] = 10 + rand() % 91;
    {
        size_t old_count = chain->count;
        size_t cursor = 0;
        while (cursor < eligible_count)
        {
            Block *confirmed = &chain->items[chain->count];
            unsigned long long miner_attempts[MINERS_IN_POOL] = {0};
            attempts = 0;
            memset(confirmed, 0, sizeof(*confirmed));
            confirmed->record_count = eligible_count - cursor;
            if (confirmed->record_count > MAX_RECORDS_PER_BLOCK)
                confirmed->record_count = MAX_RECORDS_PER_BLOCK;
            for (size_t j = 0; j < confirmed->record_count; j++)
            {
                LendingRecord *record = &confirmed->records[j];
                size_t member_index = members->count;
                *record = pending->items[order[cursor + j]].record;
                for (size_t k = 0; k < members->count; k++)
                    if (strcmp(record->member_id, members->items[k].member_id) == 0)
                    {
                        member_index = k;
                        break;
                    }
                if (member_index == members->count)
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: pending request refers to unknown member.\n");
                    return 0;
                }
                record->nonce = next_nonces[member_index]++;
                if (!make_record_id(record) || !sign_record(record, key))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: could not re-sign request with its confirmation nonce.\n");
                    return 0;
                }
            }
            if (!mine_one_block(confirmed, chain, difficulty,
                                strcmp(mode, "pool") == 0 ? "pool-miners" :
                                strcmp(mode, "cloud") == 0 ? "cloud-miner" : "solo-miner",
                                &attempts,
                                strcmp(mode, "pool") == 0 ? miner_attempts : NULL,
                                strcmp(mode, "pool") == 0 ? miner_rates : NULL,
                                strcmp(mode, "pool") == 0 ? payout_count : 0))
            {
                chain->count = old_count;
                printf("ERROR: could not mine pending block.\n");
                return 0;
            }
            if (strcmp(mode, "pool") == 0)
                memcpy(block_miner_attempts[chain->count - old_count], miner_attempts,
                       sizeof(miner_attempts));
            chain->count++;
            printf("Mined block %d: records=%zu, reward=%d, txid=%s, hash attempts=%llu\n",
                   confirmed->index, confirmed->record_count, confirmed->token_reward,
                   confirmed->transaction_id[0] ? confirmed->transaction_id : "none", attempts);
            cursor += confirmed->record_count;
        }
        if (!save_chain(ledger_path, chain))
        {
            chain->count = old_count;
            printf("ERROR: could not persist mined blocks.\n");
            return 0;
        }
        for (size_t i = old_count; i < chain->count; i++)
        {
            for (size_t j = 0; j < chain->items[i].record_count; j++)
            {
                LendingRecord *record = &chain->items[i].records[j];
                if (strcmp(record->action, "RETURNED") == 0 &&
                    record->token_reward > 0)
                    apply_record_reward(ledger, record);
                else if (strcmp(record->action, "TRANSFER") == 0 &&
                         strcmp(record->reason_code,
                                ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
                         !transfer_tokens(ledger, record->member_id, record->book_title,
                                          record->token_reward,
                                          (unsigned long long)record->due_date,
                                          record->record_id))
                {
                    fprintf(stderr, "ERROR: confirmed token transfer failed to apply; inspect chain and ledger backups.\n");
                    return 0;
                }
            }
            if (strcmp(mode, "pool") == 0)
            {
                unsigned long long total_attempts = 0;
                for (size_t miner = 0; miner < payout_count; miner++)
                    total_attempts += block_miner_attempts[i - old_count][miner];
                if (total_attempts == 0)
                {
                    fprintf(stderr, "ERROR: pool produced no measured mining contributions.\n");
                    return 0;
                }
                for (size_t miner = 0; miner < payout_count; miner++)
                {
                    double share = (double)block_miner_attempts[i - old_count][miner] /
                                   (double)total_attempts;
                    double payout = share * MINING_REWARD * 0.98;
                    if (!apply_mining_reward(ledger, payout_members[miner], payout,
                                             chain->items[i].hash, (unsigned int)miner))
                    {
                        fprintf(stderr, "ERROR: could not credit pool reward to %s.\n",
                                payout_members[miner]);
                        return 0;
                    }
                }
                print_pool_shares(block_miner_attempts[i - old_count], payout_members,
                                  payout_count, MINING_REWARD);
            }
            else if (strcmp(mode, "solo") == 0)
            {
                if (!apply_mining_reward(ledger, payout_members[0], MINING_REWARD,
                                         chain->items[i].hash, 0))
                {
                    fprintf(stderr, "ERROR: could not credit solo mining reward to %s.\n",
                            payout_members[0]);
                    return 0;
                }
                printf("Solo miner %s reward: %d coins\n", payout_members[0], MINING_REWARD);
            }
            printf("Confirmed block %d after chain persistence.\n", chain->items[i].index);
            printf("Ledger after confirmed block %d:\n", chain->items[i].index);
            print_balances(ledger);
            print_utxos(ledger);
        }
        {
            size_t remaining = 0;
            for (size_t i = 0; i < pending->count; i++)
                if (!selected[i])
                    pending->items[remaining++] = pending->items[i];
            pending->count = remaining;
        }
        printf("Pending pool cleared; %zu request(s) confirmed.\n", eligible_count);
        if (!save_library_state(state_path, copies, reservations, pending))
        {
            fprintf(stderr, "ERROR: confirmed chain but could not persist library state.\n");
            return 0;
        }
        if (!save_token_ledger(ledger, chain))
            fprintf(stderr, "ERROR: confirmed chain but could not persist token ledger; chain rewards will be replayed at next startup.\n");
        if (strcmp(mode, "cloud") == 0)
        {
            int gross = 0;
            int fees = 0;
            double net_profit;
            printf("Cloud rental summary (%d rounds):\n", cloud_rounds);
            for (int round = 1; round <= cloud_rounds; round++)
            {
                gross += MINING_REWARD;
                fees += CLOUD_RENTAL_FEE + CLOUD_MAINTENANCE_FEE;
                printf("  round %d: gross=%d, rental=%d, maintenance=%d, cumulative net=%d\n", round,
                       MINING_REWARD, CLOUD_RENTAL_FEE, CLOUD_MAINTENANCE_FEE, gross - fees);
                if (fees > gross)
                    printf("  WARNING: cloud rental is unprofitable at round %d.\n", round);
            }
            net_profit = (double)(gross - fees);
            printf("Gross earnings=%d, total fees=%d, net profit=%.2f coins\n",
                   gross, fees, net_profit);
            if (gross > 0 &&
                !apply_mining_reward(ledger, payout_members[0], (double)gross,
                                     chain->items[chain->count - 1].hash, 0))
                fprintf(stderr, "ERROR: could not credit cloud mining reward to %s.\n",
                        payout_members[0]);
            else
                printf("Cloud mining reward credited to %s: %d coins gross; rental costs are reported separately.\n",
                       payout_members[0], gross);
            if (!save_token_ledger(ledger, chain))
                fprintf(stderr, "ERROR: could not persist cloud mining payout.\n");
            print_balances(ledger);
            print_utxos(ledger);
        }
    }
    return 1;
}

static void print_records(const Chain *chain, EVP_PKEY *key)
{
    char timestamp[32];
    for (size_t i = 1; i < chain->count; i++)
    {
        const Block *block = &chain->items[i];
        struct tm *time_info = localtime(&block->timestamp);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);
        for (size_t j = 0; j < block->record_count; j++)
        {
            const LendingRecord *record = &block->records[j];
            printf("[%d:%zu] %s | %s | copy=%s | %s (%s) | %s | due=%lld fine=%d reward=%d | signature: %s\n",
                   block->index, j + 1, timestamp, record->book_title, record->copy_id,
                   record->member_name, record->member_id, record->action,
                   (long long)record->due_date, record->fine_amount, record->token_reward,
                   verify_record_signature(record, key) ? "VALID" : "INVALID");
        }
    }
    if (chain->count == 1)
        printf("No lending records yet.\n");
}

static const char *copy_state_text(CopyState state)
{
    switch (state)
    {
    case COPY_AVAILABLE:
        return "AVAILABLE";
    case COPY_BORROWED:
        return "BORROWED";
    case COPY_RESERVED:
        return "RESERVED";
    case COPY_STATE_LOST:
        return "LOST";
    }
    return "INVALID";
}

static const char *copy_condition_text(CopyCondition condition)
{
    switch (condition)
    {
    case COPY_NEW:
        return "NEW";
    case COPY_GOOD:
        return "GOOD";
    case COPY_WORN:
        return "WORN";
    case COPY_LOST:
        return "LOST";
    }
    return "INVALID";
}

static int parse_copy_condition(const char *text, CopyCondition *condition)
{
    if (strcmp(text, "NEW") == 0)
        *condition = COPY_NEW;
    else if (strcmp(text, "GOOD") == 0)
        *condition = COPY_GOOD;
    else if (strcmp(text, "WORN") == 0)
        *condition = COPY_WORN;
    else
        return 0;
    return 1;
}

static void print_copies(const CopyRegistry *copies, const BookRegistry *books)
{
    printf("Copy inventory:\n");
    for (size_t i = 0; i < copies->count; i++)
    {
        const BookCopy *copy = &copies->items[i];
        const Book *book = find_book_const(books, copy->book_id);
        printf("  %s | %s | %s | %s | holder=%s | due=%lld\n",
               copy->copy_id, copy->book_id, book ? book->title : "(unknown)",
               copy_state_text(copy->state), copy->current_holder_id[0] ? copy->current_holder_id : "-",
               (long long)copy->due_date);
    }
}

static void print_reservations(const ReservationQueue *reservations)
{
    printf("Reservation queue: %zu waiting member(s)\n", reservations->count);
    for (size_t i = 0; i < reservations->count; i++)
        printf("  %zu. book=%s member=%s reserved_at=%lld\n", i + 1,
               reservations->items[i].book_id, reservations->items[i].member_id,
               (long long)reservations->items[i].reservation_date);
}

static BookCopy *select_copy(CopyRegistry *copies, const char *book_id,
                             const char *member_id, const char *copy_id)
{
    if (copy_id && copy_id[0])
    {
        BookCopy *copy = find_copy(copies, copy_id);
        return copy && strcmp(copy->book_id, book_id) == 0 ? copy : NULL;
    }
    for (size_t i = 0; i < copies->count; i++)
        if (strcmp(copies->items[i].book_id, book_id) == 0 &&
            copies->items[i].state == COPY_RESERVED &&
            strcmp(copies->items[i].current_holder_id, member_id) == 0)
            return &copies->items[i];
    for (size_t i = 0; i < copies->count; i++)
        if (strcmp(copies->items[i].book_id, book_id) == 0 &&
            copies->items[i].state == COPY_AVAILABLE)
            return &copies->items[i];
    return NULL;
}

static int has_available_copy(const CopyRegistry *copies, const char *book_id)
{
    for (size_t i = 0; i < copies->count; i++)
        if (strcmp(copies->items[i].book_id, book_id) == 0 &&
            copies->items[i].state == COPY_AVAILABLE)
            return 1;
    return 0;
}

static int has_reservation_from_other(const ReservationQueue *reservations,
                                      const char *book_id, const char *member_id)
{
    for (size_t i = 0; i < reservations->count; i++)
        if (strcmp(reservations->items[i].book_id, book_id) == 0 &&
            strcmp(reservations->items[i].member_id, member_id) != 0)
            return 1;
    return 0;
}

static int assign_next_reservation(ReservationQueue *reservations,
                                   BookCopy *copy, const char *book_id)
{
    size_t oldest = reservations->count;
    for (size_t i = 0; i < reservations->count; i++)
        if (strcmp(reservations->items[i].book_id, book_id) == 0 &&
            (oldest == reservations->count ||
             reservations->items[i].reservation_date < reservations->items[oldest].reservation_date))
            oldest = i;
    if (oldest == reservations->count)
        return 0;
    copy->state = COPY_RESERVED;
    snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s",
             reservations->items[oldest].member_id);
    copy->due_date = 0;
    for (size_t i = oldest + 1; i < reservations->count; i++)
        reservations->items[i - 1] = reservations->items[i];
    reservations->count--;
    return 1;
}

static int pending_record_exists(const Chain *chain, const PendingPool *pending,
                                 const char *copy_id, const char *action, time_t due_date)
{
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if (strcmp(record->copy_id, copy_id) == 0 &&
                strcmp(record->action, action) == 0 && record->due_date == due_date)
                return 1;
        }
    for (size_t i = 0; i < pending->count; i++)
    {
        if (pending->items[i].status != REQUEST_PENDING)
            continue;
        const LendingRecord *record = &pending->items[i].record;
        if (strcmp(record->copy_id, copy_id) == 0 &&
            strcmp(record->action, action) == 0 && record->due_date == due_date)
            return 1;
    }
    return 0;
}

static int validate_inventory_projection(const Chain *chain, const PendingPool *pending,
                                         const CopyRegistry *copies)
{
    for (size_t c = 0; c < copies->count; c++)
    {
        const BookCopy *copy = &copies->items[c];
        const LendingRecord *latest = NULL;
        for (size_t i = 1; i < chain->count; i++)
            for (size_t j = 0; j < chain->items[i].record_count; j++)
            {
                const LendingRecord *record = &chain->items[i].records[j];
                if (strcmp(record->copy_id, copy->copy_id) == 0 &&
                    (strcmp(record->action, "BORROWED") == 0 ||
                     strcmp(record->action, "RETURNED") == 0 ||
                     strcmp(record->action, "RENEWED") == 0 ||
                     strcmp(record->action, "LOST") == 0))
                    latest = record;
            }
        for (size_t i = 0; i < pending->count; i++)
        {
            if (pending->items[i].status != REQUEST_PENDING)
                continue;
            const LendingRecord *record = &pending->items[i].record;
            if (strcmp(record->copy_id, copy->copy_id) == 0 &&
                (strcmp(record->action, "BORROWED") == 0 ||
                 strcmp(record->action, "RETURNED") == 0 ||
                 strcmp(record->action, "RENEWED") == 0 ||
                 strcmp(record->action, "LOST") == 0))
                latest = record;
        }
        if (!latest)
        {
            if (copy->state != COPY_AVAILABLE && copy->state != COPY_STATE_LOST)
            {
                fprintf(stderr, "ERROR: copy state has no corresponding lending record: %s.\n", copy->copy_id);
                return 0;
            }
            continue;
        }
        if (strcmp(latest->action, "BORROWED") == 0 || strcmp(latest->action, "RENEWED") == 0)
        {
            if (copy->state != COPY_BORROWED ||
                strcmp(copy->current_holder_id, latest->member_id) != 0 ||
                copy->due_date != latest->due_date)
            {
                fprintf(stderr, "ERROR: persisted state disagrees with chain for copy %s.\n", copy->copy_id);
                return 0;
            }
        }
        else if (strcmp(latest->action, "RETURNED") == 0)
        {
            if (copy->state == COPY_BORROWED || copy->state == COPY_STATE_LOST)
            {
                fprintf(stderr, "ERROR: returned copy has an invalid persisted state: %s.\n", copy->copy_id);
                return 0;
            }
        }
        else if (copy->state != COPY_STATE_LOST)
        {
            fprintf(stderr, "ERROR: lost-copy record disagrees with persisted state: %s.\n", copy->copy_id);
            return 0;
        }
    }
    for (size_t c = 0; c < copies->count; c++)
    {
        const LendingRecord *latest_condition = NULL;
        for (size_t i = 1; i < chain->count; i++)
            for (size_t j = 0; j < chain->items[i].record_count; j++)
            {
                const LendingRecord *record = &chain->items[i].records[j];
                if (strcmp(record->action, "CONDITION") == 0 &&
                    strcmp(record->copy_id, copies->items[c].copy_id) == 0)
                    latest_condition = record;
            }
        for (size_t i = 0; i < pending->count; i++)
            if (pending->items[i].status == REQUEST_PENDING &&
                strcmp(pending->items[i].record.action, "CONDITION") == 0 &&
                strcmp(pending->items[i].record.copy_id, copies->items[c].copy_id) == 0)
                latest_condition = &pending->items[i].record;
        if (latest_condition &&
            copies->items[c].condition != (CopyCondition)latest_condition->fine_amount)
        {
            fprintf(stderr, "ERROR: persisted condition disagrees with signed event for copy %s.\n",
                    copies->items[c].copy_id);
            return 0;
        }
    }
    return 1;
}

static int queue_borrow(const Chain *chain, PendingPool *pending, CopyRegistry *copies,
                        Book *book, Member *member, const char *copy_id, EVP_PKEY *key)
{
    BookCopy *copy = select_copy(copies, book->book_id, member->member_id, copy_id);
    time_t now = time(NULL);
    if (!copy || (copy->state != COPY_AVAILABLE &&
                  !(copy->state == COPY_RESERVED && strcmp(copy->current_holder_id, member->member_id) == 0)))
    {
        printf("ERROR: no available copy for this member.\n");
        return 0;
    }
    if (!append_transaction(chain, pending, book, member, copy, "BORROWED",
                            now + LOAN_PERIOD_SECONDS, 0, 0, key))
    {
        printf("ERROR: could not create signed borrow request.\n");
        return 0;
    }
    {
        char reason[64];
        PendingRequest *request = &pending->items[pending->count - 1];
        if (detect_suspicious_borrow(chain, pending, copies, book, member,
                                     &request->record, reason, sizeof(reason)))
        {
            if (!mark_request_suspicious(request, reason, key))
            {
                pending->count--;
                printf("ERROR: could not sign fraud-review request.\n");
                return 0;
            }
            printf("Borrow request flagged SUSPICIOUS (%s); inventory was not changed.\n", reason);
            return 1;
        }
    }
    copy->state = COPY_BORROWED;
    snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s", member->member_id);
    copy->due_date = now + LOAN_PERIOD_SECONDS;
    copy->renewal_count = 0;
    printf("Borrow request queued for %s, due at %lld.\n", copy->copy_id, (long long)copy->due_date);
    return 1;
}

static int queue_return(const Chain *chain, PendingPool *pending, CopyRegistry *copies,
                        ReservationQueue *reservations, Book *book, Member *member,
                        const char *copy_id, EVP_PKEY *key)
{
    BookCopy *copy = NULL;
    if (copy_id && copy_id[0])
        copy = find_copy(copies, copy_id);
    else
        for (size_t i = 0; i < copies->count; i++)
            if (strcmp(copies->items[i].book_id, book->book_id) == 0 &&
                copies->items[i].state == COPY_BORROWED &&
                strcmp(copies->items[i].current_holder_id, member->member_id) == 0)
            {
                copy = &copies->items[i];
                break;
            }
    time_t now = time(NULL);
    int late_days = 0;
    int fine = 0;
    int reward;
    if (!copy || strcmp(copy->book_id, book->book_id) != 0 ||
        copy->state != COPY_BORROWED ||
        strcmp(copy->current_holder_id, member->member_id) != 0)
    {
        printf("ERROR: no active loan of that copy by this member.\n");
        return 0;
    }
    if (now > copy->due_date)
    {
        time_t overdue_seconds = now - copy->due_date;
        late_days = (int)((overdue_seconds + 86400 - 1) / 86400);
        fine = late_days * FINE_PER_DAY;
    }
    reward = late_days == 0 ? 10 : 5;
    if (!append_transaction(chain, pending, book, member, copy, "RETURNED",
                            copy->due_date, fine, reward, key))
    {
        printf("ERROR: could not create signed return request.\n");
        return 0;
    }
    if (!assign_next_reservation(reservations, copy, book->book_id))
    {
        copy->state = COPY_AVAILABLE;
        copy->current_holder_id[0] = '\0';
        copy->due_date = 0;
    }
    copy->renewal_count = 0;
    printf("Return request queued for %s; late days=%d fine=%d reward=%d.\n",
           copy->copy_id, late_days, fine, reward);
    if (copy->state == COPY_RESERVED)
        printf("Copy automatically offered to the next reservation: %s.\n", copy->current_holder_id);
    return 1;
}

static int fine_record_assesses_debt(const LendingRecord *record)
{
    return record->fine_amount > 0 &&
           (strcmp(record->action, "OVERDUE") == 0 ||
            strcmp(record->action, "RETURNED") == 0);
}

static int fine_group_balance(const Chain *chain, const PendingPool *pending,
                              const char *member_id, const char *copy_id, time_t due_date)
{
    int assessed = 0;
    int paid = 0;
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if (fine_record_assesses_debt(record) &&
                strcmp(record->member_id, member_id) == 0 &&
                strcmp(record->copy_id, copy_id) == 0 &&
                record->due_date == due_date && record->fine_amount > assessed)
                assessed = record->fine_amount;
            if (strcmp(record->action, "FINEPAID") == 0 &&
                strcmp(record->member_id, member_id) == 0 &&
                strcmp(record->copy_id, copy_id) == 0 &&
                record->due_date == due_date)
                paid += record->fine_amount;
        }
    for (size_t i = 0; i < pending->count; i++)
    {
        const LendingRecord *record = &pending->items[i].record;
        if (fine_record_assesses_debt(record) &&
            strcmp(record->member_id, member_id) == 0 &&
            strcmp(record->copy_id, copy_id) == 0 &&
            record->due_date == due_date && record->fine_amount > assessed)
            assessed = record->fine_amount;
        if (strcmp(record->action, "FINEPAID") == 0 &&
            strcmp(record->member_id, member_id) == 0 &&
            strcmp(record->copy_id, copy_id) == 0 &&
            record->due_date == due_date)
            paid += record->fine_amount;
    }
    return paid >= assessed ? 0 : assessed - paid;
}

static int copy_fine_balance(const Chain *chain, const PendingPool *pending,
                             const BookCopy *copy, const char *member_id)
{
    int total = 0;
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            int first_for_due_date = fine_record_assesses_debt(record) &&
                                     strcmp(record->member_id, member_id) == 0 &&
                                     strcmp(record->copy_id, copy->copy_id) == 0;
            if (!first_for_due_date)
                continue;
            for (size_t pi = 1; pi <= i && first_for_due_date; pi++)
            {
                size_t limit = pi == i ? j : chain->items[pi].record_count;
                for (size_t pj = 0; pj < limit; pj++)
                {
                    const LendingRecord *previous = &chain->items[pi].records[pj];
                    if (fine_record_assesses_debt(previous) &&
                        strcmp(previous->member_id, member_id) == 0 &&
                        strcmp(previous->copy_id, copy->copy_id) == 0 &&
                        previous->due_date == record->due_date)
                    {
                        first_for_due_date = 0;
                        break;
                    }
                }
            }
            if (first_for_due_date)
                total += fine_group_balance(chain, pending, member_id, copy->copy_id,
                                            record->due_date);
        }
    for (size_t i = 0; i < pending->count; i++)
    {
        const LendingRecord *record = &pending->items[i].record;
        int confirmed_group_exists = 0;
        if (!fine_record_assesses_debt(record) ||
            strcmp(record->member_id, member_id) != 0 ||
            strcmp(record->copy_id, copy->copy_id) != 0)
            continue;
        for (size_t ci = 1; ci < chain->count && !confirmed_group_exists; ci++)
            for (size_t cj = 0; cj < chain->items[ci].record_count; cj++)
            {
                const LendingRecord *confirmed = &chain->items[ci].records[cj];
                if (fine_record_assesses_debt(confirmed) &&
                    strcmp(confirmed->member_id, member_id) == 0 &&
                    strcmp(confirmed->copy_id, copy->copy_id) == 0 &&
                    confirmed->due_date == record->due_date)
                {
                    confirmed_group_exists = 1;
                    break;
                }
            }
        if (!confirmed_group_exists)
        {
            int first_pending = 1;
            for (size_t p = 0; p < i; p++)
                if (fine_record_assesses_debt(&pending->items[p].record) &&
                    strcmp(pending->items[p].record.member_id, member_id) == 0 &&
                    strcmp(pending->items[p].record.copy_id, copy->copy_id) == 0 &&
                    pending->items[p].record.due_date == record->due_date)
                    first_pending = 0;
            if (first_pending)
                total += fine_group_balance(chain, pending, member_id, copy->copy_id,
                                            record->due_date);
        }
    }
    return total;
}

static time_t oldest_unsettled_fine_due(const Chain *chain, const PendingPool *pending,
                                        const BookCopy *copy, const char *member_id,
                                        int *balance)
{
    time_t oldest_due = 0;
    *balance = 0;
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if (fine_record_assesses_debt(record) &&
                strcmp(record->member_id, member_id) == 0 &&
                strcmp(record->copy_id, copy->copy_id) == 0)
            {
                int group_balance = fine_group_balance(chain, pending, member_id,
                                                       copy->copy_id, record->due_date);
                if (group_balance > 0 &&
                    (oldest_due == 0 || record->due_date < oldest_due))
                {
                    oldest_due = record->due_date;
                    *balance = group_balance;
                }
            }
        }
    for (size_t i = 0; i < pending->count; i++)
    {
        const LendingRecord *record = &pending->items[i].record;
        if (fine_record_assesses_debt(record) &&
            strcmp(record->member_id, member_id) == 0 &&
            strcmp(record->copy_id, copy->copy_id) == 0)
        {
            int group_balance = fine_group_balance(chain, pending, member_id,
                                                   copy->copy_id, record->due_date);
            if (group_balance > 0 &&
                (oldest_due == 0 || record->due_date < oldest_due))
            {
                oldest_due = record->due_date;
                *balance = group_balance;
            }
        }
    }
    return oldest_due;
}

static int queue_fine_settlement(const Chain *chain, PendingPool *pending,
                                 CopyRegistry *copies, const BookRegistry *books,
                                 const Member *member, const char *copy_id, int amount,
                                 EVP_PKEY *key)
{
    BookCopy *copy = find_copy(copies, copy_id);
    const Book *book;
    time_t due_date;
    int payable = 0;
    if (!copy || amount <= 0)
    {
        printf("ERROR: fine settlement requires a positive amount and a valid copy ID.\n");
        return 0;
    }
    book = find_book_const(books, copy->book_id);
    if (!book)
        return 0;
    due_date = oldest_unsettled_fine_due(chain, pending, copy, member->member_id,
                                         &payable);
    if (due_date == 0 || amount > payable)
    {
        printf("ERROR: amount exceeds the oldest unsettled fine balance (%d).\n", payable);
        return 0;
    }
    if (!append_transaction(chain, pending, book, member, copy, "FINEPAID",
                            due_date, amount, 0, key))
    {
        printf("ERROR: could not create signed fine-settlement request.\n");
        return 0;
    }
    printf("Fine settlement queued for mining: member=%s copy=%s amount=%d.\n",
           member->member_id, copy_id, amount);
    return 1;
}

static int queue_reservation(const Chain *chain, PendingPool *pending,
                             ReservationQueue *reservations, const CopyRegistry *copies,
                             Book *book, Member *member, EVP_PKEY *key)
{
    if (has_available_copy(copies, book->book_id))
    {
        printf("ERROR: a copy is available; borrow it instead of reserving.\n");
        return 0;
    }
    if (reservations->count >= MAX_RESERVATIONS)
    {
        printf("ERROR: reservation queue is full.\n");
        return 0;
    }
    for (size_t i = 0; i < reservations->count; i++)
        if (strcmp(reservations->items[i].book_id, book->book_id) == 0 &&
            strcmp(reservations->items[i].member_id, member->member_id) == 0)
        {
            printf("ERROR: member already has a reservation for this title.\n");
            return 0;
        }
    if (!append_transaction(chain, pending, book, member, NULL, "RESERVED", 0, 0, 0, key))
    {
        printf("ERROR: could not create signed reservation request.\n");
        return 0;
    }
    snprintf(reservations->items[reservations->count].book_id,
             sizeof(reservations->items[reservations->count].book_id), "%s", book->book_id);
    snprintf(reservations->items[reservations->count].member_id,
             sizeof(reservations->items[reservations->count].member_id), "%s", member->member_id);
    reservations->items[reservations->count].reservation_date = time(NULL);
    reservations->count++;
    printf("Reservation queued; member added to the FIFO queue.\n");
    return 1;
}

static int queue_renewal(const Chain *chain, PendingPool *pending, CopyRegistry *copies,
                         const ReservationQueue *reservations, Book *book, Member *member,
                         const char *copy_id, EVP_PKEY *key)
{
    BookCopy *copy = find_copy(copies, copy_id);
    time_t now = time(NULL);
    if (!copy || strcmp(copy->book_id, book->book_id) != 0 ||
        copy->state != COPY_BORROWED ||
        strcmp(copy->current_holder_id, member->member_id) != 0)
    {
        printf("ERROR: member does not hold this copy.\n");
        return 0;
    }
    if (copy->renewal_count >= MAX_RENEWALS)
    {
        printf("ERROR: maximum renewals reached.\n");
        return 0;
    }
    if (has_reservation_from_other(reservations, book->book_id, member->member_id))
    {
        printf("ERROR: another member is waiting for this title.\n");
        return 0;
    }
    if (now > copy->due_date)
    {
        printf("ERROR: overdue copies cannot be renewed.\n");
        return 0;
    }
    if (!append_transaction(chain, pending, book, member, copy, "RENEWED",
                            copy->due_date + RENEWAL_PERIOD_SECONDS, 0, 0, key))
    {
        printf("ERROR: could not create signed renewal request.\n");
        return 0;
    }
    copy->due_date += RENEWAL_PERIOD_SECONDS;
    copy->renewal_count++;
    printf("Renewal queued; new due date=%lld (%u/%d renewals).\n",
           (long long)copy->due_date, copy->renewal_count, MAX_RENEWALS);
    return 1;
}

static int check_overdue(const Chain *chain, PendingPool *pending, CopyRegistry *copies,
                         const BookRegistry *books, const MemberRegistry *members,
                         EVP_PKEY *key, int queue_records)
{
    time_t now = time(NULL);
    int overdue_count = 0;
    for (size_t i = 0; i < copies->count; i++)
    {
        BookCopy *copy = &copies->items[i];
        if (copy->state != COPY_BORROWED || copy->due_date >= now)
            continue;
        int days = (int)(((now - copy->due_date) + 86400 - 1) / 86400);
        overdue_count++;
        printf("OVERDUE: copy=%s holder=%s days=%d accrued_fine=%d\n",
               copy->copy_id, copy->current_holder_id, days, days * FINE_PER_DAY);
        if (queue_records && !pending_record_exists(chain, pending, copy->copy_id, "OVERDUE", copy->due_date))
        {
            const Book *book = find_book_const(books, copy->book_id);
            const Member *member = find_member_const(members, copy->current_holder_id);
            if (book && member)
            {
                if (!append_transaction(chain, pending, book, member, copy, "OVERDUE",
                                        copy->due_date, days * FINE_PER_DAY, 0, key))
                    fprintf(stderr, "ERROR: could not queue overdue record for %s.\n", copy->copy_id);
            }
        }
    }
    if (overdue_count == 0)
        printf("No overdue copies.\n");
    return overdue_count;
}

static int queue_mark_lost(const Chain *chain, PendingPool *pending, CopyRegistry *copies,
                           Book *book, Member *member, const char *copy_id,
                           const char *reason, EVP_PKEY *key)
{
    BookCopy *copy = find_copy(copies, copy_id);
    if (!copy || strcmp(copy->book_id, book->book_id) != 0 ||
        (copy->state != COPY_AVAILABLE && copy->state != COPY_BORROWED) ||
        !reason || !reason[0] || strlen(reason) >= sizeof(copy->copy_id) + 40 ||
        !valid_record_text(reason))
    {
        printf("ERROR: mark_lost requires an available/borrowed copy and a reason code.\n");
        return 0;
    }
    if (!append_transaction(chain, pending, book, member, copy, "LOST", copy->due_date, 0, 0, key))
    {
        printf("ERROR: could not create signed lost-copy record.\n");
        return 0;
    }
    snprintf(pending->items[pending->count - 1].record.reason_code,
             sizeof(pending->items[pending->count - 1].record.reason_code), "%s", reason);
    if (!make_record_id(&pending->items[pending->count - 1].record) ||
        !sign_record(&pending->items[pending->count - 1].record, key))
    {
        pending->count--;
        printf("ERROR: could not sign lost-copy reason.\n");
        return 0;
    }
    copy->state = COPY_STATE_LOST;
    copy->condition = COPY_LOST;
    copy->current_holder_id[0] = '\0';
    copy->due_date = 0;
    return 1;
}

static int queue_condition_change(const Chain *chain, PendingPool *pending,
                                  CopyRegistry *copies, const BookRegistry *books,
                                  Member *actor, const char *copy_id,
                                  CopyCondition condition, const char *reason,
                                  EVP_PKEY *key)
{
    BookCopy *copy = find_copy(copies, copy_id);
    const Book *book;
    int explicit_override = reason && strncmp(reason, "OVERRIDE:", 9) == 0 &&
                            reason[9] != '\0';
    if (!copy || copy->state == COPY_STATE_LOST ||
        condition < COPY_NEW || condition > COPY_WORN ||
        condition == copy->condition || !reason || !reason[0] ||
        strlen(reason) >= sizeof(((LendingRecord *)0)->reason_code) ||
        !valid_record_text(reason))
    {
        printf("ERROR: condition change requires a non-lost copy, a different NEW/GOOD/WORN condition, and a reason code.\n");
        return 0;
    }
    book = find_book_const(books, copy->book_id);
    if (!book || !append_transaction(chain, pending, book, actor, copy,
                                     "CONDITION", copy->due_date,
                                     (int)condition, 0, key))
    {
        printf("ERROR: could not queue signed condition-change request.\n");
        return 0;
    }
    PendingRequest *request = &pending->items[pending->count - 1];
    snprintf(request->record.reason_code, sizeof(request->record.reason_code), "%s", reason);
    request->priority = 1;
    if (!make_record_id(&request->record) || !sign_record(&request->record, key))
    {
        pending->count--;
        printf("ERROR: could not sign condition-change reason.\n");
        return 0;
    }
    if ((int)condition > (int)copy->condition + 1 && !explicit_override)
    {
        if (!mark_request_suspicious(request, "condition-downgrade-exceeds-one-level", key))
        {
            pending->count--;
            printf("ERROR: could not sign condition-review request.\n");
            return 0;
        }
        printf("Condition change flagged SUSPICIOUS; use OVERRIDE:<reason> for an authorized multi-level downgrade.\n");
        return 1;
    }
    copy->condition = condition;
    printf("Condition change queued for mining: copy=%s condition=%s.\n",
           copy_id, copy_condition_text(condition));
    return 1;
}

static int authenticate(const char *path)
{
    FILE *file = fopen(path, "r");
    char username[64];
    char password[64];
    char stored_user[MAX_LINE];
    char stored_hash[HASH_HEX_LENGTH];
    char password_hash[HASH_HEX_LENGTH];
    int authenticated = 0;
    if (!file)
    {
        fprintf(stderr, "ERROR: users.txt is missing or cannot be opened.\n");
        return 0;
    }
    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin))
    {
        fclose(file);
        return 0;
    }
    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin))
    {
        fclose(file);
        return 0;
    }
    trim(username);
    trim(password);
    sha256_text(password, password_hash);
    while (fgets(stored_user, sizeof(stored_user), file))
    {
        char *separator;
        trim(stored_user);
        separator = strchr(stored_user, ',');
        if (!separator)
            continue;
        *separator++ = '\0';
        snprintf(stored_hash, sizeof(stored_hash), "%s", separator);
        if (strcmp(username, stored_user) == 0 && strcmp(password_hash, stored_hash) == 0)
        {
            authenticated = 1;
            break;
        }
    }
    fclose(file);
    if (authenticated)
        return 1;
    fprintf(stderr, "ERROR: authentication failed.\n");
    return 0;
}

static void print_help(void)
{
    printf("Commands:\n");
    printf("  register_member ID NAME COURSE | view_member ID | member_nonce ID\n");
    printf("  register_book ID TITLE AUTHOR | view_book ID | add_copy COPY_ID BOOK_ID CONDITION\n");
    printf("  member_key ID | account_nonce ID | difficulty_status\n");
    printf("  borrow BOOK_ID MEMBER_ID [COPY_ID] | return BOOK_ID MEMBER_ID [COPY_ID]\n");
    printf("  reserve BOOK_ID MEMBER_ID | renew COPY_ID MEMBER_ID | overdue [COPY_ID]\n");
    printf("  settle_fine MEMBER_ID COPY_ID AMOUNT\n");
    printf("  copies | reservations | reservation_status BOOK_ID|MEMBER_ID | copy COPY_ID | mark_lost COPY_ID MEMBER_ID REASON\n");
    printf("  set_condition COPY_ID MEMBER_ID NEW|GOOD|WORN REASON_CODE\n");
    printf("  pending | pool_view | mine solo MEMBER | mine pool MINER1 MINER2 [MINER3 [MINER4]]\n");
    printf("  mine cloud ROUNDS MEMBER | view | validate | chain_save | chain_load\n");
    printf("  set_difficulty 1-4\n");
    printf("  balances | token_balance ID | utxos | transfer SENDER RECIPIENT AMOUNT NONCE\n");
    printf("  history ID | lending_history | member_history ID | book_history ID | view_fines [MEMBER_ID]\n");
    printf("  fraud_review | approve_suspicious ID | reject_suspicious ID | difficulty_status | tamper | help | quit\n");
}

static void print_pending(const PendingPool *pending)
{
    printf("Pending pool: %zu unconfirmed request(s)\n", pending->count);
    for (size_t i = 0; i < pending->count; i++)
    {
        const PendingRequest *request = &pending->items[i];
        const LendingRecord *record = &request->record;
        printf("  [%s] %s | copy=%s | %s | %s | priority=%d status=%s\n",
               record->record_id, record->book_title, record->copy_id, record->member_name,
               record->action, request->priority,
               request->status == REQUEST_SUSPICIOUS ? "SUSPICIOUS" :
               request->status == REQUEST_CONFIRMED ? "CONFIRMED" : "PENDING");
    }
}

static void print_fraud_review(const PendingPool *pending)
{
    size_t suspicious = 0;
    for (size_t i = 0; i < pending->count; i++)
        if (pending->items[i].status == REQUEST_SUSPICIOUS)
        {
            const LendingRecord *record = &pending->items[i].record;
            printf("[%s] member=%s book=%s copy=%s action=%s reason=%s\n",
                   record->record_id, record->member_id, record->book_id, record->copy_id,
                   record->action, record->reason_code);
            suspicious++;
        }
    if (suspicious == 0)
        printf("No suspicious requests.\n");
}

static PendingRequest *find_pending_request(PendingPool *pending, const char *id)
{
    PendingRequest *match = NULL;
    size_t id_length = strlen(id);
    for (size_t i = 0; i < pending->count; i++)
        if (strncmp(pending->items[i].record.record_id, id, id_length) == 0)
        {
            if (match)
                return NULL;
            match = &pending->items[i];
        }
    return match;
}

static void print_lending_history(const Chain *chain, const MemberRegistry *members,
                                  const char *member_id, const char *book_id)
{
    size_t matches = 0;
    for (size_t i = 1; i < chain->count; i++)
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if ((!member_id || strcmp(member_id, record->member_id) == 0) &&
                (!book_id || strcmp(book_id, record->book_id) == 0))
            {
                printf("block=%d record=%s member=%s book=%s copy=%s action=%s due=%lld fine=%d\n",
                       chain->items[i].index, record->record_id, record->member_id,
                       record->book_id, record->copy_id, record->action,
                       (long long)record->due_date, record->fine_amount);
                matches++;
            }
        }
    if (matches == 0)
        printf("No confirmed lending records match.\n");
    (void)members;
}

static int register_member(MemberRegistry *members, const char *member_id,
                           const char *full_name, const char *course_code)
{
    FILE *file;
    if (members->count >= MAX_MEMBERS ||
        !valid_identifier(member_id, sizeof(members->items[0].member_id)) ||
        !full_name[0] || strlen(full_name) >= sizeof(members->items[0].full_name) ||
        !valid_record_text(full_name) || strchr(full_name, ',') ||
        !valid_identifier(course_code, sizeof(members->items[0].course_code)) ||
        find_member(members, member_id))
        return 0;
    file = fopen("members.txt", "a");
    if (!file)
        return 0;
    {
        int write_ok = fprintf(file, "%s,%s,%s\n", member_id, full_name, course_code) >= 0;
        if (fclose(file) != 0)
            write_ok = 0;
        if (!write_ok)
            return 0;
    }
    snprintf(members->items[members->count].member_id, sizeof(members->items[0].member_id), "%s", member_id);
    snprintf(members->items[members->count].full_name, sizeof(members->items[0].full_name), "%s", full_name);
    snprintf(members->items[members->count].course_code, sizeof(members->items[0].course_code), "%s", course_code);
    members->count++;
    return 1;
}

static int register_book(BookRegistry *books, const char *book_id,
                         const char *title, const char *author)
{
    FILE *file;
    if (books->count >= MAX_BOOKS ||
        !valid_identifier(book_id, sizeof(books->items[0].book_id)) ||
        !title[0] || strlen(title) >= sizeof(books->items[0].title) ||
        !author[0] || strlen(author) >= sizeof(books->items[0].author) ||
        !valid_record_text(title) || !valid_record_text(author) ||
        strchr(title, ',') || strchr(author, ',') || find_book(books, book_id))
        return 0;
    file = fopen("books.txt", "a");
    if (!file)
        return 0;
    {
        int write_ok = fprintf(file, "%s,%s,%s\n", book_id, title, author) >= 0;
        if (fclose(file) != 0)
            write_ok = 0;
        if (!write_ok)
            return 0;
    }
    snprintf(books->items[books->count].book_id, sizeof(books->items[0].book_id), "%s", book_id);
    snprintf(books->items[books->count].title, sizeof(books->items[0].title), "%s", title);
    snprintf(books->items[books->count].author, sizeof(books->items[0].author), "%s", author);
    books->count++;
    return 1;
}

static int save_chain_metadata(const char *path, int difficulty)
{
    char temporary_path[128];
    FILE *file;
    int reward = MINING_REWARD;
    int success;
    if (difficulty < 1 || difficulty > 4)
        return 0;
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path) >=
        (int)sizeof(temporary_path))
        return 0;
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    success = fwrite(METADATA_MAGIC, 1, 8, file) == 8 &&
              fwrite(&difficulty, sizeof(difficulty), 1, file) == 1 &&
              fwrite(&reward, sizeof(reward), 1, file) == 1 &&
              fflush(file) == 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success)
    {
        remove(temporary_path);
        return 0;
    }
    remove(path);
    return rename(temporary_path, path) == 0;
}

static int load_chain_metadata(const char *path, int *difficulty)
{
    FILE *file = fopen(path, "rb");
    char magic[9] = {0};
    int saved_difficulty;
    int saved_reward;
    if (!file)
        return 0;
    int valid = fread(magic, 1, 8, file) == 8 &&
                fread(&saved_difficulty, sizeof(saved_difficulty), 1, file) == 1 &&
                fread(&saved_reward, sizeof(saved_reward), 1, file) == 1 &&
                fgetc(file) == EOF &&
                strcmp(magic, METADATA_MAGIC) == 0 &&
                saved_difficulty >= 1 && saved_difficulty <= 4 &&
                saved_reward == MINING_REWARD;
    fclose(file);
    if (!valid)
    {
        fprintf(stderr, "ERROR: chain_metadata.dat is corrupt or incompatible.\n");
        return -1;
    }
    *difficulty = saved_difficulty;
    return 1;
}

int main(int argc, char **argv)
{
    BookRegistry books;
    MemberRegistry members;
    static CopyRegistry copies;
    static Chain chain;
    static ReservationQueue reservations;
    static PendingPool pending;
    static TokenLedger ledger;
    LedgerModel model = MODEL_UTXO;
    int difficulty = 2;
    int requested_difficulty = 2;
    int difficulty_from_args = 0;
    int session_chain_valid = 1;
    EVP_PKEY *key;
    char line[MAX_LINE];
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc)
        {
            i++;
            if (strcmp(argv[i], "utxo") == 0)
                model = MODEL_UTXO;
            else if (strcmp(argv[i], "account") == 0)
                model = MODEL_ACCOUNT;
            else
            {
                fprintf(stderr, "ERROR: --model must be utxo or account.\n");
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "--difficulty") == 0 && i + 1 < argc)
        {
            char *end = NULL;
            long parsed;
            i++;
            parsed = strtol(argv[i], &end, 10);
            if (!end || *end || parsed < 1 || parsed > 4)
            {
                fprintf(stderr, "ERROR: --difficulty must be from 1 to 4.\n");
                return EXIT_FAILURE;
            }
            difficulty = (int)parsed;
            requested_difficulty = difficulty;
            difficulty_from_args = 1;
        }
        else
        {
            fprintf(stderr, "Usage: %s [--model utxo|account] [--difficulty 1-4]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    {
        int metadata_status = load_chain_metadata("chain_metadata.dat", &difficulty);
        if (metadata_status < 0)
            return EXIT_FAILURE;
        if (difficulty_from_args)
            difficulty = requested_difficulty;
        if (!save_chain_metadata("chain_metadata.dat", difficulty))
        {
            fprintf(stderr, "ERROR: could not persist chain metadata.\n");
            return EXIT_FAILURE;
        }
    }
    srand((unsigned int)time(NULL));
    if (!load_books("books.txt", &books) || !load_members("members.txt", &members) ||
        !load_copies("copies.txt", &books, &copies))
        return EXIT_FAILURE;
    printf("Loaded %zu books, %zu members, and %zu copies.\n",
           books.count, members.count, copies.count);
    key = load_or_create_key("signing_key.pem");
    if (!key || !authenticate("users.txt"))
    {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!initialize_member_signing_keys(&members))
    {
        free_member_signing_keys();
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!load_chain("blockchain.dat", &chain, key) ||
        !load_library_state("library_state.dat", &copies, &reservations, &pending,
                            &chain, &books, &members, key) ||
        !validate_inventory_projection(&chain, &pending, &copies) ||
        !validate_chain(&chain, key, &books, &members, &copies, 1))
    {
        free_member_signing_keys();
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
    {
        fprintf(stderr, "ERROR: could not persist loaded library state.\n");
        free_member_signing_keys();
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!initialize_ledger(&ledger, &members, &chain, model))
    {
        free_ledger(&ledger);
        free_member_signing_keys();
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    {
        int token_state = load_token_ledger(&ledger, &members, &chain);
        if (token_state < 0)
        {
            fprintf(stderr, "ERROR: token state does not match the saved chain; preserve the file and restore a matching backup before continuing.\n");
            free_ledger(&ledger);
            free_member_signing_keys();
            EVP_PKEY_free(key);
            return EXIT_FAILURE;
        }
        if (token_state == 0 && !save_token_ledger(&ledger, &chain))
        {
            fprintf(stderr, "ERROR: could not initialize persistent token ledger.\n");
            free_ledger(&ledger);
            free_member_signing_keys();
            EVP_PKEY_free(key);
            return EXIT_FAILURE;
        }
    }
    printf("Authenticated as librarian.\n");
    printf("Token model: %s | mining difficulty: %d leading zero(s)\n",
           model == MODEL_UTXO ? "UTXO" : "account", difficulty);
    check_overdue(&chain, &pending, &copies, &books, &members, key, 1);
    if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
        fprintf(stderr, "ERROR: overdue scan could not persist library state.\n");
    print_help();
    while (printf("library> ") && fgets(line, sizeof(line), stdin))
    {
        char command[32] = {0}, first[128] = {0}, second[128] = {0},
             third[128] = {0}, fourth[128] = {0}, fifth[128] = {0};
        int fields = sscanf(line, "%31s %127s %127s %127s %127s %127s",
                            command, first, second, third, fourth, fifth);
        if (fields == EOF || fields == 0)
            continue;
        if (strcmp(command, "mine_solo") == 0 && fields == 2)
        {
            char recipient[128];
            snprintf(recipient, sizeof(recipient), "%s", first);
            snprintf(command, sizeof(command), "mine");
            snprintf(second, sizeof(second), "%s", recipient);
            snprintf(first, sizeof(first), "solo");
            fields = 3;
        }
        else if (strcmp(command, "mine_pool") == 0 && fields >= 3 && fields <= 5)
        {
            char miner1[128], miner2[128], miner3[128], miner4[128];
            snprintf(miner1, sizeof(miner1), "%s", first);
            snprintf(miner2, sizeof(miner2), "%s", second);
            snprintf(miner3, sizeof(miner3), "%s", third);
            snprintf(miner4, sizeof(miner4), "%s", fourth);
            snprintf(command, sizeof(command), "mine");
            snprintf(first, sizeof(first), "pool");
            snprintf(second, sizeof(second), "%s", miner1);
            snprintf(third, sizeof(third), "%s", miner2);
            snprintf(fourth, sizeof(fourth), "%s", miner3);
            snprintf(fifth, sizeof(fifth), "%s", miner4);
            fields++;
        }
        else if (strcmp(command, "mine_cloud") == 0 && fields == 3)
        {
            snprintf(command, sizeof(command), "mine");
            snprintf(third, sizeof(third), "%s", second);
            snprintf(second, sizeof(second), "%s", first);
            snprintf(first, sizeof(first), "cloud");
            fields = 4;
        }
        else if (strcmp(command, "token_transfer") == 0 ||
                 strcmp(command, "account_transfer") == 0)
            snprintf(command, sizeof(command), "transfer");
        else if (strcmp(command, "utxo_view") == 0)
            snprintf(command, sizeof(command), "utxos");
        else if (strcmp(command, "pool_view") == 0)
            snprintf(command, sizeof(command), "pending");
        else if (strcmp(command, "chain_view") == 0)
            snprintf(command, sizeof(command), "view");
        else if (strcmp(command, "validate_chain") == 0)
            snprintf(command, sizeof(command), "validate");
        else if (strcmp(command, "transaction_history") == 0)
            snprintf(command, sizeof(command), "history");
        if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0)
            break;
        if (strcmp(command, "help") == 0)
        {
            print_help();
            continue;
        }
        if (!session_chain_valid && strcmp(command, "validate") != 0)
        {
            fprintf(stderr, "ERROR: chain validation failed; run validate before other commands.\n");
            continue;
        }
        if (strcmp(command, "register_member") == 0 && fields == 4)
        {
            if (ledger.account_count < MAX_MEMBERS &&
                register_member(&members, first, second, third))
            {
                if (!ensure_member_signing_key(&members, first) ||
                    !add_ledger_member(&ledger, first))
                    fprintf(stderr, "ERROR: member row was written, but key/account initialization failed; resolve before use.\n");
                else
                {
                    if (!save_token_ledger(&ledger, &chain))
                        fprintf(stderr, "ERROR: member registered but token ledger state was not persisted.\n");
                    printf("Registered member %s. Names with spaces should be entered with underscores.\n", first);
                }
            }
            else
                printf("ERROR: member registration rejected; check fields, uniqueness, and registry capacity.\n");
            continue;
        }
        if (strcmp(command, "register_book") == 0 && fields == 4)
        {
            if (register_book(&books, first, second, third))
                printf("Registered book %s; add one or more physical copies with add_copy.\n", first);
            else
                printf("ERROR: book registration rejected; check fields, uniqueness, and registry capacity.\n");
            continue;
        }
        if ((strcmp(command, "view_member") == 0 || strcmp(command, "member_nonce") == 0 ||
             strcmp(command, "account_nonce") == 0) && fields == 2)
        {
            Member *member = find_member(&members, first);
            if (!member)
                printf("ERROR: Member not found.\n");
            else if (strcmp(command, "view_member") == 0)
                printf("%s | %s | %s | token_balance=%d\n", member->member_id, member->full_name,
                       member->course_code, ledger_balance(&ledger, member->member_id));
            else if (strcmp(command, "account_nonce") == 0)
            {
                Account *account = find_account(&ledger, first);
                printf("%s next outgoing account nonce=%llu\n", first, account ? account->nonce : 0ULL);
            }
            else
            {
                unsigned long long next_nonce = 0;
                for (size_t i = 1; i < chain.count; i++)
                    for (size_t j = 0; j < chain.items[i].record_count; j++)
                        if (strcmp(chain.items[i].records[j].member_id, first) == 0 &&
                            chain.items[i].records[j].nonce >= next_nonce)
                            next_nonce = chain.items[i].records[j].nonce + 1;
                printf("%s next confirmed lending nonce=%llu\n", first, next_nonce);
            }
            continue;
        }
        if (strcmp(command, "member_key") == 0 && fields == 2)
        {
            char public_path[96];
            char key_line[160];
            FILE *public_key_file;
            if (!find_member(&members, first) ||
                snprintf(public_path, sizeof(public_path), "member_%s_public.pem", first) >= (int)sizeof(public_path) ||
                !(public_key_file = fopen(public_path, "r")))
                printf("ERROR: member public key not found.\n");
            else
            {
                printf("Public key for %s:\n", first);
                while (fgets(key_line, sizeof(key_line), public_key_file))
                    fputs(key_line, stdout);
                fclose(public_key_file);
            }
            continue;
        }
        if ((strcmp(command, "token_balance") == 0 || strcmp(command, "account_balance") == 0) &&
            fields == 2)
        {
            if (!find_member(&members, first))
                printf("ERROR: Member not found.\n");
            else
                printf("%s balance=%d coins\n", first, ledger_balance(&ledger, first));
            continue;
        }
        if (strcmp(command, "reservation_status") == 0 && fields == 2)
        {
            int found = 0;
            for (size_t i = 0; i < reservations.count; i++)
                if (strcmp(reservations.items[i].book_id, first) == 0 ||
                    strcmp(reservations.items[i].member_id, first) == 0)
                {
                    printf("%zu. book=%s member=%s reserved_at=%lld\n", i + 1,
                           reservations.items[i].book_id, reservations.items[i].member_id,
                           (long long)reservations.items[i].reservation_date);
                    found = 1;
                }
            for (size_t i = 0; i < copies.count; i++)
                if (copies.items[i].state == COPY_RESERVED &&
                    (strcmp(copies.items[i].current_holder_id, first) == 0 ||
                     strcmp(copies.items[i].book_id, first) == 0))
                {
                    printf("offered copy=%s book=%s member=%s\n", copies.items[i].copy_id,
                           copies.items[i].book_id, copies.items[i].current_holder_id);
                    found = 1;
                }
            if (!found)
                printf("No reservation queue entry or copy offer found.\n");
            continue;
        }
        if (strcmp(command, "fraud_review") == 0)
        {
            print_fraud_review(&pending);
            continue;
        }
        if ((strcmp(command, "approve_suspicious") == 0 ||
             strcmp(command, "reject_suspicious") == 0) && fields == 2)
        {
            PendingRequest *request = find_pending_request(&pending, first);
            if (!request || request->status != REQUEST_SUSPICIOUS)
                printf("ERROR: suspicious request not found (ID must be unique).\n");
            else if (strcmp(command, "approve_suspicious") == 0)
            {
                BookCopy *copy = NULL;
                CopyState old_state = COPY_AVAILABLE;
                char old_holder[20] = {0};
                time_t old_due_date = 0;
                unsigned int old_renewals = 0;
                CopyCondition old_condition = COPY_GOOD;
                if (strcmp(request->record.action, "BORROWED") == 0)
                {
                    copy = find_copy(&copies, request->record.copy_id);
                    if (!copy ||
                        (copy->state != COPY_AVAILABLE &&
                         !(copy->state == COPY_RESERVED &&
                           strcmp(copy->current_holder_id, request->record.member_id) == 0)))
                    {
                        printf("ERROR: cannot approve; requested copy is no longer available to this member.\n");
                        continue;
                    }
                    old_state = copy->state;
                    snprintf(old_holder, sizeof(old_holder), "%s", copy->current_holder_id);
                    old_due_date = copy->due_date;
                    old_renewals = copy->renewal_count;
                    old_condition = copy->condition;
                    copy->state = COPY_BORROWED;
                    snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s",
                             request->record.member_id);
                    copy->due_date = request->record.due_date;
                    copy->renewal_count = 0;
                }
                else if (strcmp(request->record.action, "CONDITION") == 0)
                {
                    copy = find_copy(&copies, request->record.copy_id);
                    if (!copy || copy->state == COPY_STATE_LOST ||
                        request->record.fine_amount < COPY_NEW ||
                        request->record.fine_amount > COPY_WORN)
                    {
                        printf("ERROR: cannot approve; copy condition request is no longer valid.\n");
                        continue;
                    }
                    old_condition = copy->condition;
                    copy->condition = (CopyCondition)request->record.fine_amount;
                }
                request->status = REQUEST_PENDING;
                if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                {
                    request->status = REQUEST_SUSPICIOUS;
                    if (copy)
                    {
                        copy->state = old_state;
                        snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s", old_holder);
                        copy->due_date = old_due_date;
                        copy->renewal_count = old_renewals;
                        copy->condition = old_condition;
                    }
                    fprintf(stderr, "ERROR: approved request but failed to persist review decision.\n");
                }
                else
                    printf("Approved request %s; it may now be mined.\n", request->record.record_id);
            }
            else
            {
                size_t index = (size_t)(request - pending.items);
                char rejected_id[HASH_HEX_LENGTH];
                snprintf(rejected_id, sizeof(rejected_id), "%s", request->record.record_id);
                for (size_t i = index + 1; i < pending.count; i++)
                    pending.items[i - 1] = pending.items[i];
                pending.count--;
                if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                    fprintf(stderr, "ERROR: rejected request but failed to persist review decision.\n");
                else
                    printf("Rejected and removed request %s.\n", rejected_id);
            }
            continue;
        }
        if ((strcmp(command, "lending_history") == 0 && fields == 1) ||
            (strcmp(command, "member_history") == 0 && fields == 2) ||
            (strcmp(command, "book_history") == 0 && fields == 2))
        {
            const char *member_filter = NULL;
            const char *book_filter = NULL;
            if (strcmp(command, "member_history") == 0)
            {
                if (!find_member(&members, first))
                {
                    printf("ERROR: Member not found.\n");
                    continue;
                }
                member_filter = first;
            }
            else if (strcmp(command, "book_history") == 0)
            {
                if (!find_book(&books, first))
                {
                    printf("ERROR: Book not found.\n");
                    continue;
                }
                book_filter = first;
            }
            print_lending_history(&chain, &members, member_filter, book_filter);
            continue;
        }
        if (strcmp(command, "settle_fine") == 0 && fields == 4)
        {
            char *end = NULL;
            long amount = strtol(third, &end, 10);
            Member *member = find_member(&members, first);
            if (!end || *end || amount <= 0 || amount > INT_MAX || !member)
                printf("ERROR: provide a registered member, copy, and positive fine amount.\n");
            else
            {
                check_overdue(&chain, &pending, &copies, &books, &members, key, 1);
                if (queue_fine_settlement(&chain, &pending, &copies, &books, member,
                                          second, (int)amount, key))
                    print_pending(&pending);
                if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                    fprintf(stderr, "ERROR: could not persist fine settlement request.\n");
            }
            continue;
        }
        if (strcmp(command, "view_fines") == 0 && (fields == 1 || fields == 2))
        {
            int total = 0;
            for (size_t m = 0; m < members.count; m++)
            {
                if (fields == 2 && strcmp(first, members.items[m].member_id) != 0)
                    continue;
                for (size_t c = 0; c < copies.count; c++)
                {
                    int outstanding = copy_fine_balance(&chain, &pending, &copies.items[c],
                                                        members.items[m].member_id);
                    if (outstanding > 0)
                    {
                        printf("member=%s copy=%s outstanding=%d\n",
                               members.items[m].member_id, copies.items[c].copy_id, outstanding);
                        total += outstanding;
                    }
                }
            }
            printf("Total outstanding fines (pending settlements deducted): %d\n", total);
            continue;
        }
        if (strcmp(command, "difficulty_status") == 0)
        {
            printf("Mining difficulty: %d leading zero hexadecimal character(s); block reward=%d coins\n",
                   difficulty, MINING_REWARD);
            continue;
        }
        if (strcmp(command, "set_difficulty") == 0 && fields == 2)
        {
            char *end = NULL;
            long parsed = strtol(first, &end, 10);
            if (!end || *end || parsed < 1 || parsed > 4)
                printf("ERROR: difficulty must be an integer from 1 to 4.\n");
            else if (!save_chain_metadata("chain_metadata.dat", (int)parsed))
                fprintf(stderr, "ERROR: difficulty was not changed because metadata could not be persisted.\n");
            else
            {
                difficulty = (int)parsed;
                printf("Mining difficulty set to %d and persisted.\n", difficulty);
            }
            continue;
        }
        if (strcmp(command, "chain_save") == 0)
        {
            printf(save_chain("blockchain.dat", &chain) ? "Chain saved.\n" : "ERROR: chain save failed.\n");
            continue;
        }
        if (strcmp(command, "chain_load") == 0)
        {
            if (!load_chain("blockchain.dat", &chain, key) ||
                !validate_chain(&chain, key, &books, &members, &copies, 1))
            {
                session_chain_valid = 0;
                printf("Chain load/validation failed; operations are blocked.\n");
            }
            else
                printf("Chain loaded and validated.\n");
            continue;
        }
        if (strcmp(command, "view") == 0)
        {
            print_records(&chain, key);
            continue;
        }
        if (strcmp(command, "validate") == 0)
        {
            session_chain_valid = validate_chain_file("blockchain.dat", &chain, key,
                                                      &books, &members, &copies);
            continue;
        }
        if (strcmp(command, "pending") == 0)
        {
            print_pending(&pending);
            continue;
        }
        if (strcmp(command, "balances") == 0)
        {
            print_balances(&ledger);
            continue;
        }
        if (strcmp(command, "utxos") == 0)
        {
            print_utxos(&ledger);
            continue;
        }
        if (strcmp(command, "history") == 0 && fields == 2)
        {
            print_history(&ledger, first);
            continue;
        }
        if (strcmp(command, "copies") == 0)
        {
            print_copies(&copies, &books);
            continue;
        }
        if ((strcmp(command, "copy") == 0 || strcmp(command, "view_copy") == 0) && fields == 2)
        {
            BookCopy *copy = find_copy(&copies, first);
            if (!copy)
                printf("ERROR: copy not found.\n");
            else
            {
                Book *book = find_book(&books, copy->book_id);
                printf("%s | %s | %s | %s | holder=%s | due=%lld renewals=%u\n",
                       copy->copy_id, copy->book_id, book ? book->title : "(unknown)",
                       copy_state_text(copy->state), copy->current_holder_id[0] ? copy->current_holder_id : "-",
                       (long long)copy->due_date, copy->renewal_count);
            }
            continue;
        }
        if (strcmp(command, "reservations") == 0)
        {
            print_reservations(&reservations);
            continue;
        }
        if (strcmp(command, "view_book") == 0 && fields == 2)
        {
            Book *book = find_book(&books, first);
            if (!book)
                printf("ERROR: book not found.\n");
            else
            {
                printf("%s | %s | %s\n", book->book_id, book->title, book->author);
                for (size_t i = 0; i < copies.count; i++)
                    if (strcmp(copies.items[i].book_id, book->book_id) == 0)
                        printf("  %s | %s | %s\n", copies.items[i].copy_id,
                               copy_state_text(copies.items[i].state),
                               copy_condition_text(copies.items[i].condition));
            }
            continue;
        }
        if (strcmp(command, "transfer") == 0 && fields == 5)
        {
            char *amount_end = NULL;
            char *nonce_end = NULL;
            long amount = strtol(third, &amount_end, 10);
            unsigned long long nonce = strtoull(fourth, &nonce_end, 10);
            size_t previous_pending_count = pending.count;
            if (!amount_end || *amount_end || !nonce_end || *nonce_end ||
                fourth[0] == '-' || amount <= 0 || amount > INT_MAX)
                printf("ERROR: invalid transfer amount or nonce.\n");
            else if (!queue_token_transfer(&chain, &pending, &ledger, &members,
                                           first, second, (int)amount, nonce))
                printf("ERROR: transfer rejected (unknown account, insufficient available balance, invalid nonce, or invalid amount).\n");
            else
            {
                if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                {
                    pending.count = previous_pending_count;
                    fprintf(stderr, "ERROR: queued transfer could not be persisted; request discarded.\n");
                }
                else
                {
                    printf("Transfer queued for mining.\n");
                    print_pending(&pending);
                }
            }
            continue;
        }
        if (strcmp(command, "mine") == 0 && fields >= 3 && fields <= 6)
        {
            int rounds = 0;
            const char *payout_members[MINERS_IN_POOL] = {0};
            size_t payout_count = 0;
            if (strcmp(first, "solo") != 0 && strcmp(first, "pool") != 0 && strcmp(first, "cloud") != 0)
                printf("ERROR: mining mode must be solo, pool, or cloud.\n");
            else if ((strcmp(first, "solo") == 0 && fields != 3) ||
                     (strcmp(first, "pool") == 0 && (fields < 4 || fields > 6)) ||
                     (strcmp(first, "cloud") == 0 && fields != 4))
                printf("ERROR: usage is mine solo MEMBER, mine pool MINER1 MINER2 [MINER3 [MINER4]], or mine cloud ROUNDS MEMBER.\n");
            else
            {
                if (strcmp(first, "solo") == 0)
                {
                    payout_members[0] = second;
                    payout_count = 1;
                }
                else if (strcmp(first, "pool") == 0)
                {
                    payout_members[0] = second;
                    payout_members[1] = third;
                    payout_count = (size_t)(fields - 2);
                    if (payout_count > 2)
                        payout_members[2] = fourth;
                    if (payout_count > 3)
                        payout_members[3] = fifth;
                }
                else
                {
                    char *end = NULL;
                    long parsed = strtol(second, &end, 10);
                    if (!end || *end || parsed < 1 || parsed > 5)
                    {
                        printf("ERROR: cloud rental duration must be 1 to 5 rounds.\n");
                        continue;
                    }
                    rounds = (int)parsed;
                    payout_members[0] = third;
                    payout_count = 1;
                }
                confirm_pending(&chain, &pending, &copies, &reservations, &ledger,
                                &members, key,
                                "blockchain.dat", "library_state.dat",
                                difficulty, first, rounds, payout_members, payout_count);
            }
            continue;
        }
        if (strcmp(command, "tamper") == 0)
        {
            static Chain tampered_chain;
            if (chain.count < 2)
                printf("ERROR: add a lending record before tampering.\n");
            else
            {
                memcpy(tampered_chain.items, chain.items, chain.count * sizeof(Block));
                tampered_chain.count = chain.count;
                if (tampered_chain.items[1].record_count == 0)
                    continue;
                tampered_chain.items[1].records[0].member_name[0] =
                    tampered_chain.items[1].records[0].member_name[0] == 'X' ? 'J' : 'X';
                printf("Simulated tampering with block 1:\n");
                validate_chain(&tampered_chain, key, &books, &members, &copies, 1);
            }
            continue;
        }
        if (strcmp(command, "borrow") == 0 && (fields == 3 || fields == 4))
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else
                queue_borrow(&chain, &pending, &copies, book, member,
                             fields == 4 ? third : NULL, key);
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist borrow request.\n");
            print_pending(&pending);
            continue;
        }
        if (strcmp(command, "return") == 0 && (fields == 3 || fields == 4))
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else
                queue_return(&chain, &pending, &copies, &reservations, book, member,
                             fields == 4 ? third : NULL, key);
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist return request.\n");
            print_pending(&pending);
            continue;
        }
        if (strcmp(command, "reserve") == 0 && fields == 3)
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else
                queue_reservation(&chain, &pending, &reservations, &copies, book, member, key);
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist reservation.\n");
            print_reservations(&reservations);
            continue;
        }
        if (strcmp(command, "renew") == 0 && fields == 3)
        {
            BookCopy *copy = find_copy(&copies, first);
            Member *member = find_member(&members, second);
            Book *book = copy ? find_book(&books, copy->book_id) : NULL;
            if (!copy || !member || !book)
                printf("ERROR: Copy or Member not found.\n");
            else
                queue_renewal(&chain, &pending, &copies, &reservations, book, member, copy->copy_id, key);
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist renewal.\n");
            continue;
        }
        if ((strcmp(command, "overdue") == 0 || strcmp(command, "check_overdue") == 0) &&
            (fields == 1 || fields == 2))
        {
            if (fields == 1)
                check_overdue(&chain, &pending, &copies, &books, &members, key, 1);
            else
            {
                BookCopy *copy = find_copy(&copies, first);
                if (!copy)
                    printf("ERROR: Copy not found.\n");
                else if (copy->state != COPY_BORROWED || copy->due_date >= time(NULL))
                    printf("Copy is not overdue.\n");
                else
                    printf("Copy is overdue; accrued fine=%d.\n",
                           (int)(((time(NULL) - copy->due_date + 86399) / 86400) * FINE_PER_DAY));
                check_overdue(&chain, &pending, &copies, &books, &members, key, 1);
            }
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist overdue scan.\n");
            continue;
        }
        if (strcmp(command, "mark_lost") == 0 && fields == 4)
        {
            BookCopy *copy = find_copy(&copies, first);
            Book *book = copy ? find_book(&books, copy->book_id) : NULL;
            Member *librarian = find_member(&members, second);
            if (!book || !librarian)
                printf("ERROR: Copy or librarian member ID not found.\n");
            else if (queue_mark_lost(&chain, &pending, &copies, book, librarian,
                                     copy->copy_id, third, key))
                printf("Copy marked LOST; reason=%s. Record awaits mining.\n", third);
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist lost-copy state.\n");
            continue;
        }
        if (strcmp(command, "set_condition") == 0 && fields == 5)
        {
            BookCopy *copy = find_copy(&copies, first);
            Member *actor = find_member(&members, second);
            CopyCondition condition;
            size_t previous_pending_count = pending.count;
            CopyCondition previous_condition = copy ? copy->condition : COPY_GOOD;
            if (!copy || !actor || !parse_copy_condition(third, &condition))
                printf("ERROR: provide a valid copy, registered librarian member ID, and NEW/GOOD/WORN condition.\n");
            else if (queue_condition_change(&chain, &pending, &copies, &books, actor,
                                           first, condition, fourth, key))
            {
                if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                {
                    pending.count = previous_pending_count;
                    copy->condition = previous_condition;
                    fprintf(stderr, "ERROR: condition change was rolled back because state could not be persisted.\n");
                }
                else
                    print_pending(&pending);
            }
            continue;
        }
        if (strcmp(command, "add_copy") == 0 && fields == 4)
        {
            Book *book = find_book(&books, second);
            if (!book)
                printf("ERROR: Book not found.\n");
            else if (copies.count >= MAX_COPIES || find_copy(&copies, first))
                printf("ERROR: copy registry is full or copy ID already exists.\n");
            else
            {
                BookCopy *copy = &copies.items[copies.count++];
                memset(copy, 0, sizeof(*copy));
                snprintf(copy->copy_id, sizeof(copy->copy_id), "%s", first);
                snprintf(copy->book_id, sizeof(copy->book_id), "%s", second);
                if (strcmp(third, "NEW") == 0)
                    copy->condition = COPY_NEW;
                else if (strcmp(third, "GOOD") == 0)
                    copy->condition = COPY_GOOD;
                else if (strcmp(third, "WORN") == 0)
                    copy->condition = COPY_WORN;
                else
                {
                    copies.count--;
                    printf("ERROR: condition must be NEW, GOOD, or WORN.\n");
                    continue;
                }
                printf("Added copy %s.\n", first);
            }
            if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
                fprintf(stderr, "ERROR: could not persist added copy.\n");
            continue;
        }
        printf("ERROR: invalid command or arguments.\n");
    }
    if (!save_chain("blockchain.dat", &chain) ||
        !save_library_state("library_state.dat", &copies, &reservations, &pending))
        fprintf(stderr, "ERROR: failed to persist final library state.\n");
    free_ledger(&ledger);
    free_member_signing_keys();
    EVP_PKEY_free(key);
    return EXIT_SUCCESS;
}
