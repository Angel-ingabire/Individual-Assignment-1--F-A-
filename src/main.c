#define _CRT_SECURE_NO_WARNINGS
#if defined(__MINGW32__)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
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
#define MAX_UTXOS 10000
#define MAX_LINE 256
#define HASH_HEX_LENGTH 65
#define SIGNATURE_MAX_LENGTH 72
#define ACTION_LENGTH 10
#define LEDGER_MAGIC "LIBCHAIN2"
#define LOAN_PERIOD_SECONDS (14 * 24 * 60 * 60)
#define REWARD_FEE 1
#define MINING_REWARD 2
#define CLOUD_RENTAL_FEE 2
#define CLOUD_MAINTENANCE_FEE 1
#define MINERS_IN_POOL 4

/* A block hash covers every persisted field except the hash itself. */
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
} LegacyBlock;

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

typedef struct
{
    Block items[MAX_BLOCKS];
    size_t count;
} Chain;

typedef struct
{
    Block items[MAX_BLOCKS];
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
    struct TransactionRecord *next;
} TransactionRecord;

typedef struct
{
    char member_id[20];
    int balance;
    unsigned long long nonce;
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
        if (registry->count >= MAX_BOOKS || !split_csv(line, fields, 3) || !fields[0][0] || !fields[1][0] || !fields[2][0])
        {
            fprintf(stderr, "ERROR: invalid book registry row.\n");
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
        if (registry->count >= MAX_MEMBERS || !split_csv(line, fields, 3) || !fields[0][0] || !fields[1][0] || !fields[2][0])
        {
            fprintf(stderr, "ERROR: invalid member registry row.\n");
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

static Book *find_book(BookRegistry *registry, const char *id)
{
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->items[i].book_id, id) == 0)
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

static void block_unsigned_data(const Block *block, char *output, size_t output_size)
{
    snprintf(output, output_size, "%d|%lld|%s|%s|%s|%s|%s|%s", block->index, (long long)block->timestamp,
             block->book_id, block->book_title, block->member_id, block->member_name, block->action, block->previous_hash);
}

static void block_hash_data(const Block *block, char *output, size_t output_size)
{
    char signature_hex[SIGNATURE_MAX_LENGTH * 2 + 1];
    hex_encode(block->signature, block->signature_len, signature_hex, sizeof(signature_hex));
    snprintf(output, output_size, "%d|%lld|%s|%s|%s|%s|%s|%s|%d|%s|%d|%llu|%s", block->index, (long long)block->timestamp,
             block->book_id, block->book_title, block->member_id, block->member_name, block->action, block->previous_hash,
             block->token_reward, block->transaction_id, block->difficulty, block->nonce, signature_hex);
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

static int hash_block(const Block *block, char output[HASH_HEX_LENGTH])
{
    char data[1024];
    block_hash_data(block, data, sizeof(data));
    return sha256_text(data, output);
}

static int has_pow_prefix(const char *hash, int difficulty);

static int sign_block(Block *block, EVP_PKEY *key)
{
    char data[512];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signature_length = sizeof(block->signature);
    block_unsigned_data(block, data, sizeof(data));
    if (!context || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSignUpdate(context, data, strlen(data)) != 1 ||
        EVP_DigestSignFinal(context, block->signature, &signature_length) != 1 ||
        signature_length == 0 || signature_length > SIGNATURE_MAX_LENGTH)
    {
        EVP_MD_CTX_free(context);
        return 0;
    }
    block->signature_len = (unsigned int)signature_length;
    EVP_MD_CTX_free(context);
    return hash_block(block, block->hash);
}

static int verify_signature(const Block *block, EVP_PKEY *key)
{
    char data[512];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int result;
    block_unsigned_data(block, data, sizeof(data));
    result = context && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) == 1 &&
             EVP_DigestVerifyUpdate(context, data, strlen(data)) == 1 &&
             EVP_DigestVerifyFinal(context, block->signature, block->signature_len) == 1;
    EVP_MD_CTX_free(context);
    return result;
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

static void create_genesis(Chain *chain)
{
    Block *genesis = &chain->items[0];
    memset(genesis, 0, sizeof(*genesis));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->action, "GENESIS");
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';
    hash_block(genesis, genesis->hash);
    chain->count = 1;
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
    else if (strcmp(magic, "LIBCHAIN1") == 0)
    {
        LegacyBlock *legacy = (LegacyBlock *)calloc(chain->count, sizeof(*legacy));
        if (!legacy || fread(legacy, sizeof(*legacy), chain->count, file) != chain->count)
        {
            free(legacy);
            fclose(file);
            fprintf(stderr, "ERROR: legacy blockchain.dat is corrupt.\n");
            return 0;
        }
        for (size_t i = 0; i < chain->count; i++)
        {
            Block *block = &chain->items[i];
            memset(block, 0, sizeof(*block));
            block->index = legacy[i].index;
            block->timestamp = legacy[i].timestamp;
            memcpy(block->book_id, legacy[i].book_id, sizeof(block->book_id));
            memcpy(block->book_title, legacy[i].book_title, sizeof(block->book_title));
            memcpy(block->member_id, legacy[i].member_id, sizeof(block->member_id));
            memcpy(block->member_name, legacy[i].member_name, sizeof(block->member_name));
            memcpy(block->action, legacy[i].action, sizeof(block->action));
            memcpy(block->signature, legacy[i].signature, sizeof(block->signature));
            block->signature_len = legacy[i].signature_len;
            block->difficulty = 2;
            if (i == 0)
            {
                memset(block->previous_hash, '0', 64);
                block->previous_hash[64] = '\0';
            }
            else
                snprintf(block->previous_hash, sizeof(block->previous_hash), "%s", chain->items[i - 1].hash);
            if (i > 0 && !sign_block(block, key))
            {
                free(legacy);
                fclose(file);
                return 0;
            }
            if (!hash_block(block, block->hash))
            {
                free(legacy);
                fclose(file);
                return 0;
            }
            while (i > 0 && !has_pow_prefix(block->hash, block->difficulty))
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

static int validate_chain(const Chain *chain, EVP_PKEY *key, int print_result)
{
    char computed[HASH_HEX_LENGTH];
    int valid = chain->count > 0;
    for (size_t i = 0; valid && i < chain->count; i++)
    {
        const Block *block = &chain->items[i];
        valid = block->index == (int)i && block->signature_len <= SIGNATURE_MAX_LENGTH &&
                hash_block(block, computed) && strcmp(computed, block->hash) == 0;
        if (i == 0)
        {
            char genesis_previous_hash[HASH_HEX_LENGTH];
            memset(genesis_previous_hash, '0', 64);
            genesis_previous_hash[64] = '\0';
            valid = valid && strcmp(block->previous_hash, genesis_previous_hash) == 0 &&
                    strcmp(block->action, "GENESIS") == 0;
        }
        if (i > 0)
            valid = valid && (strcmp(block->action, "BORROWED") == 0 || strcmp(block->action, "RETURNED") == 0 || strcmp(block->action, "OVERDUE") == 0) &&
                    strcmp(block->previous_hash, chain->items[i - 1].hash) == 0 && verify_signature(block, key);
        if (i > 0 && valid)
        {
                valid = block->difficulty >= 1 && block->difficulty <= 4 &&
                    has_pow_prefix(block->hash, block->difficulty);
            if (strcmp(block->action, "BORROWED") == 0 || strcmp(block->action, "OVERDUE") == 0)
                valid = valid && block->token_reward == 0 && block->transaction_id[0] == '\0';
            if (strcmp(block->action, "RETURNED") == 0)
                valid = valid && (block->token_reward == 0 || block->token_reward == 5 || block->token_reward == 10);
            if (valid && strcmp(block->action, "RETURNED") == 0 && block->token_reward > 0)
            {
                char transaction_data[160];
                char transaction_id[HASH_HEX_LENGTH];
                snprintf(transaction_data, sizeof(transaction_data), "%s|%s|%s|%d|%d|%lld", block->member_id,
                         block->book_id, block->action, block->token_reward, REWARD_FEE, (long long)block->timestamp);
                valid = sha256_text(transaction_data, transaction_id) && strcmp(transaction_id, block->transaction_id) == 0;
            }
        }
        if (!valid && print_result)
            fprintf(stderr, "INVALID: block %d failed integrity, proof-of-work, signature, or reward validation.\n", block->index);
    }
    if (print_result)
        printf("Chain validation: %s (%zu blocks)\n", valid ? "VALID" : "INVALID", chain->count);
    return valid;
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
static void apply_reward(TokenLedger *ledger, const Block *block)
{
    Account *account = NULL;
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, block->member_id) == 0)
        {
            account = &ledger->accounts[i];
            break;
        }
    if (!account || block->token_reward <= REWARD_FEE)
        return;
    if (ledger->model == MODEL_ACCOUNT)
    {
        account->balance += block->token_reward - REWARD_FEE;
        add_history(account, "SYSTEM", account->member_id, block->token_reward, REWARD_FEE, 0);
    }
    else
    {
        add_utxo(ledger, block->transaction_id, 0, account->member_id, block->token_reward - REWARD_FEE);
        add_history(account, "SYSTEM", account->member_id, block->token_reward, REWARD_FEE, 0);
    }
}

static void initialize_ledger(TokenLedger *ledger, const MemberRegistry *members, const Chain *chain, LedgerModel model)
{
    memset(ledger, 0, sizeof(*ledger));
    ledger->model = model;
    ledger->account_count = members->count;
    for (size_t i = 0; i < members->count; i++)
        snprintf(ledger->accounts[i].member_id, sizeof(ledger->accounts[i].member_id), "%s", members->items[i].member_id);
    for (size_t i = 1; i < chain->count; i++)
        if (strcmp(chain->items[i].action, "RETURNED") == 0 && chain->items[i].token_reward > 0)
            apply_reward(ledger, &chain->items[i]);
}

static Account *find_account(TokenLedger *ledger, const char *member_id)
{
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
            return &ledger->accounts[i];
    return NULL;
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

static int transfer_tokens(TokenLedger *ledger, const char *sender_id, const char *recipient_id, int amount, unsigned long long nonce)
{
    Account *sender = find_account(ledger, sender_id);
    Account *recipient = find_account(ledger, recipient_id);
    const int fee = 1;
    if (!sender || !recipient || sender == recipient || amount <= 0)
        return 0;
    if (ledger->model == MODEL_ACCOUNT)
    {
        if (nonce != sender->nonce || sender->balance < amount + fee)
            return 0;
        sender->balance -= amount + fee;
        recipient->balance += amount;
        if (!add_history(sender, sender_id, recipient_id, amount, fee, nonce) ||
            !add_history(recipient, sender_id, recipient_id, amount, fee, nonce))
            return 0;
        sender->nonce++;
        return 1;
    }
    {
        int total = 0;
        char data[160];
        char txid[HASH_HEX_LENGTH];
        unsigned int selected[MAX_UTXOS];
        size_t selected_count = 0;
        /* Consume only unspent owner outputs; any excess becomes a change output. */
        for (size_t i = 0; i < ledger->utxo_count && total < amount + fee; i++)
            if (!ledger->utxos[i].spent && strcmp(ledger->utxos[i].owner, sender_id) == 0)
            {
                total += ledger->utxos[i].amount;
                selected[selected_count++] = (unsigned int)i;
            }
        if (total < amount + fee || ledger->utxo_count + 2 > MAX_UTXOS)
            return 0;
        ledger->transaction_sequence++;
        snprintf(data, sizeof(data), "%s|%s|%d|%d|%lld|%llu", sender_id, recipient_id, amount, fee,
                 (long long)time(NULL), ledger->transaction_sequence);
        if (!sha256_text(data, txid))
            return 0;
        for (size_t i = 0; i < selected_count; i++)
            ledger->utxos[selected[i]].spent = 1;
        if (!add_utxo(ledger, txid, 0, recipient_id, amount) || !add_utxo(ledger, txid, 1, sender_id, total - amount - fee))
            return 0;
        add_history(sender, sender_id, recipient_id, amount, fee, 0);
        add_history(recipient, sender_id, recipient_id, amount, fee, 0);
        return 1;
    }
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
        printf("  %s -> %s amount=%d fee=%d nonce=%llu\n", record->sender, record->recipient,
               record->amount, record->fee, record->nonce);
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

static int book_state(const Chain *chain, const PendingPool *pending, const char *book_id,
                      time_t *borrowed_at, char *borrower_id, size_t borrower_size)
{
    int borrowed = 0;
    for (size_t i = 1; i < chain->count; i++)
    {
        const Block *block = &chain->items[i];
        if (strcmp(block->book_id, book_id) == 0)
        {
            borrowed = strcmp(block->action, "BORROWED") == 0;
            if (borrowed && borrowed_at)
                *borrowed_at = block->timestamp;
            if (borrowed && borrower_id)
                snprintf(borrower_id, borrower_size, "%s", block->member_id);
        }
    }
    for (size_t i = 0; i < pending->count; i++)
    {
        const Block *block = &pending->items[i];
        if (strcmp(block->book_id, book_id) == 0)
        {
            borrowed = strcmp(block->action, "BORROWED") == 0;
            if (borrowed && borrowed_at)
                *borrowed_at = block->timestamp;
            if (borrowed && borrower_id)
                snprintf(borrower_id, borrower_size, "%s", block->member_id);
        }
    }
    return borrowed;
}

static int append_transaction(Chain *chain, PendingPool *pending, Book *book, Member *member, const char *action, EVP_PKEY *key)
{
    Block *block;
    time_t borrowed_at = 0;
    if (chain->count + pending->count >= MAX_BLOCKS || pending->count >= MAX_BLOCKS)
        return 0;
    block = &pending->items[pending->count];
    memset(block, 0, sizeof(*block));
    block->index = (int)(chain->count + pending->count);
    block->timestamp = time(NULL);
    snprintf(block->book_id, sizeof(block->book_id), "%s", book->book_id);
    snprintf(block->book_title, sizeof(block->book_title), "%s", book->title);
    snprintf(block->member_id, sizeof(block->member_id), "%s", member->member_id);
    snprintf(block->member_name, sizeof(block->member_name), "%s", member->full_name);
    snprintf(block->action, sizeof(block->action), "%s", action);
    snprintf(block->previous_hash, sizeof(block->previous_hash), "%s", chain->items[chain->count - 1].hash);
    if (strcmp(action, "RETURNED") == 0)
    {
        book_state(chain, pending, book->book_id, &borrowed_at, NULL, 0);
        block->token_reward = block->timestamp - borrowed_at <= LOAN_PERIOD_SECONDS ? 10 : 5;
        {
            char transaction_data[160];
            snprintf(transaction_data, sizeof(transaction_data), "%s|%s|%s|%d|%d|%lld", member->member_id,
                     book->book_id, action, block->token_reward, REWARD_FEE, (long long)block->timestamp);
            if (!sha256_text(transaction_data, block->transaction_id))
                return 0;
        }
    }
    if (!sign_block(block, key))
        return 0;
    pending->count++;
    return 1;
}

static int mine_one_block(Block *block, const Chain *chain, EVP_PKEY *key, int difficulty,
                          unsigned long long *attempts, unsigned long long miner_attempts[MINERS_IN_POOL],
                          const int miner_rates[MINERS_IN_POOL])
{
    int total_rate = 0;
    char previous_hash[HASH_HEX_LENGTH];
    block->index = (int)chain->count;
    memcpy(previous_hash, chain->items[chain->count - 1].hash, sizeof(previous_hash));
    memcpy(block->previous_hash, previous_hash, sizeof(block->previous_hash));
    block->difficulty = difficulty;
    block->nonce = 0;
    if (!sign_block(block, key))
        return 0;
    for (int i = 0; i < MINERS_IN_POOL; i++)
        total_rate += miner_rates ? miner_rates[i] : 0;
    for (;;)
    {
        if (!hash_block(block, block->hash))
            return 0;
        (*attempts)++;
        if (miner_attempts && miner_rates)
        {
            int draw = rand() % total_rate;
            for (int i = 0; i < MINERS_IN_POOL; i++)
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

static void print_pool_shares(const unsigned long long attempts[MINERS_IN_POOL], int block_reward)
{
    unsigned long long total = 0;
    for (int i = 0; i < MINERS_IN_POOL; i++)
        total += attempts[i];
    printf("Miner   Attempts   Share      Reward\n");
    for (int i = 0; i < MINERS_IN_POOL; i++)
    {
        double share = total ? (double)attempts[i] / (double)total : 0.0;
        printf("M%-6d %-10llu %6.2f%%    %.4f\n", i + 1, attempts[i], share * 100.0, share * block_reward * 0.98);
    }
    printf("Pool fee: %.2f coins (2%%)\n", block_reward * 0.02);
}

static int confirm_pending(Chain *chain, PendingPool *pending, TokenLedger *ledger, EVP_PKEY *key,
                           const char *ledger_path, int difficulty, const char *mode, int cloud_rounds)
{
    unsigned long long attempts;
    int miner_rates[MINERS_IN_POOL];
    if (pending->count == 0)
    {
        printf("Pending pool is empty.\n");
        return 1;
    }
    if (chain->count + pending->count > MAX_BLOCKS)
    {
        printf("ERROR: chain capacity exceeded.\n");
        return 0;
    }
    for (int i = 0; i < MINERS_IN_POOL; i++)
        miner_rates[i] = 10 + rand() % 91;
    {
        size_t old_count = chain->count;
        size_t pending_count = pending->count;
        /* Confirm every queued event in order; balances change only after chain persistence. */
        for (size_t i = 0; i < pending_count; i++)
        {
            Block *confirmed = &chain->items[chain->count];
            unsigned long long miner_attempts[MINERS_IN_POOL] = {0};
            attempts = 0;
            *confirmed = pending->items[i];
            if (!mine_one_block(confirmed, chain, key, difficulty, &attempts,
                                strcmp(mode, "pool") == 0 ? miner_attempts : NULL,
                                strcmp(mode, "pool") == 0 ? miner_rates : NULL))
            {
                chain->count = old_count;
                printf("ERROR: could not mine pending block.\n");
                return 0;
            }
            chain->count++;
                 printf("Mined block candidate %d: %s, reward=%d, txid=%s, hash attempts=%llu\n",
                   confirmed->index, confirmed->action, confirmed->token_reward,
                   confirmed->transaction_id[0] ? confirmed->transaction_id : "none", attempts);
            if (strcmp(mode, "pool") == 0)
                print_pool_shares(miner_attempts, MINING_REWARD);
            else if (strcmp(mode, "solo") == 0)
                printf("Solo miner reward: %d coins\n", MINING_REWARD);
        }
        if (!save_chain(ledger_path, chain))
        {
            chain->count = old_count;
            printf("ERROR: could not persist mined blocks.\n");
            return 0;
        }
        for (size_t i = old_count; i < chain->count; i++)
        {
            if (strcmp(chain->items[i].action, "RETURNED") == 0 && chain->items[i].token_reward > 0)
                apply_reward(ledger, &chain->items[i]);
            printf("Confirmed block %d after chain persistence.\n", chain->items[i].index);
            printf("Ledger after confirmed block %d:\n", chain->items[i].index);
            print_balances(ledger);
            print_utxos(ledger);
        }
        pending->count = 0;
        printf("Pending pool cleared; %zu block(s) confirmed.\n", pending_count);
        if (strcmp(mode, "cloud") == 0)
        {
            int gross = 0;
            int fees = 0;
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
            printf("Gross earnings=%d, total fees=%d, net profit=%d coins\n", gross, fees, gross - fees);
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
        printf("[%d] %s | %s | %s (%s) | %s | reward=%d | signature: %s\n", block->index, timestamp,
               block->book_title, block->member_name, block->member_id, block->action,
               block->token_reward, verify_signature(block, key) ? "VALID" : "INVALID");
    }
    if (chain->count == 1)
        printf("No lending records yet.\n");
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
    printf("  borrow BOOK_ID MEMBER_ID | return BOOK_ID MEMBER_ID | overdue BOOK_ID\n");
    printf("  pending | mine solo | mine pool | mine cloud ROUNDS | view | validate\n");
    printf("  balances | utxos | transfer SENDER_ID RECIPIENT_ID AMOUNT NONCE | history MEMBER_ID\n");
    printf("  tamper | help | quit\n");
}

static void print_pending(const PendingPool *pending)
{
    printf("Pending pool: %zu unconfirmed block(s)\n", pending->count);
    for (size_t i = 0; i < pending->count; i++)
        printf("  [%zu] %s | %s | %s | reward=%d\n", i + 1, pending->items[i].book_title,
               pending->items[i].member_name, pending->items[i].action, pending->items[i].token_reward);
}

int main(int argc, char **argv)
{
    BookRegistry books;
    MemberRegistry members;
    static Chain chain;
    static PendingPool pending;
    static TokenLedger ledger;
    LedgerModel model = MODEL_UTXO;
    int difficulty = 2;
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
        }
        else
        {
            fprintf(stderr, "Usage: %s [--model utxo|account] [--difficulty 1-4]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    srand((unsigned int)time(NULL));
    if (!load_books("books.txt", &books) || !load_members("members.txt", &members))
        return EXIT_FAILURE;
    printf("Loaded %zu books and %zu members.\n", books.count, members.count);
    key = load_or_create_key("signing_key.pem");
    if (!key || !authenticate("users.txt"))
    {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!load_chain("blockchain.dat", &chain, key) || !validate_chain(&chain, key, 1))
    {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    initialize_ledger(&ledger, &members, &chain, model);
    printf("Authenticated as librarian.\n");
    printf("Token model: %s | mining difficulty: %d leading zero(s)\n",
           model == MODEL_UTXO ? "UTXO" : "account", difficulty);
    print_help();
    while (printf("library> ") && fgets(line, sizeof(line), stdin))
    {
        char command[16] = {0}, first[32] = {0}, second[32] = {0}, third[32] = {0}, fourth[32] = {0};
        int fields = sscanf(line, "%15s %31s %31s %31s %31s", command, first, second, third, fourth);
        if (fields == EOF || fields == 0)
            continue;
        if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0)
            break;
        if (strcmp(command, "help") == 0)
        {
            print_help();
            continue;
        }
        if (strcmp(command, "view") == 0)
        {
            print_records(&chain, key);
            continue;
        }
        if (strcmp(command, "validate") == 0)
        {
            validate_chain(&chain, key, 1);
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
        if (strcmp(command, "transfer") == 0 && fields == 5)
        {
            char *amount_end = NULL;
            char *nonce_end = NULL;
            long amount = strtol(third, &amount_end, 10);
            unsigned long long nonce = strtoull(fourth, &nonce_end, 10);
            if (!amount_end || *amount_end || !nonce_end || *nonce_end || amount <= 0 || amount > 2147483647L)
                printf("ERROR: invalid transfer amount or nonce.\n");
            else if (!transfer_tokens(&ledger, first, second, (int)amount, nonce))
                printf("ERROR: transfer rejected (unknown account, insufficient balance, reused nonce, or invalid amount).\n");
            else
            {
                printf("Transfer confirmed in the in-memory token ledger.\n");
                print_balances(&ledger);
                print_utxos(&ledger);
            }
            continue;
        }
        if (strcmp(command, "mine") == 0 && (fields == 2 || fields == 3))
        {
            int rounds = 0;
            if (strcmp(first, "solo") != 0 && strcmp(first, "pool") != 0 && strcmp(first, "cloud") != 0)
                printf("ERROR: mining mode must be solo, pool, or cloud.\n");
            else if ((strcmp(first, "cloud") == 0 && fields != 3) || (strcmp(first, "cloud") != 0 && fields != 2))
                printf("ERROR: cloud requires a rental duration; solo and pool do not take one.\n");
            else
            {
                if (strcmp(first, "cloud") == 0)
                {
                    char *end = NULL;
                    long parsed = strtol(second, &end, 10);
                    if (!end || *end || parsed < 1 || parsed > 5)
                    {
                        printf("ERROR: cloud rental duration must be 1 to 5 rounds.\n");
                        continue;
                    }
                    rounds = (int)parsed;
                }
                confirm_pending(&chain, &pending, &ledger, key, "blockchain.dat", difficulty, first, rounds);
            }
            continue;
        }
        if (strcmp(command, "tamper") == 0)
        {
            if (chain.count < 2)
                printf("ERROR: add a lending record before tampering.\n");
            else
            {
                chain.items[1].member_name[0] = chain.items[1].member_name[0] == 'X' ? 'J' : 'X';
                printf("Tampered with block 1 in memory.\n");
                validate_chain(&chain, key, 1);
            }
            continue;
        }
        if (strcmp(command, "borrow") == 0 && fields == 3)
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else if (book_state(&chain, &pending, book->book_id, NULL, NULL, 0))
                printf("ERROR: book is already on loan.\n");
            else if (!append_transaction(&chain, &pending, book, member, "BORROWED", key))
                printf("ERROR: could not create borrow transaction.\n");
            else
                printf("Borrow queued for mining.\n");
            print_pending(&pending);
            continue;
        }
        if (strcmp(command, "return") == 0 && fields == 3)
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            time_t borrowed_at = 0;
            char borrower_id[20] = {0};
            int is_borrowed = book && book_state(&chain, &pending, book->book_id, &borrowed_at, borrower_id, sizeof(borrower_id));
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else if (!is_borrowed)
                printf("ERROR: book has no active loan.\n");
            else if (strcmp(borrower_id, member->member_id) != 0)
                printf("ERROR: only the borrowing member can return this book.\n");
            else if (!append_transaction(&chain, &pending, book, member, "RETURNED", key))
                printf("ERROR: could not create return transaction.\n");
            else
                printf("Return queued for mining; token reward=%d (net after fee=%d).\n",
                       time(NULL) - borrowed_at <= LOAN_PERIOD_SECONDS ? 10 : 5,
                       (time(NULL) - borrowed_at <= LOAN_PERIOD_SECONDS ? 10 : 5) - REWARD_FEE);
            print_pending(&pending);
            continue;
        }
        if (strcmp(command, "overdue") == 0 && fields == 2)
        {
            Book *book = find_book(&books, first);
            time_t borrowed_at = 0;
            int borrowed = book && book_state(&chain, &pending, book->book_id, &borrowed_at, NULL, 0);
            if (!book)
                printf("ERROR: Book not found.\n");
            else if (!borrowed)
                printf("Book has no active loan.\n");
            else if (time(NULL) - borrowed_at > LOAN_PERIOD_SECONDS)
                printf("Book is overdue and unreturned; no reward transaction is created.\n");
            else
                printf("Book is still within its 14-day loan period.\n");
            continue;
        }
        printf("ERROR: invalid command or arguments.\n");
    }
    free_ledger(&ledger);
    EVP_PKEY_free(key);
    return EXIT_SUCCESS;
}
