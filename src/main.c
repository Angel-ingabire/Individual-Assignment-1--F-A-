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
#define MAX_LINE 256
#define HASH_HEX_LENGTH 65
#define SIGNATURE_MAX_LENGTH 72
#define ACTION_LENGTH 10
#define LEDGER_MAGIC "LIBCHAIN1"

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
    unsigned char signature[SIGNATURE_MAX_LENGTH];
    unsigned int signature_len;
    char hash[HASH_HEX_LENGTH];
} Block;

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
    snprintf(output, output_size, "%d|%lld|%s|%s|%s|%s|%s|%s|%s", block->index, (long long)block->timestamp,
             block->book_id, block->book_title, block->member_id, block->member_name, block->action, block->previous_hash, signature_hex);
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
    char data[512];
    block_hash_data(block, data, sizeof(data));
    return sha256_text(data, output);
}

static int sign_block(Block *block, EVP_PKEY *key)
{
    char data[512];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signature_length = sizeof(block->signature);
    block_unsigned_data(block, data, sizeof(data));
    if (!context || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSignUpdate(context, data, strlen(data)) != 1 ||
        EVP_DigestSignFinal(context, block->signature, &signature_length) != 1 || signature_length > SIGNATURE_MAX_LENGTH)
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
    FILE *file = fopen(path, "rb");
    EVP_PKEY *key = NULL;
    if (file)
    {
        key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        fclose(file);
        return key;
    }
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) != 1 || EVP_PKEY_keygen(context, &key) != 1)
    {
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    file = fopen(path, "wb");
    if (!file || PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) != 1)
    {
        if (file)
            fclose(file);
        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    fclose(file);
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

static int load_chain(const char *path, Chain *chain)
{
    FILE *file = fopen(path, "rb");
    char magic[10] = {0};
    if (!file)
    {
        create_genesis(chain);
        return save_chain(path, chain);
    }
    if (fread(magic, 1, 9, file) != 9 || strcmp(magic, LEDGER_MAGIC) != 0 || fread(&chain->count, sizeof(chain->count), 1, file) != 1 || chain->count == 0 || chain->count > MAX_BLOCKS || fread(chain->items, sizeof(Block), chain->count, file) != chain->count)
    {
        fclose(file);
        fprintf(stderr, "ERROR: blockchain.dat is corrupt.\n");
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
        valid = block->index == (int)i && hash_block(block, computed) && strcmp(computed, block->hash) == 0;
        if (i == 0)
        {
            char genesis_previous_hash[HASH_HEX_LENGTH];
            memset(genesis_previous_hash, '0', 64);
            genesis_previous_hash[64] = '\0';
            valid = valid && strcmp(block->previous_hash, genesis_previous_hash) == 0;
        }
        if (i > 0)
            valid = valid && strcmp(block->previous_hash, chain->items[i - 1].hash) == 0 && verify_signature(block, key);
        if (!valid && print_result)
            fprintf(stderr, "INVALID: block %d failed hash, link, or signature verification.\n", block->index);
    }
    if (print_result)
        printf("Chain validation: %s (%zu blocks)\n", valid ? "VALID" : "INVALID", chain->count);
    return valid;
}

static int book_on_loan(const Chain *chain, const char *book_id)
{
    for (size_t i = chain->count; i > 1; i--)
    {
        const Block *block = &chain->items[i - 1];
        if (strcmp(block->book_id, book_id) == 0)
            return strcmp(block->action, "BORROWED") == 0;
    }
    return 0;
}

static int append_transaction(Chain *chain, Book *book, Member *member, const char *action, EVP_PKEY *key)
{
    Block *block;
    char previous_hash[HASH_HEX_LENGTH];
    if (chain->count >= MAX_BLOCKS)
        return 0;
    block = &chain->items[chain->count];
    memset(block, 0, sizeof(*block));
    block->index = (int)chain->count;
    block->timestamp = time(NULL);
    snprintf(block->book_id, sizeof(block->book_id), "%s", book->book_id);
    snprintf(block->book_title, sizeof(block->book_title), "%s", book->title);
    snprintf(block->member_id, sizeof(block->member_id), "%s", member->member_id);
    snprintf(block->member_name, sizeof(block->member_name), "%s", member->full_name);
    snprintf(block->action, sizeof(block->action), "%s", action);
    memcpy(previous_hash, chain->items[chain->count - 1].hash, sizeof(previous_hash));
    memcpy(block->previous_hash, previous_hash, sizeof(block->previous_hash));
    if (!sign_block(block, key))
        return 0;
    chain->count++;
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
        printf("[%d] %s | %s | %s | %s | signature: %s\n", block->index, timestamp, block->book_title, block->member_name, block->action, verify_signature(block, key) ? "VALID" : "INVALID");
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
    printf("Commands: borrow BOOK_ID MEMBER_ID | return BOOK_ID MEMBER_ID | view | validate | tamper | help | quit\n");
}

int main(void)
{
    BookRegistry books;
    MemberRegistry members;
    static Chain chain;
    EVP_PKEY *key;
    char line[MAX_LINE];
    if (!load_books("books.txt", &books) || !load_members("members.txt", &members))
        return EXIT_FAILURE;
    printf("Loaded %zu books and %zu members.\n", books.count, members.count);
    key = load_or_create_key("signing_key.pem");
    if (!key || !authenticate("users.txt"))
    {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    if (!load_chain("blockchain.dat", &chain) || !validate_chain(&chain, key, 1))
    {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    printf("Authenticated as librarian.\n");
    print_help();
    while (printf("library> ") && fgets(line, sizeof(line), stdin))
    {
        char command[16] = {0}, first[32] = {0}, second[32] = {0};
        int fields = sscanf(line, "%15s %31s %31s", command, first, second);
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
            else if (book_on_loan(&chain, book->book_id))
                printf("ERROR: book is already on loan.\n");
            else if (!append_transaction(&chain, book, member, "BORROWED", key))
                printf("ERROR: could not create borrow transaction.\n");
            else if (save_chain("blockchain.dat", &chain))
                printf("Borrow recorded in block %zu.\n", chain.count - 1);
            else
            {
                chain.count--;
                printf("ERROR: could not persist borrow transaction.\n");
            }
            continue;
        }
        if (strcmp(command, "return") == 0 && fields == 3)
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else if (!book_on_loan(&chain, book->book_id))
                printf("ERROR: book has no active loan.\n");
            else if (!append_transaction(&chain, book, member, "RETURNED", key))
                printf("ERROR: could not create return transaction.\n");
            else if (save_chain("blockchain.dat", &chain))
                printf("Return recorded in block %zu.\n", chain.count - 1);
            else
            {
                chain.count--;
                printf("ERROR: could not persist return transaction.\n");
            }
            continue;
        }
        printf("ERROR: invalid command or arguments.\n");
    }
    EVP_PKEY_free(key);
    return EXIT_SUCCESS;
}
