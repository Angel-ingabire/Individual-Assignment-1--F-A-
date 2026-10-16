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
static int make_record_id(LendingRecord *record);

static int public_key_fingerprint(EVP_PKEY *key, char output[HASH_HEX_LENGTH])
{
    unsigned char *der = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    int der_length;
    int success = 0;
    if (!key || (der_length = i2d_PUBKEY(key, NULL)) <= 0)
        return 0;
    der = (unsigned char *)OPENSSL_malloc((size_t)der_length);
    if (der)
    {
        unsigned char *cursor = der;
        if (i2d_PUBKEY(key, &cursor) == der_length &&
            EVP_Digest(der, (size_t)der_length, digest, &digest_length,
                       EVP_sha256(), NULL) == 1 &&
            digest_length == 32)
        {
            hex_encode(digest, digest_length, output, HASH_HEX_LENGTH);
            success = 1;
        }
    }
    OPENSSL_free(der);
    return success;
}

static int record_unsigned_data(const LendingRecord *record, char *output, size_t output_size)
{
    size_t used = 0;
    int length = snprintf(output, output_size, "%s|%s|%s|%s|%s|%s|%s|%s|%lld|%d|%llu|%d|%s|%u|%zu",
                          record->record_id, record->book_id, record->copy_id, record->book_title,
                          record->member_id, record->member_name, record->action,
                          record->reason_code, (long long)record->due_date,
                          record->fine_amount, record->nonce, record->token_reward,
                          record->signing_key_fingerprint, record->utxo_proof.version,
                          record->utxo_proof.input_count);
    if (length < 0 || (size_t)length >= output_size)
        return 0;
    used = (size_t)length;
    if (record->utxo_proof.input_count > MAX_TRANSFER_INPUTS ||
        record->utxo_proof.output_count > MAX_TRANSFER_OUTPUTS)
        return 0;
    for (size_t i = 0; i < record->utxo_proof.input_count; i++)
    {
        length = snprintf(output + used, output_size - used, "|%s:%u",
                          record->utxo_proof.inputs[i].transaction_id,
                          record->utxo_proof.inputs[i].output_index);
        if (length < 0 || (size_t)length >= output_size - used)
            return 0;
        used += (size_t)length;
    }
    length = snprintf(output + used, output_size - used, "|%zu",
                      record->utxo_proof.output_count);
    if (length < 0 || (size_t)length >= output_size - used)
        return 0;
    used += (size_t)length;
    for (size_t i = 0; i < record->utxo_proof.output_count; i++)
    {
        length = snprintf(output + used, output_size - used, "|%s:%d",
                          record->utxo_proof.outputs[i].owner,
                          record->utxo_proof.outputs[i].amount);
        if (length < 0 || (size_t)length >= output_size - used)
            return 0;
        used += (size_t)length;
    }
    return 1;
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

static int legacy_v4_record_unsigned_data(const LendingRecord *record, char *output, size_t output_size)
{
    int length = snprintf(output, output_size, "%s|%s|%s|%s|%s|%s|%s|%s|%lld|%d|%llu|%d",
                          record->record_id, record->book_id, record->copy_id, record->book_title,
                          record->member_id, record->member_name, record->action,
                          record->reason_code, (long long)record->due_date,
                          record->fine_amount, record->nonce, record->token_reward);
    return length >= 0 && (size_t)length < output_size;
}

static int legacy_make_record_id(LendingRecord *record)
{
    char data[512];
    record->record_id[0] = '\0';
    return legacy_record_unsigned_data(record, data, sizeof(data)) &&
           sha256_text(data, record->record_id);
}

static int legacy_v4_make_record_id(LendingRecord *record)
{
    char data[512];
    record->record_id[0] = '\0';
    return legacy_v4_record_unsigned_data(record, data, sizeof(data)) &&
           sha256_text(data, record->record_id);
}

static int hash_record(const LendingRecord *record, char output[HASH_HEX_LENGTH])
{
    char data[4096];
    char signature_hex[SIGNATURE_MAX_LENGTH * 2 + 1];
    char complete[4200];
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
    char data[16384];
    size_t used;
    int length;
    if (block->record_count > MAX_RECORDS_PER_BLOCK)
        return 0;
    length = snprintf(data, sizeof(data), "%d|%lld|%zu|%s|%s|%s|%d|%s|%d|%llu|%s|%zu|%s|%s|%u|%zu|%d",
                      block->index, (long long)block->timestamp, block->record_count,
                      block->previous_hash, block->merkle_root, block->sealed_by,
                      block->token_reward, block->transaction_id, block->difficulty, block->nonce,
                      block->legacy_source_tip, block->legacy_block_count, block->mining_mode,
                      block->token_model,
                      block->cloud_rounds, block->payout_count, block->cloud_cost);
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
    if (block->payout_count > MAX_BLOCK_PAYOUTS)
        return 0;
    for (size_t i = 0; i < block->payout_count; i++)
    {
        const MiningPayout *payout = &block->payouts[i];
        if (payout->cost_input_count > MAX_TRANSFER_INPUTS)
            return 0;
        length = snprintf(data + used, sizeof(data) - used, "|P:%s:%llu:%lld:%zu:%d",
                          payout->member_id, payout->attempts,
                          (long long)payout->reward_units,
                          payout->cost_input_count, payout->cost_change);
        if (length < 0 || (size_t)length >= sizeof(data) - used)
            return 0;
        used += (size_t)length;
        for (size_t j = 0; j < payout->cost_input_count; j++)
        {
            length = snprintf(data + used, sizeof(data) - used, "|C:%s:%u",
                              payout->cost_inputs[j].transaction_id,
                              payout->cost_inputs[j].output_index);
            if (length < 0 || (size_t)length >= sizeof(data) - used)
                return 0;
            used += (size_t)length;
        }
    }
    return sha256_text(data, output);
}

static int sign_record(LendingRecord *record, EVP_PKEY *key)
{
    char data[4096];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signature_length = sizeof(record->signature);
    EVP_PKEY *signing_key = (strcmp(record->action, "LOST") == 0 ||
                             strcmp(record->action, "CONDITION") == 0)
                                ? key
                                : member_signing_key(record->member_id);
    if (!signing_key || !public_key_fingerprint(signing_key,
                                                record->signing_key_fingerprint))
    {
        EVP_MD_CTX_free(context);
        return 0;
    }
    if (!make_record_id(record))
    {
        EVP_MD_CTX_free(context);
        return 0;
    }
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
    char data[4096];
    char fingerprint[HASH_HEX_LENGTH];
    EVP_PKEY *member_key = member_verification_key(record->member_id);
    EVP_PKEY *selected_key = NULL;
    EVP_MD_CTX *context;
    int result = 0;
    if (!record->signature_len || record->signature_len > SIGNATURE_MAX_LENGTH ||
        !record_unsigned_data(record, data, sizeof(data)))
        return 0;
    if (member_key && public_key_fingerprint(member_key, fingerprint) &&
        strcmp(fingerprint, record->signing_key_fingerprint) == 0)
        selected_key = member_key;
    if (!selected_key && key && public_key_fingerprint(key, fingerprint) &&
        strcmp(fingerprint, record->signing_key_fingerprint) == 0)
        selected_key = key;
    if (!selected_key)
        return 0;
    context = EVP_MD_CTX_new();
    result = context && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, selected_key) == 1 &&
             EVP_DigestVerifyUpdate(context, data, strlen(data)) == 1 &&
             EVP_DigestVerifyFinal(context, record->signature, record->signature_len) == 1;
    EVP_MD_CTX_free(context);
    return result;
}

static int verify_legacy_v4_record_signature(const LendingRecord *record, EVP_PKEY *key)
{
    char data[512];
    EVP_PKEY *member_key = member_verification_key(record->member_id);
    EVP_MD_CTX *context;
    int result = 0;
    if (!record->signature_len || record->signature_len > SIGNATURE_MAX_LENGTH ||
        !legacy_v4_record_unsigned_data(record, data, sizeof(data)))
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
    if (legacy_v4_make_record_id(&identity) &&
        strcmp(identity.record_id, stored_id) == 0 &&
        verify_legacy_v4_record_signature(record, librarian_key))
    {
        record->record_id[0] = '\0';
        return make_record_id(record) && sign_record(record, librarian_key);
    }
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
    else if (strcmp(magic, "LIBCHAIN4") == 0 ||
             strcmp(magic, "LIBCHAIN3") == 0)
    {
        int version_four = strcmp(magic, "LIBCHAIN4") == 0;
        LegacyV4Block *legacy = (LegacyV4Block *)calloc(chain->count, sizeof(*legacy));
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
                snprintf(block->legacy_source_tip, sizeof(block->legacy_source_tip), "%s",
                         legacy[chain->count - 1].hash);
                block->legacy_block_count = chain->count - 1;
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
            snprintf(block->mining_mode, sizeof(block->mining_mode), "legacy");
            snprintf(block->token_model, sizeof(block->token_model), "legacy");
            snprintf(block->previous_hash, sizeof(block->previous_hash), "%s",
                     chain->items[i - 1].hash);
            for (size_t j = 0; j < block->record_count; j++)
            {
                const LegacyV4LendingRecord *old_record = &old->records[j];
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
        printf("Migrated version-%d ledger to the version-5 chain format.\n",
               version_four ? 4 : 3);
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
            snprintf(block->mining_mode, sizeof(block->mining_mode), "legacy");
            snprintf(block->token_model, sizeof(block->token_model), "legacy");
            if (i == 0)
            {
                block->timestamp = old_timestamp;
                memset(block->previous_hash, '0', 64);
                block->previous_hash[64] = '\0';
                block->legacy_source_tip[0] = '\0';
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
                        if (version_two)
                            snprintf(chain->items[0].legacy_source_tip, sizeof(chain->items[0].legacy_source_tip),
                                     "%s", legacy_v2[chain->count - 1].hash);
                        else
                            snprintf(chain->items[0].legacy_source_tip, sizeof(chain->items[0].legacy_source_tip),
                                     "%s", legacy_v1[chain->count - 1].hash);
                        chain->items[0].legacy_block_count = chain->count - 1;
                        if (!hash_block(&chain->items[0], chain->items[0].hash))
                        {
                            free(legacy_v2);
                            free(legacy_v1);
                            fclose(file);
                            return 0;
                        }
                        for (size_t i = 1; i < chain->count; i++)
                        {
                            snprintf(chain->items[i].previous_hash, sizeof(chain->items[i].previous_hash),
                                     "%s", chain->items[i - 1].hash);
                            if (!hash_block(&chain->items[i], chain->items[i].hash))
                            {
                                free(legacy_v2);
                                free(legacy_v1);
                                fclose(file);
                                return 0;
                            }
                            chain->items[i].nonce = 0;
                            while (!has_pow_prefix(chain->items[i].hash, chain->items[i].difficulty))
                            {
                                chain->items[i].nonce++;
                                if (!hash_block(&chain->items[i], chain->items[i].hash))
                                {
                                    free(legacy_v2);
                                    free(legacy_v1);
                                    fclose(file);
                                    return 0;
                                }
                            }
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

static int utxo_proof_is_empty(const UTXOTransactionProof *proof)
{
    return proof->version == 0 && proof->input_count == 0 &&
           proof->output_count == 0;
}

static int validate_block_payouts(const Block *block,
                                  const MemberRegistry *members,
                                  size_t block_number,
                                  size_t legacy_block_count)
{
    unsigned long long total_attempts = 0;
    int64_t total_reward_units = 0;
    int no_cost_inputs = 1;
    if (block_number <= legacy_block_count)
        return strcmp(block->mining_mode, "legacy") == 0 &&
               strcmp(block->token_model, "legacy") == 0 &&
               block->payout_count == 0 && block->cloud_rounds == 0 &&
               block->cloud_cost == 0;
    if (strcmp(block->mining_mode, "legacy") == 0 ||
        (strcmp(block->token_model, "ACCOUNT") != 0 &&
         strcmp(block->token_model, "UTXO") != 0) ||
        block->payout_count == 0 ||
        block->payout_count > MAX_BLOCK_PAYOUTS)
        return 0;
    for (size_t i = 0; i < block->payout_count; i++)
    {
        const MiningPayout *payout = &block->payouts[i];
        int known_member = 0;
        if (!payout->member_id[0] || payout->reward_units < 0 ||
            payout->cost_input_count > MAX_TRANSFER_INPUTS ||
            payout->cost_change < 0)
            return 0;
        for (size_t j = 0; j < members->count; j++)
            if (strcmp(payout->member_id, members->items[j].member_id) == 0)
                known_member = 1;
        for (size_t j = 0; j < i; j++)
            if (strcmp(payout->member_id, block->payouts[j].member_id) == 0)
                return 0;
        if (!known_member || ULLONG_MAX - total_attempts < payout->attempts ||
            INT64_MAX - total_reward_units < payout->reward_units)
            return 0;
        if (payout->cost_input_count != 0 || payout->cost_change != 0)
            no_cost_inputs = 0;
        total_attempts += payout->attempts;
        total_reward_units += payout->reward_units;
    }
    if (total_attempts == 0)
        return 0;
    if (strcmp(block->mining_mode, "solo") == 0)
        return block->payout_count == 1 && block->cloud_rounds == 0 &&
               block->cloud_cost == 0 &&
               no_cost_inputs &&
               total_reward_units == (int64_t)MINING_REWARD * MINING_REWARD_SCALE;
    if (strcmp(block->mining_mode, "pool") == 0)
        return block->payout_count >= 2 && block->cloud_rounds == 0 &&
               block->cloud_cost == 0 &&
               no_cost_inputs &&
               total_reward_units ==
                   (int64_t)MINING_REWARD * MINING_REWARD_SCALE * 98 / 100;
    if (strcmp(block->mining_mode, "cloud") == 0)
        return block->payout_count == 1 && block->cloud_rounds >= 1 &&
               block->cloud_rounds <= 5 &&
               block->cloud_cost ==
                   (int)(block->cloud_rounds *
                         (CLOUD_RENTAL_FEE + CLOUD_MAINTENANCE_FEE)) &&
               total_reward_units ==
                   (int64_t)block->cloud_rounds * MINING_REWARD *
                       MINING_REWARD_SCALE &&
               (strcmp(block->token_model, "ACCOUNT") == 0
                    ? (block->payouts[0].cost_input_count == 0 &&
                       block->payouts[0].cost_change == 0)
                    : block->payouts[0].cost_input_count > 0);
    return 0;
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
                    block->record_count == 0 &&
                    block->legacy_block_count < chain->count &&
                    (block->legacy_source_tip[0] == '\0'
                         ? block->legacy_block_count == 0
                         : strlen(block->legacy_source_tip) == HASH_HEX_LENGTH - 1);
        }
        if (i > 0)
            valid = valid && block->record_count > 0 &&
                    block->legacy_source_tip[0] == '\0' &&
                    block->legacy_block_count == 0 &&
                    strcmp(block->previous_hash, chain->items[i - 1].hash) == 0 &&
                    block->timestamp > chain->items[i - 1].timestamp &&
                    merkle_root(block->records, block->record_count, computed_root) &&
                    strcmp(computed_root, block->merkle_root) == 0;
        if (i > 0 && valid)
        {
            int total_reward = 0;
            valid = block->difficulty >= 1 && block->difficulty <= 4 &&
                    has_pow_prefix(block->hash, block->difficulty) &&
                    validate_block_payouts(block, members, i,
                                           chain->items[0].legacy_block_count);
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
                if (valid && chain->items[0].legacy_source_tip[0] == '\0')
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
                if (token_transfer && strcmp(record->reason_code, "UTXO") == 0)
                {
                    if (i <= chain->items[0].legacy_block_count)
                        valid = valid && utxo_proof_is_empty(&record->utxo_proof);
                    else
                        valid = valid && record->utxo_proof.version == 1 &&
                                record->utxo_proof.input_count > 0 &&
                                record->utxo_proof.input_count <= MAX_TRANSFER_INPUTS &&
                                record->utxo_proof.output_count > 0 &&
                                record->utxo_proof.output_count <= MAX_TRANSFER_OUTPUTS;
                }
                else
                    valid = valid && utxo_proof_is_empty(&record->utxo_proof);
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
    if (valid)
    {
        TokenLedger *account_ledger = (TokenLedger *)calloc(1, sizeof(*account_ledger));
        TokenLedger *utxo_ledger = (TokenLedger *)calloc(1, sizeof(*utxo_ledger));
        if (!account_ledger || !utxo_ledger)
            valid = 0;
        else
            valid = initialize_ledger(account_ledger, members, chain, MODEL_ACCOUNT) &&
                    initialize_ledger(utxo_ledger, members, chain, MODEL_UTXO);
        if (account_ledger)
        {
            free_ledger(account_ledger);
            free(account_ledger);
        }
        if (utxo_ledger)
        {
            free_ledger(utxo_ledger);
            free(utxo_ledger);
        }
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
