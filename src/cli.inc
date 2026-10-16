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
    printf("  set_difficulty 1-4 | set_renewal_days 1-3650\n");
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
    if (members->count >= MAX_MEMBERS ||
        !valid_identifier(member_id, sizeof(members->items[0].member_id)) ||
        !full_name[0] || strlen(full_name) >= sizeof(members->items[0].full_name) ||
        !valid_record_text(full_name) || strchr(full_name, ',') ||
        !valid_identifier(course_code, sizeof(members->items[0].course_code)) ||
        find_member(members, member_id))
        return 0;
    snprintf(members->items[members->count].member_id, sizeof(members->items[0].member_id), "%s", member_id);
    snprintf(members->items[members->count].full_name, sizeof(members->items[0].full_name), "%s", full_name);
    snprintf(members->items[members->count].course_code, sizeof(members->items[0].course_code), "%s", course_code);
    members->count++;
    return 1;
}

static int register_book(BookRegistry *books, const char *book_id,
                         const char *title, const char *author)
{
    if (books->count >= MAX_BOOKS ||
        !valid_identifier(book_id, sizeof(books->items[0].book_id)) ||
        !title[0] || strlen(title) >= sizeof(books->items[0].title) ||
        !author[0] || strlen(author) >= sizeof(books->items[0].author) ||
        !valid_record_text(title) || !valid_record_text(author) ||
        strchr(title, ',') || strchr(author, ',') || find_book(books, book_id))
        return 0;
    snprintf(books->items[books->count].book_id, sizeof(books->items[0].book_id), "%s", book_id);
    snprintf(books->items[books->count].title, sizeof(books->items[0].title), "%s", title);
    snprintf(books->items[books->count].author, sizeof(books->items[0].author), "%s", author);
    books->count++;
    return 1;
}

static int save_member_registry(const char *path,
                                const MemberRegistry *members)
{
    char temporary_path[512];
    FILE *file;
    int success = 1;
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path) >=
        (int)sizeof(temporary_path))
        return 0;
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    for (size_t i = 0; success && i < members->count; i++)
        success = fprintf(file, "%s,%s,%s\n", members->items[i].member_id,
                          members->items[i].full_name,
                          members->items[i].course_code) >= 0;
    if (fflush(file) != 0)
        success = 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success || !replace_file_atomically(temporary_path, path))
    {
        remove(temporary_path);
        return 0;
    }
    return 1;
}

static int save_book_registry(const char *path, const BookRegistry *books)
{
    char temporary_path[512];
    FILE *file;
    int success = 1;
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path) >=
        (int)sizeof(temporary_path))
        return 0;
    file = fopen(temporary_path, "wb");
    if (!file)
        return 0;
    for (size_t i = 0; success && i < books->count; i++)
        success = fprintf(file, "%s,%s,%s\n", books->items[i].book_id,
                          books->items[i].title,
                          books->items[i].author) >= 0;
    if (fflush(file) != 0)
        success = 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success || !replace_file_atomically(temporary_path, path))
    {
        remove(temporary_path);
        return 0;
    }
    return 1;
}

static int save_chain_metadata(const char *path, int difficulty, int renewal_days)
{
    char temporary_path[128];
    FILE *file;
    int reward = MINING_REWARD;
    int success;
    if (difficulty < 1 || difficulty > 4 || renewal_days < 1 ||
        renewal_days > 3650)
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
              fwrite(&renewal_days, sizeof(renewal_days), 1, file) == 1 &&
              fflush(file) == 0;
    if (fclose(file) != 0)
        success = 0;
    if (!success)
    {
        remove(temporary_path);
        return 0;
    }
    if (!replace_file_atomically(temporary_path, path))
    {
        remove(temporary_path);
        return 0;
    }
    return 1;
}

static int load_chain_metadata(const char *path, int *difficulty,
                               int *renewal_days)
{
    FILE *file = fopen(path, "rb");
    char magic[9] = {0};
    int saved_difficulty;
    int saved_reward;
    int saved_renewal_days = 14;
    if (!file)
        return 0;
    int valid = fread(magic, 1, 8, file) == 8 &&
                fread(&saved_difficulty, sizeof(saved_difficulty), 1, file) == 1 &&
                fread(&saved_reward, sizeof(saved_reward), 1, file) == 1;
    if (valid && strcmp(magic, METADATA_MAGIC) == 0)
        valid = fread(&saved_renewal_days, sizeof(saved_renewal_days), 1, file) == 1 &&
                fgetc(file) == EOF;
    else if (valid && strcmp(magic, "LIBMETA1") == 0)
        valid = fgetc(file) == EOF;
    else
        valid = 0;
    valid = valid && saved_difficulty >= 1 && saved_difficulty <= 4 &&
            saved_reward == MINING_REWARD &&
            saved_renewal_days >= 1 && saved_renewal_days <= 3650;
    fclose(file);
    if (!valid)
    {
        fprintf(stderr, "ERROR: chain_metadata.dat is corrupt or incompatible.\n");
        return -1;
    }
    *difficulty = saved_difficulty;
    *renewal_days = saved_renewal_days;
    return 1;
}
