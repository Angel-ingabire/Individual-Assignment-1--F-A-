static int parse_cli_tokens(const char *line, char tokens[6][128],
                            size_t *token_count)
{
    const unsigned char *cursor = (const unsigned char *)line;
    *token_count = 0;
    while (*cursor)
    {
        size_t length = 0;
        size_t capacity;
        while (*cursor && isspace(*cursor))
            cursor++;
        if (!*cursor)
            break;
        if (*token_count == 6)
            return 0;
        capacity = *token_count == 0 ? 32 : 128;
        while (*cursor && !isspace(*cursor))
        {
            if (length + 1 >= capacity)
                return 0;
            tokens[*token_count][length++] = (char)*cursor++;
        }
        tokens[*token_count][length] = '\0';
        (*token_count)++;
    }
    return 1;
}

static int cli_command_arity_valid(const char *command, int fields)
{
#define EXACT(name, count) (strcmp(command, name) == 0 && fields == count)
#define RANGE(name, minimum, maximum) \
    (strcmp(command, name) == 0 && fields >= minimum && fields <= maximum)
    if (EXACT("quit", 1) || EXACT("exit", 1) || EXACT("help", 1) ||
        EXACT("view", 1) || EXACT("validate", 1) ||
        EXACT("validate_chain", 1) || EXACT("pending", 1) ||
        EXACT("balances", 1) || EXACT("utxos", 1) ||
        EXACT("utxo_view", 1) || EXACT("copies", 1) ||
        EXACT("reservations", 1) ||
        RANGE("view_fines", 1, 2) || EXACT("difficulty_status", 1) ||
        EXACT("chain_save", 1) || EXACT("chain_load", 1) ||
        EXACT("chain_view", 1) || EXACT("tamper", 1) ||
        EXACT("lending_history", 1) || EXACT("fraud_review", 1) ||
        EXACT("pool_view", 1))
        return 1;
    if (EXACT("register_member", 4) || EXACT("register_book", 4) ||
        EXACT("reserve", 3) || EXACT("renew", 3) ||
        EXACT("add_copy", 4) || EXACT("mark_lost", 4) ||
        EXACT("settle_fine", 4))
        return 1;
    if (EXACT("borrow", 3) || EXACT("borrow", 4) ||
        EXACT("return", 3) || EXACT("return", 4) ||
        EXACT("overdue", 1) || EXACT("overdue", 2) ||
        EXACT("check_overdue", 1) || EXACT("check_overdue", 2) ||
        EXACT("copy", 2) || EXACT("view_copy", 2) ||
        EXACT("view_book", 2) || EXACT("view_member", 2) ||
        EXACT("member_nonce", 2) || EXACT("account_nonce", 2) ||
        EXACT("member_key", 2) || EXACT("token_balance", 2) ||
        EXACT("account_balance", 2) || EXACT("reservation_status", 2) ||
        EXACT("approve_suspicious", 2) || EXACT("reject_suspicious", 2) ||
        EXACT("member_history", 2) || EXACT("book_history", 2) ||
        EXACT("history", 2) || EXACT("set_difficulty", 2) ||
        EXACT("set_renewal_days", 2) || EXACT("set_condition", 5) ||
        EXACT("transfer", 5) || EXACT("token_transfer", 5) ||
        EXACT("account_transfer", 5) ||
        EXACT("transaction_history", 2) ||
        EXACT("mine_solo", 2) || RANGE("mine_pool", 3, 5) ||
        EXACT("mine_cloud", 3))
        return 1;
    if (EXACT("mine", 3) || RANGE("mine", 4, 6))
        return 1;
    return 0;
#undef EXACT
#undef RANGE
}

static int discard_overlong_cli_line(const char *line)
{
    size_t length = strlen(line);
    int character;
    if (length > 0 && line[length - 1] == '\n')
        return 0;
    character = fgetc(stdin);
    if (character == EOF || character == '\n')
        return 0;
    while (character != EOF && character != '\n')
        character = fgetc(stdin);
    return 1;
}

static LibraryState *begin_library_state_transaction(
    const CopyRegistry *copies, const ReservationQueue *reservations,
    const PendingPool *pending)
{
    LibraryState *candidate = (LibraryState *)malloc(sizeof(*candidate));
    if (!candidate)
        return NULL;
    candidate->copies = *copies;
    candidate->reservations = *reservations;
    candidate->pending = *pending;
    return candidate;
}

static int commit_library_state_transaction(
    const char *path, LibraryState *candidate, CopyRegistry *copies,
    ReservationQueue *reservations, PendingPool *pending)
{
    int saved = save_library_state(path, &candidate->copies,
                                   &candidate->reservations,
                                   &candidate->pending);
    if (saved)
    {
        *copies = candidate->copies;
        *reservations = candidate->reservations;
        *pending = candidate->pending;
    }
    free(candidate);
    return saved;
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
        int metadata_status = load_chain_metadata("chain_metadata.dat", &difficulty,
                                                  &renewal_period_days);
        if (metadata_status < 0)
            return EXIT_FAILURE;
        if (difficulty_from_args)
            difficulty = requested_difficulty;
        if (!save_chain_metadata("chain_metadata.dat", difficulty,
                                 renewal_period_days))
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
        if (token_state == 0 && chain.items[0].legacy_block_count > 0)
        {
            fprintf(stderr, "ERROR: this migrated chain requires its matching legacy token snapshot; preserve the chain and restore the model-specific token-state backup.\n");
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
    fflush(stdout);
    check_overdue(&chain, &pending, &copies, &books, &members, key, 1);
    if (!save_library_state("library_state.dat", &copies, &reservations, &pending))
        fprintf(stderr, "ERROR: overdue scan could not persist library state.\n");
    print_help();
    while (printf("library> ") && fflush(stdout) != EOF &&
           fgets(line, sizeof(line), stdin))
    {
        char command[32] = {0}, first[128] = {0}, second[128] = {0},
             third[128] = {0}, fourth[128] = {0}, fifth[128] = {0};
        char tokens[6][128] = {{0}};
        size_t token_count = 0;
        int fields;
        if (discard_overlong_cli_line(line))
        {
            fprintf(stderr, "ERROR: command line is too long; the entire line was discarded.\n");
            continue;
        }
        if (!parse_cli_tokens(line, tokens, &token_count))
        {
            fprintf(stderr, "ERROR: command has too many arguments or a token exceeds its length limit.\n");
            continue;
        }
        fields = (int)token_count;
        if (fields > 0)
            snprintf(command, sizeof(command), "%s", tokens[0]);
        if (fields > 1)
            snprintf(first, sizeof(first), "%s", tokens[1]);
        if (fields > 2)
            snprintf(second, sizeof(second), "%s", tokens[2]);
        if (fields > 3)
            snprintf(third, sizeof(third), "%s", tokens[3]);
        if (fields > 4)
            snprintf(fourth, sizeof(fourth), "%s", tokens[4]);
        if (fields > 5)
            snprintf(fifth, sizeof(fifth), "%s", tokens[5]);
        if (fields == 0)
            continue;
        if (!cli_command_arity_valid(command, fields))
        {
            printf("ERROR: invalid command or arguments.\n");
            continue;
        }
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
            MemberRegistry candidate_members = members;
            TokenLedger *candidate_ledger =
                (TokenLedger *)malloc(sizeof(*candidate_ledger));
            if (!candidate_ledger)
            {
                fprintf(stderr, "ERROR: could not stage member account registration.\n");
                continue;
            }
            *candidate_ledger = ledger;
            if (ledger.account_count >= MAX_MEMBERS ||
                !register_member(&candidate_members, first, second, third))
            {
                active_member_registry = &members;
                free(candidate_ledger);
                printf("ERROR: member registration rejected; check fields, uniqueness, and registry capacity.\n");
                continue;
            }
            active_member_registry = &candidate_members;
            if (!ensure_member_signing_key(&candidate_members, first) ||
                !add_ledger_member(candidate_ledger, first))
            {
                active_member_registry = &members;
                free(candidate_ledger);
                fprintf(stderr, "ERROR: member registration could not initialize its key or account; registry was unchanged.\n");
            }
            else if (!save_member_registry("members.txt", &candidate_members))
            {
                active_member_registry = &members;
                free(candidate_ledger);
                fprintf(stderr, "ERROR: member registry could not be persisted; registration was not applied.\n");
            }
            else if (!save_token_ledger(candidate_ledger, &chain))
            {
                if (!save_member_registry("members.txt", &members))
                    fprintf(stderr, "ERROR: member token-state save failed and the prior registry could not be restored; repair members.txt before continuing.\n");
                else
                    fprintf(stderr, "ERROR: member token-state save failed; registry was rolled back.\n");
                active_member_registry = &members;
                free(candidate_ledger);
            }
            else
            {
                members = candidate_members;
                ledger = *candidate_ledger;
                active_member_registry = &members;
                free(candidate_ledger);
                printf("Registered member %s. Names with spaces should be entered with underscores.\n", first);
            }
            continue;
        }
        if (strcmp(command, "register_book") == 0 && fields == 4)
        {
            BookRegistry candidate_books = books;
            if (register_book(&candidate_books, first, second, third) &&
                save_book_registry("books.txt", &candidate_books))
            {
                books = candidate_books;
                printf("Registered book %s; add one or more physical copies with add_copy.\n", first);
            }
            else
                printf("ERROR: book registration rejected or could not be persisted; check fields, uniqueness, and registry capacity.\n");
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
            LibraryState *candidate = begin_library_state_transaction(
                &copies, &reservations, &pending);
            PendingRequest *request;
            if (!candidate)
            {
                fprintf(stderr, "ERROR: could not stage suspicious-request review.\n");
                continue;
            }
            request = find_pending_request(&candidate->pending, first);
            if (!request || request->status != REQUEST_SUSPICIOUS)
            {
                free(candidate);
                printf("ERROR: suspicious request not found (ID must be unique).\n");
            }
            else if (strcmp(command, "approve_suspicious") == 0)
            {
                BookCopy *copy = NULL;
                char approved_id[HASH_HEX_LENGTH];
                snprintf(approved_id, sizeof(approved_id), "%s",
                         request->record.record_id);
                if (strcmp(request->record.action, "BORROWED") == 0)
                {
                    copy = find_copy(&candidate->copies, request->record.copy_id);
                    if (!copy ||
                        (copy->state != COPY_AVAILABLE &&
                         !(copy->state == COPY_RESERVED &&
                           strcmp(copy->current_holder_id, request->record.member_id) == 0)))
                    {
                        free(candidate);
                        printf("ERROR: cannot approve; requested copy is no longer available to this member.\n");
                        continue;
                    }
                    copy->state = COPY_BORROWED;
                    snprintf(copy->current_holder_id, sizeof(copy->current_holder_id), "%s",
                             request->record.member_id);
                    copy->due_date = request->record.due_date;
                    copy->renewal_count = 0;
                }
                else if (strcmp(request->record.action, "CONDITION") == 0)
                {
                    copy = find_copy(&candidate->copies, request->record.copy_id);
                    if (!copy || copy->state == COPY_STATE_LOST ||
                        request->record.fine_amount < COPY_NEW ||
                        request->record.fine_amount > COPY_WORN)
                    {
                        free(candidate);
                        printf("ERROR: cannot approve; copy condition request is no longer valid.\n");
                        continue;
                    }
                    copy->condition = (CopyCondition)request->record.fine_amount;
                }
                request->status = REQUEST_PENDING;
                if (!commit_library_state_transaction(
                        "library_state.dat", candidate, &copies,
                        &reservations, &pending))
                    fprintf(stderr, "ERROR: approved request but failed to persist review decision.\n");
                else
                    printf("Approved request %s; it may now be mined.\n", approved_id);
            }
            else
            {
                size_t index = (size_t)(request - candidate->pending.items);
                char rejected_id[HASH_HEX_LENGTH];
                snprintf(rejected_id, sizeof(rejected_id), "%s", request->record.record_id);
                for (size_t i = index + 1; i < candidate->pending.count; i++)
                    candidate->pending.items[i - 1] = candidate->pending.items[i];
                candidate->pending.count--;
                if (!commit_library_state_transaction(
                        "library_state.dat", candidate, &copies,
                        &reservations, &pending))
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
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage fine settlement.\n");
                else
                {
                    check_overdue(&chain, &candidate->pending, &candidate->copies,
                                  &books, &members, key, 1);
                    if (queue_fine_settlement(&chain, &candidate->pending,
                                              &candidate->copies, &books, member,
                                          second, (int)amount, key))
                    {
                        if (!commit_library_state_transaction(
                                "library_state.dat", candidate, &copies,
                                &reservations, &pending))
                            fprintf(stderr, "ERROR: could not persist fine settlement; no state was changed.\n");
                        else
                            print_pending(&pending);
                    }
                    else
                        free(candidate);
                }
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
            printf("Mining difficulty: %d leading zero hexadecimal character(s); block reward=%d coins; renewal period=%d day(s)\n",
                   difficulty, MINING_REWARD, renewal_period_days);
            continue;
        }
        if (strcmp(command, "set_renewal_days") == 0 && fields == 2)
        {
            char *end = NULL;
            long parsed = strtol(first, &end, 10);
            if (!end || *end || parsed < 1 || parsed > 3650)
                printf("ERROR: renewal period must be an integer from 1 to 3650 days.\n");
            else if (!save_chain_metadata("chain_metadata.dat", difficulty,
                                          (int)parsed))
                fprintf(stderr, "ERROR: renewal period was not changed because metadata could not be persisted.\n");
            else
            {
                renewal_period_days = (int)parsed;
                printf("Renewal period set to %d day(s).\n", renewal_period_days);
            }
            continue;
        }
        if (strcmp(command, "set_difficulty") == 0 && fields == 2)
        {
            char *end = NULL;
            long parsed = strtol(first, &end, 10);
            if (!end || *end || parsed < 1 || parsed > 4)
                printf("ERROR: difficulty must be an integer from 1 to 4.\n");
            else if (!save_chain_metadata("chain_metadata.dat", (int)parsed,
                                          renewal_period_days))
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
            if (!amount_end || *amount_end || !nonce_end || *nonce_end ||
                fourth[0] == '-' || amount <= 0 || amount > INT_MAX)
                printf("ERROR: invalid transfer amount or nonce.\n");
            else
            {
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                {
                    fprintf(stderr, "ERROR: could not stage transfer request.\n");
                    continue;
                }
                if (!queue_token_transfer(&chain, &candidate->pending, &ledger, &members,
                                           first, second, (int)amount, nonce))
                {
                    free(candidate);
                    printf("ERROR: transfer rejected (unknown account, insufficient available balance, invalid nonce, or invalid amount).\n");
                }
                else if (!commit_library_state_transaction(
                             "library_state.dat", candidate, &copies,
                             &reservations, &pending))
                {
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
            {
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage borrow request.\n");
                else
                {
                    queue_borrow(&chain, &candidate->pending, &candidate->copies,
                                 book, member, fields == 4 ? third : NULL, key);
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist borrow request; no state was changed.\n");
                    else
                        print_pending(&pending);
                }
            }
            continue;
        }
        if (strcmp(command, "return") == 0 && (fields == 3 || fields == 4))
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else
            {
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage return request.\n");
                else
                {
                    queue_return(&chain, &candidate->pending, &candidate->copies,
                                 &candidate->reservations, book, member,
                                 fields == 4 ? third : NULL, key);
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist return request; no state was changed.\n");
                    else
                        print_pending(&pending);
                }
            }
            continue;
        }
        if (strcmp(command, "reserve") == 0 && fields == 3)
        {
            Book *book = find_book(&books, first);
            Member *member = find_member(&members, second);
            if (!book || !member)
                printf("ERROR: Book or Member not found.\n");
            else
            {
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage reservation.\n");
                else
                {
                    queue_reservation(&chain, &candidate->pending,
                                      &candidate->reservations,
                                      &candidate->copies, book, member, key);
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist reservation; no state was changed.\n");
                    else
                        print_reservations(&reservations);
                }
            }
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
            {
                char copy_id[sizeof(copy->copy_id)];
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                snprintf(copy_id, sizeof(copy_id), "%s", copy->copy_id);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage renewal.\n");
                else
                {
                    queue_renewal(&chain, &candidate->pending,
                                  &candidate->copies, &candidate->reservations,
                                  book, member, copy_id, key);
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist renewal; no state was changed.\n");
                }
            }
            continue;
        }
        if ((strcmp(command, "overdue") == 0 || strcmp(command, "check_overdue") == 0) &&
            (fields == 1 || fields == 2))
        {
            LibraryState *candidate = begin_library_state_transaction(
                &copies, &reservations, &pending);
            if (!candidate)
            {
                fprintf(stderr, "ERROR: could not stage overdue scan.\n");
                continue;
            }
            if (fields == 1)
                check_overdue(&chain, &candidate->pending, &candidate->copies,
                              &books, &members, key, 1);
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
                check_overdue(&chain, &candidate->pending, &candidate->copies,
                              &books, &members, key, 1);
            }
            if (!commit_library_state_transaction(
                    "library_state.dat", candidate, &copies,
                    &reservations, &pending))
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
            else
            {
                char copy_id[sizeof(copy->copy_id)];
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                snprintf(copy_id, sizeof(copy_id), "%s", copy->copy_id);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage lost-copy request.\n");
                else if (queue_mark_lost(&chain, &candidate->pending,
                                         &candidate->copies, book, librarian,
                                         copy_id, third, key))
                {
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist lost-copy request; no state was changed.\n");
                    else
                        printf("Copy marked LOST; reason=%s. Record awaits mining.\n", third);
                }
                else
                    free(candidate);
            }
            continue;
        }
        if (strcmp(command, "set_condition") == 0 && fields == 5)
        {
            BookCopy *copy = find_copy(&copies, first);
            Member *actor = find_member(&members, second);
            CopyCondition condition;
            if (!copy || !actor || !parse_copy_condition(third, &condition))
                printf("ERROR: provide a valid copy, registered librarian member ID, and NEW/GOOD/WORN condition.\n");
            else
            {
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage condition change.\n");
                else if (queue_condition_change(
                             &chain, &candidate->pending, &candidate->copies,
                             &books, actor, first, condition, fourth, key))
                {
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: condition change was rolled back because state could not be persisted.\n");
                    else
                        print_pending(&pending);
                }
                else
                    free(candidate);
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
                LibraryState *candidate = begin_library_state_transaction(
                    &copies, &reservations, &pending);
                if (!candidate)
                    fprintf(stderr, "ERROR: could not stage new copy.\n");
                else
                {
                    BookCopy *copy = &candidate->copies.items[
                        candidate->copies.count++];
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
                        candidate->copies.count--;
                        free(candidate);
                        printf("ERROR: condition must be NEW, GOOD, or WORN.\n");
                        continue;
                    }
                    if (!commit_library_state_transaction(
                            "library_state.dat", candidate, &copies,
                            &reservations, &pending))
                        fprintf(stderr, "ERROR: could not persist added copy; no state was changed.\n");
                    else
                        printf("Added copy %s.\n", first);
                }
            }
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
