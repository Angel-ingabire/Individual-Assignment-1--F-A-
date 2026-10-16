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
                              const MiningPayout payouts[MINERS_IN_POOL],
                              size_t miner_count)
{
    unsigned long long total = 0;
    for (size_t i = 0; i < miner_count; i++)
        total += attempts[i];
    printf("Miner ID       Attempts   Share      Reward\n");
    for (size_t i = 0; i < miner_count; i++)
    {
        double share = total ? (double)attempts[i] / (double)total : 0.0;
        printf("%-14s %-10llu %6.2f%%    %.4f\n", member_ids[i], attempts[i],
               share * 100.0,
               (double)payouts[i].reward_units / MINING_REWARD_SCALE);
    }
    printf("Pool fee: %.2f coins (2%%)\n", MINING_REWARD * 0.02);
}

static int pending_request_precedes(const PendingRequest *left, const PendingRequest *right)
{
    if (left->priority != right->priority)
        return left->priority < right->priority;
    return left->reservation_date < right->reservation_date;
}

static void restore_ledger_snapshot(TokenLedger *ledger,
                                    const TokenLedger *snapshot)
{
    size_t account_count = ledger->account_count;
    if (account_count > snapshot->account_count)
        account_count = snapshot->account_count;
    for (size_t i = 0; i < account_count; i++)
    {
        TransactionRecord *entry = snapshot->accounts[i].history_tail
                                       ? snapshot->accounts[i].history_tail->next
                                       : ledger->accounts[i].history_head;
        while (entry)
        {
            TransactionRecord *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    *ledger = *snapshot;
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
    size_t eligible_count = 0;
    size_t order[MAX_PENDING_REQUESTS];
    int selected[MAX_PENDING_REQUESTS] = {0};
    unsigned long long next_nonces[MAX_MEMBERS] = {0};
    TokenLedger *working_ledger = NULL;
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
    if (strcmp(mode, "cloud") == 0 &&
        (cloud_rounds < 1 || cloud_rounds > 5 ||
         eligible_count > MAX_RECORDS_PER_BLOCK))
    {
        printf("ERROR: cloud mining requires 1-5 rounds and a single-block request batch.\n");
        return 0;
    }
    working_ledger = (TokenLedger *)calloc(1, sizeof(*working_ledger));
    if (!working_ledger)
    {
        fprintf(stderr, "ERROR: could not allocate mining simulation ledger.\n");
        return 0;
    }
    *working_ledger = *ledger;
    for (size_t i = 0; i < working_ledger->account_count; i++)
    {
        working_ledger->accounts[i].history_head = NULL;
        working_ledger->accounts[i].history_tail = NULL;
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
                if (strcmp(record->action, "TRANSFER") == 0 &&
                    strcmp(record->reason_code, "UTXO") == 0 &&
                    (!prepare_utxo_proof(working_ledger, record->member_id,
                                         record->book_title, record->token_reward,
                                         &record->utxo_proof)))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: UTXO transfer exceeds the bounded input set or lacks funds.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
                if (!make_record_id(record) || !sign_record(record, key))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: could not re-sign request with its confirmation nonce.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
                if (strcmp(record->action, "RETURNED") == 0 &&
                    record->token_reward > 0 &&
                    !apply_record_reward(working_ledger, record))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: return reward could not be applied during confirmation simulation.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
                if (strcmp(record->action, "TRANSFER") == 0 &&
                    strcmp(record->reason_code,
                           working_ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
                    !transfer_tokens(working_ledger, record->member_id,
                                     record->book_title, record->token_reward,
                                     (unsigned long long)record->due_date,
                                     record->record_id, &record->utxo_proof))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: token transfer cannot be applied during confirmation simulation.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
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
                free_ledger(working_ledger);
                free(working_ledger);
                return 0;
            }
            snprintf(confirmed->token_model, sizeof(confirmed->token_model), "%s",
                     working_ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO");
            if (strcmp(mode, "pool") == 0)
            {
                unsigned long long total_attempts = 0;
                int64_t remaining_reward =
                    (int64_t)MINING_REWARD * MINING_REWARD_SCALE * 98 / 100;
                for (size_t miner = 0; miner < payout_count; miner++)
                    total_attempts += miner_attempts[miner];
                if (total_attempts == 0)
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: pool produced no measured mining contributions.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
                snprintf(confirmed->mining_mode, sizeof(confirmed->mining_mode), "pool");
                confirmed->payout_count = payout_count;
                for (size_t miner = 0; miner < payout_count; miner++)
                {
                    MiningPayout *payout = &confirmed->payouts[miner];
                    snprintf(payout->member_id, sizeof(payout->member_id), "%s",
                             payout_members[miner]);
                    payout->attempts = miner_attempts[miner];
                    payout->reward_units = miner + 1 == payout_count
                                               ? remaining_reward
                                               : (int64_t)((long double)
                                                   ((int64_t)MINING_REWARD *
                                                    MINING_REWARD_SCALE * 98 / 100) *
                                                   miner_attempts[miner] /
                                                   total_attempts);
                    remaining_reward -= payout->reward_units;
                }
            }
            else
            {
                MiningPayout *payout = &confirmed->payouts[0];
                snprintf(confirmed->mining_mode, sizeof(confirmed->mining_mode), "%s", mode);
                confirmed->payout_count = 1;
                snprintf(payout->member_id, sizeof(payout->member_id), "%s",
                         payout_members[0]);
                payout->attempts = attempts;
                payout->reward_units = (int64_t)MINING_REWARD *
                                       MINING_REWARD_SCALE *
                                       (strcmp(mode, "cloud") == 0 ? cloud_rounds : 1);
                if (strcmp(mode, "cloud") == 0)
                {
                    confirmed->cloud_rounds = (unsigned int)cloud_rounds;
                    confirmed->cloud_cost = cloud_rounds *
                                            (CLOUD_RENTAL_FEE +
                                             CLOUD_MAINTENANCE_FEE);
                    if (!prepare_cloud_cost_inputs(working_ledger,
                                                   payout_members[0],
                                                   confirmed->cloud_cost,
                                                   payout))
                    {
                        chain->count = old_count;
                        fprintf(stderr, "ERROR: cloud fees exceed the selected member's available balance or input limit.\n");
                        free_ledger(working_ledger);
                        free(working_ledger);
                        return 0;
                    }
                }
            }
            if (!finalize_block(confirmed))
            {
                chain->count = old_count;
                fprintf(stderr, "ERROR: could not finalize committed mining payout data.\n");
                free_ledger(working_ledger);
                free(working_ledger);
                return 0;
            }
            confirmed->nonce = 0;
            if (!hash_block(confirmed, confirmed->hash))
            {
                chain->count = old_count;
                fprintf(stderr, "ERROR: could not hash committed mining payout data.\n");
                free_ledger(working_ledger);
                free(working_ledger);
                return 0;
            }
            while (!has_pow_prefix(confirmed->hash, confirmed->difficulty))
            {
                confirmed->nonce++;
                if (!hash_block(confirmed, confirmed->hash))
                {
                    chain->count = old_count;
                    fprintf(stderr, "ERROR: could not seal committed mining payout data.\n");
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
            }
            if (!apply_block_payouts(working_ledger, confirmed))
            {
                chain->count = old_count;
                fprintf(stderr, "ERROR: committed mining payout or cloud charge cannot be applied.\n");
                free_ledger(working_ledger);
                free(working_ledger);
                return 0;
            }
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
            free_ledger(working_ledger);
            free(working_ledger);
            return 0;
        }
        TokenLedger *ledger_snapshot =
            (TokenLedger *)malloc(sizeof(*ledger_snapshot));
        PendingPool *pending_snapshot =
            (PendingPool *)malloc(sizeof(*pending_snapshot));
        if (!ledger_snapshot || !pending_snapshot)
        {
            chain->count = old_count;
            if (!save_chain(ledger_path, chain))
                fprintf(stderr, "ERROR: failed to roll back chain after snapshot allocation failure.\n");
            free(ledger_snapshot);
            free(pending_snapshot);
            free_ledger(working_ledger);
            free(working_ledger);
            fprintf(stderr, "ERROR: could not stage mining commit.\n");
            return 0;
        }
        *ledger_snapshot = *ledger;
        *pending_snapshot = *pending;
        for (size_t i = old_count; i < chain->count; i++)
        {
            for (size_t j = 0; j < chain->items[i].record_count; j++)
            {
                LendingRecord *record = &chain->items[i].records[j];
                if (strcmp(record->action, "RETURNED") == 0 &&
                    record->token_reward > 0)
                {
                    if (!apply_record_reward(ledger, record))
                    {
                        fprintf(stderr, "ERROR: confirmed return reward failed to apply; inspect chain and ledger backups.\n");
                        restore_ledger_snapshot(ledger, ledger_snapshot);
                        chain->count = old_count;
                        if (!save_chain(ledger_path, chain))
                            fprintf(stderr, "ERROR: failed to restore the prior chain after mining rollback.\n");
                        *pending = *pending_snapshot;
                        free(ledger_snapshot);
                        free(pending_snapshot);
                        free_ledger(working_ledger);
                        free(working_ledger);
                        return 0;
                    }
                }
                else if (strcmp(record->action, "TRANSFER") == 0 &&
                         strcmp(record->reason_code,
                                ledger->model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
                         !transfer_tokens(ledger, record->member_id, record->book_title,
                                          record->token_reward,
                                          (unsigned long long)record->due_date,
                                          record->record_id, &record->utxo_proof))
                {
                    fprintf(stderr, "ERROR: confirmed token transfer failed to apply; inspect chain and ledger backups.\n");
                    restore_ledger_snapshot(ledger, ledger_snapshot);
                    chain->count = old_count;
                    if (!save_chain(ledger_path, chain))
                        fprintf(stderr, "ERROR: failed to restore the prior chain after mining rollback.\n");
                    *pending = *pending_snapshot;
                    free(ledger_snapshot);
                    free(pending_snapshot);
                    free_ledger(working_ledger);
                    free(working_ledger);
                    return 0;
                }
            }
            if (strcmp(mode, "pool") == 0)
            {
                unsigned long long miner_attempts[MINERS_IN_POOL] = {0};
                for (size_t miner = 0; miner < payout_count; miner++)
                    miner_attempts[miner] = chain->items[i].payouts[miner].attempts;
                print_pool_shares(miner_attempts, payout_members,
                                  chain->items[i].payouts, payout_count);
            }
            if (!apply_block_payouts(ledger, &chain->items[i]))
            {
                fprintf(stderr, "ERROR: committed mining payout or cloud charge failed to apply; inspect chain and ledger backups.\n");
                restore_ledger_snapshot(ledger, ledger_snapshot);
                chain->count = old_count;
                if (!save_chain(ledger_path, chain))
                    fprintf(stderr, "ERROR: failed to restore the prior chain after mining rollback.\n");
                *pending = *pending_snapshot;
                free(ledger_snapshot);
                free(pending_snapshot);
                free_ledger(working_ledger);
                free(working_ledger);
                return 0;
            }
            if (strcmp(mode, "solo") == 0)
                printf("Solo miner %s reward: %d coins\n", payout_members[0],
                       MINING_REWARD);
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
            restore_ledger_snapshot(ledger, ledger_snapshot);
            chain->count = old_count;
            if (!save_chain(ledger_path, chain))
                fprintf(stderr, "ERROR: failed to restore the prior chain after mining rollback.\n");
            *pending = *pending_snapshot;
            free(ledger_snapshot);
            free(pending_snapshot);
            free_ledger(working_ledger);
            free(working_ledger);
            return 0;
        }
        if (!save_token_ledger(ledger, chain))
        {
            fprintf(stderr, "ERROR: token snapshot could not be persisted; rolling back mining commit.\n");
            restore_ledger_snapshot(ledger, ledger_snapshot);
            chain->count = old_count;
            if (!save_chain(ledger_path, chain))
                fprintf(stderr, "ERROR: failed to restore the prior chain after mining rollback.\n");
            *pending = *pending_snapshot;
            if (!save_library_state(state_path, copies, reservations, pending))
                fprintf(stderr, "ERROR: failed to restore the prior library state after mining rollback.\n");
            free(ledger_snapshot);
            free(pending_snapshot);
            free_ledger(working_ledger);
            free(working_ledger);
            return 0;
        }
        free(ledger_snapshot);
        free(pending_snapshot);
        free_ledger(working_ledger);
        free(working_ledger);
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
            printf("Cloud mining reward and rental charges committed to block data for %s (gross=%d, debited=%d).\n",
                   payout_members[0], gross, fees);
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
