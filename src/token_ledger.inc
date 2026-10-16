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
static int apply_record_reward(TokenLedger *ledger, const LendingRecord *record)
{
    Account *account = NULL;
    for (size_t i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, record->member_id) == 0)
        {
            account = &ledger->accounts[i];
            break;
        }
    if (!account || record->token_reward <= REWARD_FEE)
        return account != NULL;
    if (ledger->model == MODEL_ACCOUNT)
    {
        if (account->balance > INT_MAX - (record->token_reward - REWARD_FEE))
            return 0;
        account->balance += record->token_reward - REWARD_FEE;
        return add_history(account, "SYSTEM", account->member_id, record->token_reward, REWARD_FEE, 0);
    }
    else
    {
        if (!add_utxo(ledger, record->record_id, 0, account->member_id,
                      record->token_reward - REWARD_FEE))
            return 0;
        return add_history(account, "SYSTEM", account->member_id, record->token_reward, REWARD_FEE, 0);
    }
}

static int apply_mining_reward(TokenLedger *ledger, const char *member_id,
                               int64_t reward_units, const char *transaction_id,
                               unsigned int output_index)
{
    Account *account = find_account(ledger, member_id);
    int64_t total_units;
    int whole_coins;
    if (!account || reward_units < 0 || !transaction_id ||
        strlen(transaction_id) != HASH_HEX_LENGTH - 1)
        return 0;
    total_units = (int64_t)(account->reward_remainder * MINING_REWARD_SCALE + 0.5) +
                  reward_units;
    if (total_units < 0 || total_units / MINING_REWARD_SCALE > INT_MAX)
        return 0;
    whole_coins = (int)(total_units / MINING_REWARD_SCALE);
    if (ledger->model == MODEL_ACCOUNT &&
        whole_coins > INT_MAX - account->balance)
        return 0;
    if (ledger->model == MODEL_UTXO && whole_coins > 0 &&
        ledger->utxo_count >= MAX_UTXOS)
        return 0;
    if (reward_units > 0 &&
        !add_history(account, "MINING", member_id, 0, 0, 0))
        return 0;
    if (reward_units > 0)
        account->history_tail->exact_amount = (double)reward_units / MINING_REWARD_SCALE;
    if (ledger->model == MODEL_ACCOUNT)
        account->balance += whole_coins;
    else if (whole_coins > 0 &&
             !add_utxo(ledger, transaction_id, output_index, member_id, whole_coins))
    {
        fprintf(stderr, "ERROR: mining reward output could not be added after capacity validation.\n");
        return 0;
    }
    account->reward_remainder = (double)(total_units % MINING_REWARD_SCALE) /
                                MINING_REWARD_SCALE;
    return 1;
}

static int apply_cloud_cost(TokenLedger *ledger, const Block *block,
                            const MiningPayout *payout, size_t payout_index)
{
    Account *account = find_account(ledger, payout->member_id);
    if (!account || block->cloud_cost <= 0 ||
        payout->cost_input_count > MAX_TRANSFER_INPUTS)
        return 0;
    if (ledger->model == MODEL_ACCOUNT)
    {
        if (ledger_balance(ledger, payout->member_id) < block->cloud_cost)
            return 0;
        account->balance -= block->cloud_cost;
    }
    else
    {
        long long total = 0;
        unsigned int selected[MAX_TRANSFER_INPUTS];
        for (size_t i = 0; i < payout->cost_input_count; i++)
        {
            size_t found = ledger->utxo_count;
            for (size_t j = 0; j < ledger->utxo_count; j++)
                if (!ledger->utxos[j].spent &&
                    ledger->utxos[j].output_index == payout->cost_inputs[i].output_index &&
                    strcmp(ledger->utxos[j].transaction_id,
                           payout->cost_inputs[i].transaction_id) == 0)
                {
                    found = j;
                    break;
                }
            if (found == ledger->utxo_count ||
                strcmp(ledger->utxos[found].owner, payout->member_id) != 0)
                return 0;
            for (size_t prior = 0; prior < i; prior++)
                if (selected[prior] == found)
                    return 0;
            selected[i] = (unsigned int)found;
            total += ledger->utxos[found].amount;
        }
        if (total < block->cloud_cost ||
            payout->cost_change != total - block->cloud_cost ||
            (payout->cost_change > 0 && ledger->utxo_count >= MAX_UTXOS))
            return 0;
        for (size_t i = 0; i < payout->cost_input_count; i++)
            ledger->utxos[selected[i]].spent = 1;
        if (payout->cost_change > 0 &&
            !add_utxo(ledger, block->hash,
                      (unsigned int)(MAX_BLOCK_PAYOUTS + payout_index),
                      payout->member_id, payout->cost_change))
            return 0;
    }
    return add_history(account, payout->member_id, "CLOUD",
                       block->cloud_cost, 0, 0);
}

static int apply_block_payouts(TokenLedger *ledger, const Block *block)
{
    for (size_t i = 0; i < block->payout_count; i++)
    {
        const MiningPayout *payout = &block->payouts[i];
        if (block->cloud_cost > 0 &&
            !apply_cloud_cost(ledger, block, payout, i))
            return 0;
        if (!apply_mining_reward(ledger, payout->member_id, payout->reward_units,
                                 block->hash, (unsigned int)i))
            return 0;
    }
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
    if (chain->items[0].legacy_source_tip[0] != '\0' &&
        chain->items[0].legacy_block_count > 0)
        return 1;
    for (size_t i = 1; i < chain->count; i++)
    {
        for (size_t j = 0; j < chain->items[i].record_count; j++)
        {
            const LendingRecord *record = &chain->items[i].records[j];
            if (strcmp(record->action, "RETURNED") == 0 &&
                record->token_reward > 0 &&
                !apply_record_reward(ledger, record))
                return 0;
            else if (strcmp(record->action, "TRANSFER") == 0 &&
                     strcmp(record->reason_code,
                            model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO") == 0 &&
                     !transfer_tokens(ledger, record->member_id, record->book_title,
                                      record->token_reward,
                                      (unsigned long long)record->due_date,
                                      record->record_id, &record->utxo_proof))
            {
                fprintf(stderr, "ERROR: confirmed token transaction cannot be replayed; selected model state conflicts with the chain.\n");
                return 0;
            }
        }
        if (!apply_block_payouts(ledger, &chain->items[i]))
        {
            fprintf(stderr, "ERROR: committed mining payout or cloud expense cannot be replayed.\n");
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

static int prepare_utxo_proof(const TokenLedger *ledger, const char *sender_id,
                              const char *recipient_id, int amount,
                              UTXOTransactionProof *proof)
{
    long long total = 0;
    const int fee = 1;
    memset(proof, 0, sizeof(*proof));
    for (size_t i = 0; i < ledger->utxo_count && total < (long long)amount + fee; i++)
        if (!ledger->utxos[i].spent &&
            strcmp(ledger->utxos[i].owner, sender_id) == 0)
        {
            if (proof->input_count >= MAX_TRANSFER_INPUTS)
                return 0;
            UTXOInput *input = &proof->inputs[proof->input_count++];
            snprintf(input->transaction_id, sizeof(input->transaction_id), "%s",
                     ledger->utxos[i].transaction_id);
            input->output_index = ledger->utxos[i].output_index;
            total += ledger->utxos[i].amount;
        }
    if (total < (long long)amount + fee || total > INT_MAX)
        return 0;
    proof->version = 1;
    proof->outputs[0].amount = amount;
    snprintf(proof->outputs[0].owner, sizeof(proof->outputs[0].owner), "%s",
             recipient_id);
    proof->output_count = 1;
    if (total > (long long)amount + fee)
    {
        proof->outputs[1].amount = (int)(total - amount - fee);
        snprintf(proof->outputs[1].owner, sizeof(proof->outputs[1].owner), "%s",
                 sender_id);
        proof->output_count = 2;
    }
    return 1;
}

static int prepare_cloud_cost_inputs(const TokenLedger *ledger,
                                    const char *member_id, int cost,
                                    MiningPayout *payout)
{
    long long total = 0;
    payout->cost_input_count = 0;
    payout->cost_change = 0;
    if (ledger->model == MODEL_ACCOUNT)
        return ledger_balance(ledger, member_id) >= cost;
    for (size_t i = 0; i < ledger->utxo_count && total < cost; i++)
        if (!ledger->utxos[i].spent &&
            strcmp(ledger->utxos[i].owner, member_id) == 0)
        {
            if (payout->cost_input_count >= MAX_TRANSFER_INPUTS)
                return 0;
            UTXOInput *input = &payout->cost_inputs[payout->cost_input_count++];
            snprintf(input->transaction_id, sizeof(input->transaction_id), "%s",
                     ledger->utxos[i].transaction_id);
            input->output_index = ledger->utxos[i].output_index;
            total += ledger->utxos[i].amount;
        }
    if (total < cost || total > INT_MAX)
        return 0;
    payout->cost_change = (int)(total - cost);
    return 1;
}

static int transfer_tokens(TokenLedger *ledger, const char *sender_id,
                           const char *recipient_id, int amount,
                           unsigned long long nonce, const char *confirmed_txid,
                           const UTXOTransactionProof *proof)
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
        if (confirmed_txid && proof && proof->version == 1)
        {
            if (proof->input_count == 0 ||
                proof->input_count > MAX_TRANSFER_INPUTS ||
                proof->output_count == 0 ||
                proof->output_count > MAX_TRANSFER_OUTPUTS ||
                strcmp(proof->outputs[0].owner, recipient_id) != 0 ||
                proof->outputs[0].amount != amount)
                return 0;
            selected_count = proof->input_count;
            for (size_t i = 0; i < proof->input_count; i++)
            {
                size_t found = ledger->utxo_count;
                for (size_t j = 0; j < ledger->utxo_count; j++)
                    if (!ledger->utxos[j].spent &&
                        ledger->utxos[j].output_index == proof->inputs[i].output_index &&
                        strcmp(ledger->utxos[j].transaction_id,
                               proof->inputs[i].transaction_id) == 0)
                    {
                        found = j;
                        break;
                    }
                if (found == ledger->utxo_count ||
                    strcmp(ledger->utxos[found].owner, sender_id) != 0)
                    return 0;
                for (size_t j = 0; j < i; j++)
                    if (selected[j] == found)
                        return 0;
                selected[i] = (unsigned int)found;
                total += ledger->utxos[found].amount;
            }
            if (total < (long long)amount + fee ||
                proof->output_count !=
                    (total == (long long)amount + fee ? 1u : 2u) ||
                (proof->output_count == 1 && total != (long long)amount + fee) ||
                (proof->output_count == 2 &&
                 (strcmp(proof->outputs[1].owner, sender_id) != 0 ||
                  proof->outputs[1].amount != total - amount - fee)))
                return 0;
        }
        else
        {
            if (confirmed_txid && (!proof || proof->version != 0))
                return 0;
            for (size_t i = 0; i < ledger->utxo_count &&
                               total < (long long)amount + fee; i++)
                if (!ledger->utxos[i].spent &&
                    strcmp(ledger->utxos[i].owner, sender_id) == 0)
                {
                    total += ledger->utxos[i].amount;
                    selected[selected_count++] = (unsigned int)i;
                }
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
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path) >=
        (int)sizeof(temporary_path))
        return 0;
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
    if (!replace_file_atomically(temporary_path, path))
    {
        remove(temporary_path);
        return 0;
    }
    return 1;
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
        (strcmp(saved_tip, chain->items[chain->count - 1].hash) != 0 &&
         (chain->items[0].legacy_source_tip[0] == '\0' ||
          strcmp(saved_tip, chain->items[0].legacy_source_tip) != 0)) ||
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
                (strcmp(saved.recipient, "CLOUD") != 0 &&
                 !find_member((MemberRegistry *)members, saved.recipient)))
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
    if (!save_token_ledger(ledger, chain))
    {
        fprintf(stderr, "ERROR: could not rebind migrated token snapshot to the upgraded chain tip.\n");
        return -1;
    }
    return 1;
}
