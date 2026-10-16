typedef struct
{
    LegacyV4LendingRecord record;
    int priority;
    time_t reservation_date;
    RequestStatus status;
} LegacyV4PendingRequest;

static void copy_legacy_v4_record(LendingRecord *target,
                                  const LegacyV4LendingRecord *source)
{
    memset(target, 0, sizeof(*target));
    memcpy(target->record_id, source->record_id, sizeof(source->record_id));
    memcpy(target->book_id, source->book_id, sizeof(source->book_id));
    memcpy(target->copy_id, source->copy_id, sizeof(source->copy_id));
    memcpy(target->book_title, source->book_title, sizeof(source->book_title));
    memcpy(target->member_id, source->member_id, sizeof(source->member_id));
    memcpy(target->member_name, source->member_name, sizeof(source->member_name));
    memcpy(target->action, source->action, sizeof(source->action));
    memcpy(target->reason_code, source->reason_code, sizeof(source->reason_code));
    target->due_date = source->due_date;
    target->fine_amount = source->fine_amount;
    target->nonce = source->nonce;
    target->token_reward = source->token_reward;
    memcpy(target->signature, source->signature, sizeof(source->signature));
    target->signature_len = source->signature_len;
}

static int save_library_state(const char *path, const CopyRegistry *copies,
                              const ReservationQueue *reservations, const PendingPool *pending)
{
    char temporary_path[512];
    FILE *file;
    int success;
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", path) >=
        (int)sizeof(temporary_path))
        return 0;
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
    if (!replace_file_atomically(temporary_path, path))
    {
        remove(temporary_path);
        return 0;
    }
    return 1;
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
    int legacy_format = 0;
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
    if (fread(magic, 1, 9, file) != 9 ||
        (strcmp(magic, STATE_MAGIC) != 0 &&
         strcmp(magic, "LIBSTATE1") != 0) ||
        fread(&count, sizeof(count), 1, file) != 1 || count == 0 || count > MAX_COPIES)
    {
        fclose(file);
        fprintf(stderr, "ERROR: library_state.dat is corrupt or unsupported.\n");
        return 0;
    }
    legacy_format = strcmp(magic, "LIBSTATE1") == 0;
    CopyRegistry saved_copies;
    memset(&saved_copies, 0, sizeof(saved_copies));
    saved_copies.count = count;
    if (fread(saved_copies.items, sizeof(saved_copies.items[0]), saved_copies.count, file) != saved_copies.count ||
        fread(&reservations->count, sizeof(reservations->count), 1, file) != 1 ||
        reservations->count > MAX_RESERVATIONS ||
        fread(reservations->items, sizeof(reservations->items[0]), reservations->count, file) != reservations->count ||
        fread(&pending->count, sizeof(pending->count), 1, file) != 1 ||
        pending->count > MAX_PENDING_REQUESTS)
    {
        fclose(file);
        fprintf(stderr, "ERROR: library_state.dat is truncated or has invalid counts.\n");
        return 0;
    }
    if (legacy_format)
    {
        LegacyV4PendingRequest *legacy_pending =
            (LegacyV4PendingRequest *)calloc(pending->count, sizeof(*legacy_pending));
        if (pending->count > 0 &&
            (!legacy_pending ||
             fread(legacy_pending, sizeof(*legacy_pending), pending->count, file) != pending->count))
        {
            free(legacy_pending);
            fclose(file);
            fprintf(stderr, "ERROR: legacy library_state.dat is truncated or has invalid counts.\n");
            return 0;
        }
        for (size_t i = 0; i < pending->count; i++)
        {
            copy_legacy_v4_record(&pending->items[i].record,
                                  &legacy_pending[i].record);
            pending->items[i].priority = legacy_pending[i].priority;
            pending->items[i].reservation_date = legacy_pending[i].reservation_date;
            pending->items[i].status = legacy_pending[i].status;
        }
        free(legacy_pending);
    }
    else if (fread(pending->items, sizeof(pending->items[0]), pending->count, file) != pending->count)
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
    if (legacy_format && !save_library_state(path, copies, reservations, pending))
    {
        fprintf(stderr, "ERROR: could not persist migrated library state.\n");
        return 0;
    }
    return 1;
}
