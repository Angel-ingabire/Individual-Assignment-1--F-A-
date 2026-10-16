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

