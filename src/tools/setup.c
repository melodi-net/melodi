/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup.h"

#include "melodi.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MELODI_SETUP_LINE_MAX 4096

static char *melodi_setup_token(char **position)
{
    char *start;

    while (**position == ' ' || **position == '\t')
        (*position)++;
    if (!**position)
        return NULL;
    start = *position;
    while (**position && **position != ' ' && **position != '\t')
        (*position)++;
    if (**position)
        *(*position)++ = '\0';
    return start;
}

static int melodi_setup_service(const char *text, uint16_t *service)
{
    unsigned long value;
    char *end;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !*text || *end || !value || value > UINT16_MAX)
        return -EINVAL;
    *service = value;
    return 0;
}

static int melodi_setup_unique(const struct melodi_setup_config *config,
                               const struct melodi_setup_operation *operation)
{
    size_t peers = 0;
    size_t services = 0;
    size_t index;

    for (index = 0; index < config->operation_count; index++) {
        const struct melodi_setup_operation *current =
            &config->operations[index];

        if (current->type == operation->type &&
            (operation->type == MELODI_SETUP_POLICY ||
             operation->type == MELODI_SETUP_BROADCAST))
            return -EEXIST;
        if (current->type == MELODI_SETUP_SERVICE &&
            operation->type == MELODI_SETUP_SERVICE &&
            current->service == operation->service)
            return -EEXIST;
        if (current->type >= MELODI_SETUP_TRUST &&
            operation->type >= MELODI_SETUP_TRUST &&
            !memcmp(&current->node_id, &operation->node_id,
                    sizeof(operation->node_id)))
            return -EEXIST;
        services += current->type == MELODI_SETUP_SERVICE;
        peers += current->type >= MELODI_SETUP_TRUST;
    }
    if ((operation->type == MELODI_SETUP_SERVICE && services >= 64) ||
        (operation->type >= MELODI_SETUP_TRUST && peers >= 64))
        return -E2BIG;
    return 0;
}

static int melodi_setup_directive(char *line,
                                  struct melodi_setup_config *config)
{
    struct melodi_setup_operation operation = { 0 };
    char *tokens[4] = { 0 };
    char *position = line;
    size_t count = 0;
    size_t length;
    int error;

    while (count < 4 && (tokens[count] = melodi_setup_token(&position)))
        count++;
    if (!count)
        return 0;
    if (count == 4 || melodi_setup_token(&position))
        return -EINVAL;
    if (!strcmp(tokens[0], "identity")) {
        if (count != 3 || strcmp(tokens[1], "tpm") ||
            config->identity_path[0] || tokens[2][0] != '/')
            return -EINVAL;
        length = strlen(tokens[2]);
        if (length >= sizeof(config->identity_path))
            return -ENAMETOOLONG;
        memcpy(config->identity_path, tokens[2], length + 1);
        return 0;
    }
    if (config->operation_count >= MELODI_SETUP_MAX_OPERATIONS)
        return -E2BIG;
    if (!strcmp(tokens[0], "policy")) {
        if (count != 2)
            return -EINVAL;
        operation.type = MELODI_SETUP_POLICY;
        if (!strcmp(tokens[1], "authenticated"))
            operation.value = MELODI_POLICY_ALLOW_AUTHENTICATED;
        else if (!strcmp(tokens[1], "trusted"))
            operation.value = MELODI_POLICY_REQUIRE_TRUST;
        else
            return -EINVAL;
    } else if (!strcmp(tokens[0], "service")) {
        if (count != 3)
            return -EINVAL;
        operation.type = MELODI_SETUP_SERVICE;
        error = melodi_setup_service(tokens[1], &operation.service);
        if (error)
            return error;
        if (!strcmp(tokens[2], "allow"))
            operation.value = MELODI_POLICY_SERVICE_ALLOW;
        else if (!strcmp(tokens[2], "deny"))
            operation.value = MELODI_POLICY_SERVICE_DENY;
        else
            return -EINVAL;
    } else if (!strcmp(tokens[0], "broadcast")) {
        if (count != 2)
            return -EINVAL;
        operation.type = MELODI_SETUP_BROADCAST;
        if (!strcmp(tokens[1], "allow"))
            operation.value = 1;
        else if (strcmp(tokens[1], "deny"))
            return -EINVAL;
    } else if (!strcmp(tokens[0], "trust") ||
               !strcmp(tokens[0], "block")) {
        if (count != 2 ||
            melodi_nodeid_parse(tokens[1], strlen(tokens[1]),
                                &operation.node_id))
            return -EINVAL;
        operation.type = !strcmp(tokens[0], "trust") ?
                         MELODI_SETUP_TRUST : MELODI_SETUP_BLOCK;
    } else {
        return -EINVAL;
    }
    error = melodi_setup_unique(config, &operation);
    if (error)
        return error;
    config->operations[config->operation_count++] = operation;
    return 0;
}

int melodi_setup_parse(char *data, size_t length,
                       struct melodi_setup_config *config,
                       unsigned int *error_line)
{
    char *line;
    char *end;
    unsigned int number = 1;
    int error = 0;

    if (!data || !config || !error_line || memchr(data, '\0', length))
        return -EINVAL;
    line = data;
    end = data + length;
    memset(config, 0, sizeof(*config));
    while (line < end) {
        char *next = memchr(line, '\n', end - line);
        char *comment;
        char *tail;

        if (!next)
            next = end;
        if ((size_t)(next - line) > MELODI_SETUP_LINE_MAX) {
            error = -E2BIG;
            break;
        }
        if (next < end)
            *next = '\0';
        else
            *end = '\0';
        if (next > line && next[-1] == '\r')
            next[-1] = '\0';
        comment = strchr(line, '#');
        if (comment)
            *comment = '\0';
        tail = line + strlen(line);
        while (tail > line && (tail[-1] == ' ' || tail[-1] == '\t'))
            *--tail = '\0';
        error = melodi_setup_directive(line, config);
        if (error)
            break;
        line = next + (next < end);
        number++;
    }
    if (!error && !config->identity_path[0])
        error = -EINVAL;
    *error_line = number;
    return error;
}
