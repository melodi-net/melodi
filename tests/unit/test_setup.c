/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const struct melodi_node_id valid_node = {
    .bytes = {
        0x01, 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    },
};

static void test_valid(void)
{
    struct melodi_setup_config config;
    char node[MELODI_NODE_ID_STRING_SIZE];
    char data[2048];
    unsigned int line;
    int length;

    assert(melodi_nodeid_format(&valid_node, node) == 0);
    length = snprintf(data, sizeof(data),
                      "# mel0\nidentity tpm /var/lib/melodi/mel0.tpm\r\n"
                      "policy trusted\nservice 42 deny\n"
                      "broadcast deny\ntrust %s\n",
                      node);
    assert(length > 0 && (size_t)length < sizeof(data));
    assert(melodi_setup_parse(data, length, &config, &line) == 0);
    assert(!strcmp(config.identity_path, "/var/lib/melodi/mel0.tpm"));
    assert(config.operation_count == 4);
    assert(config.operations[0].type == MELODI_SETUP_POLICY);
    assert(config.operations[0].value == MELODI_POLICY_REQUIRE_TRUST);
    assert(config.operations[1].type == MELODI_SETUP_SERVICE);
    assert(config.operations[1].service == 42);
    assert(config.operations[1].value == MELODI_POLICY_SERVICE_DENY);
    assert(config.operations[2].type == MELODI_SETUP_BROADCAST);
    assert(config.operations[2].value == 0);
    assert(config.operations[3].type == MELODI_SETUP_TRUST);
    assert(!memcmp(&config.operations[3].node_id, &valid_node,
                   sizeof(valid_node)));
}

static void test_invalid(void)
{
    struct melodi_setup_config config;
    unsigned int line;
    char relative[] = "identity tpm relative\n";
    char duplicate[] =
        "identity tpm /var/lib/melodi/mel0.tpm\n"
        "policy trusted\npolicy authenticated\n";
    char missing[] = "broadcast allow\n";
    char trailing[] =
        "identity tpm /var/lib/melodi/mel0.tpm extra\n";
    char embedded[] =
        "identity tpm /var/lib/melodi/mel0.tpm\nservice\0 4 deny\n";

    assert(melodi_setup_parse(relative, strlen(relative), &config,
                              &line) == -EINVAL);
    assert(line == 1);
    assert(melodi_setup_parse(duplicate, strlen(duplicate), &config,
                              &line) == -EEXIST);
    assert(line == 3);
    assert(melodi_setup_parse(missing, strlen(missing), &config,
                              &line) == -EINVAL);
    assert(melodi_setup_parse(trailing, strlen(trailing), &config,
                              &line) == -EINVAL);
    assert(melodi_setup_parse(embedded, sizeof(embedded) - 1, &config,
                              &line) == -EINVAL);
}

int main(void)
{
    test_valid();
    test_invalid();
    return 0;
}
