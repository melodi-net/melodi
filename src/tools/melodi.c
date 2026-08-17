/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "netlink.h"
#include "setup.h"
#include "tpm.h"
#include "usb_attach.h"

#include "nodeid.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int melodi_attributes_begin(struct melodi_genl_builder *builder,
                                   uint8_t *buffer, size_t capacity)
{
    return melodi_genl_begin(builder, buffer, capacity, 1, 0, 0, 0,
                             MELODI_CMD_BIND);
}

static const uint8_t *melodi_attributes_data(struct melodi_genl_builder *builder)
{
    return builder->data + NLMSG_HDRLEN + GENL_HDRLEN;
}

static size_t melodi_attributes_length(struct melodi_genl_builder *builder)
{
    return builder->length - NLMSG_HDRLEN - GENL_HDRLEN;
}

static int melodi_interface(const char *name, uint32_t *ifindex)
{
    unsigned int index = if_nametoindex(name);

    if (!index)
        return errno ? -errno : -ENODEV;
    *ifindex = index;
    return 0;
}

static int melodi_request(uint8_t command,
                          struct melodi_genl_builder *attributes,
                          bool reply_expected,
                          struct melodi_genl_message *reply,
                          uint8_t *reply_buffer, size_t reply_capacity)
{
    struct melodi_socket socket_state;
    int error;

    error = melodi_socket_open(&socket_state);
    if (error)
        return error;
    error = melodi_socket_command(&socket_state, command,
                                  melodi_attributes_data(attributes),
                                  melodi_attributes_length(attributes),
                                  reply_expected, reply, reply_buffer,
                                  reply_capacity);
    melodi_socket_close(&socket_state);
    return error;
}

static int melodi_status(const char *interface_name)
{
    static const char *const names[] = {
        "disconnected", "configuring", "ready", "failed",
    };
    static const char *const failures[] = {
        "none", "transport", "stream", "protobuf", "firmware",
        "region", "modem", "hop-limit", "radio-tx", "mqtt",
        "channel", "config-nonce", "node-number", "private-port",
        "payload-budget", "queue-status", "routing-results", "timeout",
        "internal",
    };
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    uint32_t ifindex = 0;
    int32_t link_error;
    uint16_t failure;
    uint8_t state;
    const char *radio_serial = NULL;
    const char *bus_info = NULL;
    int error;

    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    melodi_attributes_begin(&attributes, attributes_buffer,
                            sizeof(attributes_buffer));
    melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    error = melodi_request(MELODI_CMD_LINK_GET, &attributes, true, &reply,
                           reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_LINK_STATE] ||
        !reply.attributes[MELODI_A_LINK_FAILURE] ||
        !reply.attributes[MELODI_A_LINK_ERROR])
        return -EPROTO;
    memcpy(&state, reply.attributes[MELODI_A_LINK_STATE], sizeof(state));
    memcpy(&failure, reply.attributes[MELODI_A_LINK_FAILURE],
           sizeof(failure));
    memcpy(&link_error, reply.attributes[MELODI_A_LINK_ERROR],
           sizeof(link_error));
    if (state > MELODI_LINK_FAILED || failure > MELODI_LINK_FAILURE_MAX ||
        (state == MELODI_LINK_FAILED) !=
            (failure != MELODI_LINK_FAILURE_NONE) ||
        (state == MELODI_LINK_FAILED ? link_error >= 0 : link_error != 0))
        return -EPROTO;
    if (state == MELODI_LINK_FAILED)
        printf("%s: failed: %s: %s\n", interface_name,
               failures[failure], strerror(-link_error));
    else {
        if (reply.attributes[MELODI_A_RADIO_SERIAL]) {
            if (!reply.lengths[MELODI_A_RADIO_SERIAL] ||
                reply.lengths[MELODI_A_RADIO_SERIAL] >
                    MELODI_RADIO_SERIAL_MAX + 1 ||
                ((const char *)reply.attributes[MELODI_A_RADIO_SERIAL])
                    [reply.lengths[MELODI_A_RADIO_SERIAL] - 1] != '\0')
                return -EPROTO;
            radio_serial = reply.attributes[MELODI_A_RADIO_SERIAL];
        }
        if (reply.attributes[MELODI_A_BUS_INFO]) {
            if (!reply.lengths[MELODI_A_BUS_INFO] ||
                reply.lengths[MELODI_A_BUS_INFO] >
                    MELODI_BUS_INFO_MAX + 1 ||
                ((const char *)reply.attributes[MELODI_A_BUS_INFO])
                    [reply.lengths[MELODI_A_BUS_INFO] - 1] != '\0')
                return -EPROTO;
            bus_info = reply.attributes[MELODI_A_BUS_INFO];
        }
        printf("%s: %s", interface_name, names[state]);
        if (radio_serial)
            printf(" radio=%s", radio_serial);
        if (bus_info)
            printf(" bus=%s", bus_info);
        putchar('\n');
    }
    return 0;
}

static int melodi_set_radio(const char *interface_name,
                            const char *radio_serial)
{
    uint8_t attributes_buffer[128];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    size_t serial_length;
    unsigned long parsed_index;
    char *end;
    uint32_t ifindex;
    unsigned int interface_index;
    int error;

    serial_length = strlen(radio_serial);
    if (!serial_length || serial_length > MELODI_RADIO_SERIAL_MAX)
        return -EINVAL;
    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    melodi_attributes_begin(&attributes, attributes_buffer,
                            sizeof(attributes_buffer));
    melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    error = melodi_genl_put(&attributes, MELODI_A_RADIO_SERIAL,
                            radio_serial, serial_length + 1);
    if (error)
        return error;
    error = melodi_request(MELODI_CMD_LINK_SET, &attributes, false, &reply,
                           reply_buffer, sizeof(reply_buffer));
    if (!error) {
        if (strncmp(interface_name, "mel", 3))
            return -EINVAL;
        errno = 0;
        parsed_index = strtoul(interface_name + 3, &end, 10);
        if (errno || end == interface_name + 3 || *end ||
            parsed_index >= MELODI_TTY_LIMIT)
            return -EINVAL;
        interface_index = parsed_index;
        error = melodi_tty_attach_serial_at("/sys", "/dev",
                                            interface_index, radio_serial);
        if (error == -ENOENT)
            error = 0;
    }
    return error;
}

static int melodi_radio_selector(const char *interface_name,
                                 char serial[MELODI_RADIO_SERIAL_MAX + 1])
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    uint32_t ifindex;
    size_t length;
    int error;

    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    melodi_attributes_begin(&attributes, attributes_buffer,
                            sizeof(attributes_buffer));
    melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    error = melodi_request(MELODI_CMD_LINK_GET, &attributes, true, &reply,
                           reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_RADIO_SERIAL])
        return -ENOENT;
    length = reply.lengths[MELODI_A_RADIO_SERIAL];
    if (length < 2 || length > MELODI_RADIO_SERIAL_MAX + 1 ||
        ((const char *)reply.attributes[MELODI_A_RADIO_SERIAL])[length - 1])
        return -EPROTO;
    memcpy(serial, reply.attributes[MELODI_A_RADIO_SERIAL], length);
    return 0;
}

static int melodi_tty_scan(void)
{
    char serial[MELODI_RADIO_SERIAL_MAX + 1];
    struct if_nameindex *interfaces;
    struct if_nameindex *entry;
    unsigned long parsed_index;
    char *end;
    int result = 0;
    int error;

    interfaces = if_nameindex();
    if (!interfaces)
        return -errno;
    for (entry = interfaces; entry->if_index; entry++) {
        error = melodi_radio_selector(entry->if_name, serial);
        if (error == -ENODEV || error == -ENOENT)
            continue;
        if (error) {
            if (!result)
                result = error;
            continue;
        }
        if (strncmp(entry->if_name, "mel", 3))
            continue;
        errno = 0;
        parsed_index = strtoul(entry->if_name + 3, &end, 10);
        if (errno || end == entry->if_name + 3 || *end ||
            parsed_index >= MELODI_TTY_LIMIT) {
            if (!result)
                result = -EINVAL;
            continue;
        }
        error = melodi_tty_attach_serial_at("/sys", "/dev", parsed_index,
                                            serial);
        if (error && error != -ENOENT && !result)
            result = error;
    }
    if_freenameindex(interfaces);
    return result;
}

static int melodi_tty_release(void)
{
    unsigned int index;
    int result = 0;
    int error;

    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        error = melodi_tty_release_at("/sys", "/dev", index);
        if (error && error != -ENOENT && !result)
            result = error;
    }
    /* Reaches an attachment whose device node was already removed. */
    error = melodi_tty_release_all_at("/sys");
    if (error && error != -ENOENT && !result)
        result = error;
    return result;
}

static int melodi_derive_public(const uint8_t private_key[32],
                                struct melodi_node_id *node_id)
{
    EVP_PKEY *key;
    size_t public_length = MELODI_NODE_KEY_SIZE;
    int error = -EINVAL;

    key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL,
                                          private_key, 32);
    if (!key)
        return -EINVAL;
    node_id->bytes[0] = MELODI_NODE_ID_SCHEME_ED25519;
    if (EVP_PKEY_get_raw_public_key(key, node_id->bytes + 1,
                                    &public_length) == 1 &&
        public_length == MELODI_NODE_KEY_SIZE)
        error = 0;
    EVP_PKEY_free(key);
    return error;
}

static int melodi_write_identity(const char *path)
{
    uint8_t private_key[32];
    ssize_t written;
    int descriptor;
    int error = 0;

    if (RAND_bytes(private_key, sizeof(private_key)) != 1)
        return -EIO;
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0)
        return -errno;
    written = write(descriptor, private_key, sizeof(private_key));
    if (written != sizeof(private_key))
        error = written < 0 ? -errno : -EIO;
    if (close(descriptor) < 0 && !error)
        error = -errno;
    OPENSSL_cleanse(private_key, sizeof(private_key));
    if (error)
        unlink(path);
    return error;
}

static int melodi_read_identity(const char *path, uint8_t private_key[32])
{
    struct stat status;
    uint8_t extra;
    ssize_t received;
    int descriptor;
    int error = 0;

    if (lstat(path, &status) < 0)
        return -errno;
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0077))
        return -EACCES;
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0)
        return -errno;
    received = read(descriptor, private_key, 32);
    if (received != 32)
        error = received < 0 ? -errno : -EINVAL;
    if (!error) {
        received = read(descriptor, &extra, 1);
        if (received != 0)
            error = received < 0 ? -errno : -EINVAL;
    }
    close(descriptor);
    return error;
}

static int melodi_parse_u32(const char *text, uint32_t *value)
{
    char *end;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno || !*text || *end || !parsed || parsed > UINT32_MAX)
        return -EINVAL;
    *value = (uint32_t)parsed;
    return 0;
}

static int melodi_install_identity(
    const char *interface_name, const uint8_t private_key[32],
    uint32_t generation, const struct melodi_node_id *previous_node_id,
    const struct melodi_node_id *confirmed_node_id)
{
    uint8_t attributes_buffer[192];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    struct melodi_node_id node_id;
    char text[MELODI_NODE_ID_STRING_SIZE];
    uint32_t ifindex;
    long serial;
    int error;

    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    error = melodi_derive_public(private_key, &node_id);
    if (error)
        return error;
    error = melodi_nodeid_format(&node_id, text);
    if (error)
        return error;
    printf("node-id=%s generation=%u\n", text, generation);
    if (previous_node_id &&
        (!confirmed_node_id ||
         memcmp(confirmed_node_id, &node_id, sizeof(node_id))))
        return -ECANCELED;
    serial = syscall(SYS_add_key, "user", "melodi:identity", private_key,
                     32, KEY_SPEC_PROCESS_KEYRING);
    if (serial < 0)
        return -errno;
    melodi_attributes_begin(&attributes, attributes_buffer,
                            sizeof(attributes_buffer));
    melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    melodi_genl_put(&attributes, MELODI_A_NODE_ID, node_id.bytes,
                    sizeof(node_id.bytes));
    melodi_genl_put_u32(&attributes, MELODI_A_KEY_SERIAL, serial);
    melodi_genl_put_u32(&attributes, MELODI_A_GENERATION, generation);
    if (previous_node_id)
        melodi_genl_put(&attributes, MELODI_A_PREVIOUS_NODE_ID,
                        previous_node_id->bytes,
                        sizeof(previous_node_id->bytes));
    return melodi_request(MELODI_CMD_IDENTITY_LOAD, &attributes, false,
                          &reply, reply_buffer, sizeof(reply_buffer));
}

static int melodi_load_identity(
    const char *interface_name, const char *path, uint32_t generation,
    const struct melodi_node_id *previous_node_id,
    const struct melodi_node_id *confirmed_node_id)
{
    uint8_t private_key[32];
    int error;

    error = melodi_read_identity(path, private_key);
    if (!error)
        error = melodi_install_identity(interface_name, private_key,
                                        generation, previous_node_id,
                                        confirmed_node_id);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return error;
}

static int melodi_tpm_provision_identity(const char *directory,
                                         const char *parent_text,
                                         const char *counter_text,
                                         const char *owner_auth_path)
{
    uint8_t private_key[32];
    struct melodi_node_id node_id;
    char text[MELODI_NODE_ID_STRING_SIZE];
    uint32_t parent;
    uint32_t counter;
    int error;

    error = melodi_parse_u32(parent_text, &parent);
    if (!error)
        error = melodi_parse_u32(counter_text, &counter);
    if (!error && RAND_bytes(private_key, sizeof(private_key)) != 1)
        error = -EIO;
    if (!error)
        error = melodi_derive_public(private_key, &node_id);
    if (!error)
        error = melodi_tpm_provision(directory, parent, counter,
                                     owner_auth_path, private_key);
    if (!error)
        error = melodi_nodeid_format(&node_id, text);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    if (!error)
        printf("node-id=%s\n", text);
    return error;
}

static int melodi_tpm_reserve_identity(
    const char *interface_name, const char *directory,
    const struct melodi_node_id *previous_node_id,
    const struct melodi_node_id *confirmed_node_id)
{
    uint8_t private_key[32];
    struct melodi_node_id node_id;
    char text[MELODI_NODE_ID_STRING_SIZE];
    uint32_t generation;
    int error;

    error = melodi_tpm_reserve(directory, private_key, &generation);
    if (error)
        return error;
    if (interface_name)
        error = melodi_install_identity(interface_name, private_key,
                                        generation, previous_node_id,
                                        confirmed_node_id);
    else {
        error = melodi_derive_public(private_key, &node_id);
        if (!error)
            error = melodi_nodeid_format(&node_id, text);
        if (!error)
            printf("node-id=%s generation=%u\n", text, generation);
    }
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return error;
}

static int melodi_identity_load_command(const char *interface_name,
                                        const char *path,
                                        const char *generation_text,
                                        const char *previous_text,
                                        const char *confirmed_text)
{
    struct melodi_node_id previous_node_id;
    struct melodi_node_id confirmed_node_id;
    const struct melodi_node_id *previous = NULL;
    const struct melodi_node_id *confirmed = NULL;
    uint32_t generation;
    int error;

    error = melodi_parse_u32(generation_text, &generation);
    if (!error && previous_text) {
        error = melodi_nodeid_parse(previous_text, strlen(previous_text),
                                    &previous_node_id);
        if (!error)
            previous = &previous_node_id;
    }
    if (!error && confirmed_text) {
        error = melodi_nodeid_parse(confirmed_text, strlen(confirmed_text),
                                    &confirmed_node_id);
        if (!error)
            confirmed = &confirmed_node_id;
    }
    return error ? error : melodi_load_identity(interface_name, path,
                                                generation, previous,
                                                confirmed);
}

static int melodi_tpm_load_command(const char *interface_name,
                                   const char *directory,
                                   const char *previous_text,
                                   const char *confirmed_text)
{
    struct melodi_node_id previous_node_id;
    struct melodi_node_id confirmed_node_id;
    const struct melodi_node_id *previous = NULL;
    const struct melodi_node_id *confirmed = NULL;
    int error = 0;

    if (previous_text) {
        error = melodi_nodeid_parse(previous_text, strlen(previous_text),
                                    &previous_node_id);
        if (!error)
            previous = &previous_node_id;
    }
    if (!error && confirmed_text) {
        error = melodi_nodeid_parse(confirmed_text, strlen(confirmed_text),
                                    &confirmed_node_id);
        if (!error)
            confirmed = &confirmed_node_id;
    }
    return error ? error : melodi_tpm_reserve_identity(interface_name,
                                                       directory, previous,
                                                       confirmed);
}

static int melodi_show_identity(const char *interface_name)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    struct melodi_node_id node_id;
    char text[MELODI_NODE_ID_STRING_SIZE];
    uint32_t ifindex;
    int error;

    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    melodi_attributes_begin(&attributes, attributes_buffer,
                            sizeof(attributes_buffer));
    melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    error = melodi_request(MELODI_CMD_IDENTITY_GET_PUBLIC, &attributes, true,
                           &reply, reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_NODE_ID] ||
        !reply.attributes[MELODI_A_GENERATION])
        return -EPROTO;
    memcpy(&node_id, reply.attributes[MELODI_A_NODE_ID], sizeof(node_id));
    error = melodi_nodeid_format(&node_id, text);
    if (error)
        return -EINVAL;
    printf("%s\n", text);
    return 0;
}

static int melodi_interface_attributes(const char *interface_name,
                                       struct melodi_genl_builder *attributes,
                                       uint8_t *buffer, size_t capacity)
{
    uint32_t ifindex = 0;
    int error;

    error = melodi_interface(interface_name, &ifindex);
    if (error)
        return error;
    error = melodi_attributes_begin(attributes, buffer, capacity);
    if (!error)
        error = melodi_genl_put_u32(attributes, MELODI_A_IFINDEX, ifindex);
    return error;
}

static int melodi_simple_interface(uint8_t command,
                                   const char *interface_name)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (error)
        return error;
    return melodi_request(command, &attributes, false, &reply, reply_buffer,
                          sizeof(reply_buffer));
}

static int melodi_peer_command(uint8_t command, const char *interface_name,
                               const char *node_text)
{
    uint8_t attributes_buffer[128];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    struct melodi_node_id node;
    int error;

    error = melodi_nodeid_parse(node_text, strlen(node_text), &node);
    if (error)
        return -EINVAL;
    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (!error)
        error = melodi_genl_put(&attributes, MELODI_A_NODE_ID, node.bytes,
                                sizeof(node.bytes));
    if (error)
        return error;
    return melodi_request(command, &attributes, false, &reply, reply_buffer,
                          sizeof(reply_buffer));
}

static int melodi_policy_reset_command(const char *interface_name)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (!error)
        error = melodi_genl_put_u8(&attributes, MELODI_A_POLICY_RESET, 1);
    if (error)
        return error;
    return melodi_request(MELODI_CMD_POLICY_SET, &attributes, false,
                          &reply, reply_buffer, sizeof(reply_buffer));
}

static int melodi_policy(const char *interface_name, const char *setting)
{
    static const char *const names[] = { "authenticated", "trusted" };
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    uint8_t mode;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (error)
        return error;
    if (setting) {
        if (strcmp(setting, names[0]) == 0)
            mode = MELODI_POLICY_ALLOW_AUTHENTICATED;
        else if (strcmp(setting, names[1]) == 0)
            mode = MELODI_POLICY_REQUIRE_TRUST;
        else
            return -EINVAL;
        error = melodi_genl_put_u8(&attributes, MELODI_A_POLICY_MODE, mode);
        if (error)
            return error;
        return melodi_request(MELODI_CMD_POLICY_SET, &attributes, false,
                              &reply, reply_buffer, sizeof(reply_buffer));
    }
    error = melodi_request(MELODI_CMD_POLICY_GET, &attributes, true, &reply,
                           reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_POLICY_MODE])
        return -EPROTO;
    memcpy(&mode, reply.attributes[MELODI_A_POLICY_MODE], sizeof(mode));
    if (mode > MELODI_POLICY_REQUIRE_TRUST)
        return -EPROTO;
    printf("%s\n", names[mode]);
    return 0;
}

static int melodi_policy_service(const char *interface_name,
                                 const char *service_text,
                                 const char *action_text)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    unsigned long parsed;
    uint16_t service;
    uint8_t action;
    char *end;
    int error;

    if (strcmp(action_text, "allow") == 0)
        action = MELODI_POLICY_SERVICE_ALLOW;
    else if (strcmp(action_text, "deny") == 0)
        action = MELODI_POLICY_SERVICE_DENY;
    else if (strcmp(action_text, "clear") == 0)
        action = MELODI_POLICY_SERVICE_CLEAR;
    else
        return -EINVAL;
    errno = 0;
    parsed = strtoul(service_text, &end, 10);
    if (errno || !*service_text || *end || !parsed || parsed > UINT16_MAX)
        return -EINVAL;
    service = parsed;
    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (!error)
        error = melodi_genl_put_u16(&attributes,
                                    MELODI_A_POLICY_SERVICE, service);
    if (!error)
        error = melodi_genl_put_u8(&attributes,
                                   MELODI_A_POLICY_ACTION, action);
    if (error)
        return error;
    return melodi_request(MELODI_CMD_POLICY_SET, &attributes, false,
                          &reply, reply_buffer, sizeof(reply_buffer));
}

static int melodi_policy_broadcast(const char *interface_name,
                                   const char *setting)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    uint8_t allowed;
    int error;

    if (strcmp(setting, "allow") == 0)
        allowed = 1;
    else if (strcmp(setting, "deny") == 0)
        allowed = 0;
    else
        return -EINVAL;
    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (!error)
        error = melodi_genl_put_u8(&attributes,
                                   MELODI_A_POLICY_BROADCAST, allowed);
    if (error)
        return error;
    return melodi_request(MELODI_CMD_POLICY_SET, &attributes, false,
                          &reply, reply_buffer, sizeof(reply_buffer));
}

static int melodi_setup_apply(const char *interface_name,
                              const struct melodi_setup_config *config)
{
    char node_text[MELODI_NODE_ID_STRING_SIZE];
    char service_text[6];
    size_t index;
    int error;

    error = melodi_tpm_load_command(interface_name, config->identity_path,
                                    NULL, NULL);
    if (!error)
        error = melodi_policy_reset_command(interface_name);
    for (index = 0; !error && index < config->operation_count; index++) {
        const struct melodi_setup_operation *operation =
            &config->operations[index];

        switch (operation->type) {
        case MELODI_SETUP_POLICY:
            error = melodi_policy(
                interface_name,
                operation->value == MELODI_POLICY_REQUIRE_TRUST ?
                "trusted" : "authenticated");
            break;
        case MELODI_SETUP_SERVICE:
            snprintf(service_text, sizeof(service_text), "%u",
                     operation->service);
            error = melodi_policy_service(
                interface_name, service_text,
                operation->value == MELODI_POLICY_SERVICE_ALLOW ?
                "allow" : "deny");
            break;
        case MELODI_SETUP_BROADCAST:
            error = melodi_policy_broadcast(
                interface_name, operation->value ? "allow" : "deny");
            break;
        case MELODI_SETUP_TRUST:
        case MELODI_SETUP_BLOCK:
            error = melodi_nodeid_format(&operation->node_id, node_text);
            if (!error)
                error = melodi_peer_command(
                    operation->type == MELODI_SETUP_TRUST ?
                    MELODI_CMD_PEER_TRUST : MELODI_CMD_PEER_BLOCK,
                    interface_name, node_text);
            break;
        }
    }
    return error;
}

static int melodi_setup_command(const char *interface_name, const char *path)
{
    enum { MELODI_SETUP_FILE_MAX = 65536 };
    struct melodi_setup_config config;
    struct stat status;
    unsigned int error_line = 0;
    char *data;
    size_t length = 0;
    ssize_t result;
    int descriptor;
    int error = 0;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return -errno;
    if (fstat(descriptor, &status) < 0)
        error = -errno;
    else if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
             (status.st_mode & 0022))
        error = -EPERM;
    else if (status.st_size < 0 || status.st_size > MELODI_SETUP_FILE_MAX)
        error = -EFBIG;
    data = error ? NULL : malloc(MELODI_SETUP_FILE_MAX + 2);
    if (!error && !data)
        error = -ENOMEM;
    while (!error && length <= MELODI_SETUP_FILE_MAX) {
        result = read(descriptor, data + length,
                      MELODI_SETUP_FILE_MAX + 1 - length);
        if (result < 0 && errno == EINTR)
            continue;
        if (result < 0) {
            error = -errno;
            break;
        }
        if (!result)
            break;
        length += result;
    }
    if (!error && length > MELODI_SETUP_FILE_MAX)
        error = -EFBIG;
    if (!error) {
        data[length] = '\0';
        error = melodi_setup_parse(data, length, &config, &error_line);
        if (error)
            fprintf(stderr, "%s:%u: invalid setup configuration\n",
                    path, error_line);
    }
    if (close(descriptor) < 0 && !error)
        error = -errno;
    if (!error)
        error = melodi_setup_apply(interface_name, &config);
    free(data);
    return error;
}

static int melodi_stats(const char *interface_name)
{
    static const char *const names[] = {
        NULL, "rx_packets", "rx_bytes", "rx_errors", "rx_dropped",
        "tx_packets", "tx_bytes", "tx_errors", "tx_dropped",
        "tx_queue_frames", "tx_queue_bytes", "authenticated_peers",
        "reassemblies", "reliable_pending", "discovery_pending",
        "auth_failures",
        "replay_drops", "broadcast_tx", "broadcast_rx", "airtime_us",
        "broadcast_airtime_us", "duty_defers", "queue_expired",
        "app_delivery_drops", "monitor_drops",
    };
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    const struct nlattr *attribute;
    const uint8_t *position;
    uint64_t value;
    size_t remaining;
    size_t aligned;
    uint16_t type;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (error)
        return error;
    error = melodi_request(MELODI_CMD_STATS_GET, &attributes, true, &reply,
                           reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_STATS])
        return -EPROTO;
    position = reply.attributes[MELODI_A_STATS];
    remaining = reply.lengths[MELODI_A_STATS];
    while (remaining) {
        attribute = (const struct nlattr *)position;
        if (remaining < sizeof(*attribute) ||
            attribute->nla_len < sizeof(*attribute) ||
            attribute->nla_len > remaining)
            return -EPROTO;
        aligned = NLA_ALIGN(attribute->nla_len);
        if (aligned > remaining)
            return -EPROTO;
        type = attribute->nla_type & NLA_TYPE_MASK;
        if (type) {
            if (type > MELODI_STAT_A_MAX ||
                attribute->nla_len != sizeof(*attribute) + sizeof(value))
                return -EPROTO;
            memcpy(&value, position + sizeof(*attribute), sizeof(value));
            printf("%s=%llu\n", names[type],
                   (unsigned long long)value);
        }
        position += aligned;
        remaining -= aligned;
    }
    return 0;
}

static int melodi_print_peer(const struct melodi_genl_message *message)
{
    static const char *const states[] = {
        "authenticated", "trusted", "blocked", "conflicted",
        "observed", "challenged",
    };
    static const char *const policies[] = {
        "default", "trusted", "blocked",
    };
    struct melodi_node_id node;
    char text[MELODI_NODE_ID_STRING_SIZE];
    uint32_t generation;
    uint32_t locator;
    uint32_t round;
    uint32_t expiry_ms;
    uint32_t capabilities;
    uint64_t last_seen_ns;
    int16_t rssi;
    int16_t snr;
    uint8_t hops;
    uint8_t policy;
    uint8_t state;
    int error;

    if (!message->attributes[MELODI_A_NODE_ID] ||
        !message->attributes[MELODI_A_PEER_NATIVE_LOCATOR] ||
        !message->attributes[MELODI_A_COLLISION_ROUND] ||
        !message->attributes[MELODI_A_GENERATION] ||
        !message->attributes[MELODI_A_PEER_STATE] ||
        !message->attributes[MELODI_A_PEER_EXPIRY_MS] ||
        !message->attributes[MELODI_A_PEER_CAPABILITIES] ||
        !message->attributes[MELODI_A_PEER_RSSI] ||
        !message->attributes[MELODI_A_PEER_SNR] ||
        !message->attributes[MELODI_A_PEER_HOPS] ||
        !message->attributes[MELODI_A_PEER_LAST_SEEN_NS] ||
        !message->attributes[MELODI_A_PEER_POLICY])
        return -EPROTO;
    memcpy(&node, message->attributes[MELODI_A_NODE_ID], sizeof(node));
    memcpy(&locator, message->attributes[MELODI_A_PEER_NATIVE_LOCATOR],
           sizeof(locator));
    memcpy(&round, message->attributes[MELODI_A_COLLISION_ROUND],
           sizeof(round));
    memcpy(&generation, message->attributes[MELODI_A_GENERATION],
           sizeof(generation));
    memcpy(&state, message->attributes[MELODI_A_PEER_STATE], sizeof(state));
    memcpy(&expiry_ms, message->attributes[MELODI_A_PEER_EXPIRY_MS],
           sizeof(expiry_ms));
    memcpy(&capabilities,
           message->attributes[MELODI_A_PEER_CAPABILITIES],
           sizeof(capabilities));
    memcpy(&rssi, message->attributes[MELODI_A_PEER_RSSI], sizeof(rssi));
    memcpy(&snr, message->attributes[MELODI_A_PEER_SNR], sizeof(snr));
    memcpy(&hops, message->attributes[MELODI_A_PEER_HOPS], sizeof(hops));
    memcpy(&last_seen_ns,
           message->attributes[MELODI_A_PEER_LAST_SEEN_NS],
           sizeof(last_seen_ns));
    memcpy(&policy, message->attributes[MELODI_A_PEER_POLICY],
           sizeof(policy));
    error = melodi_nodeid_format(&node, text);
    if (error || state > MELODI_PEER_CHALLENGED ||
        policy > MELODI_PEER_POLICY_BLOCKED)
        return -EPROTO;
    printf("%s state=%s locator=%08x round=%u generation=%u expiry-ms=%u "
           "policy=%s capabilities=%08x rssi=%d snr=%d hops=%u "
           "last-seen-ns=%llu\n",
           text, states[state], locator, round, generation, expiry_ms,
           policies[policy], capabilities, rssi, snr, hops,
           (unsigned long long)last_seen_ns);
    return 0;
}

static int melodi_peers(const char *interface_name)
{
    uint8_t attributes_buffer[64];
    uint8_t response[8192];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message message;
    struct melodi_socket socket_state;
    struct nlmsghdr *header;
    ssize_t received;
    int remaining;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (error)
        return error;
    error = melodi_socket_open(&socket_state);
    if (error)
        return error;
    error = melodi_socket_request(
        &socket_state, MELODI_CMD_PEER_DUMP,
        melodi_attributes_data(&attributes),
        melodi_attributes_length(&attributes), NLM_F_REQUEST | NLM_F_DUMP);
    while (!error) {
        received = recv(socket_state.descriptor, response, sizeof(response), 0);
        if (received < 0) {
            error = -errno;
            break;
        }
        remaining = received;
        for (header = (struct nlmsghdr *)response;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != socket_state.sequence)
                continue;
            if (header->nlmsg_type == NLMSG_DONE)
                goto out;
            if (header->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *netlink_error = NLMSG_DATA(header);

                error = header->nlmsg_len >=
                        NLMSG_LENGTH(sizeof(*netlink_error)) ?
                        netlink_error->error : -EPROTO;
                goto out;
            }
            if (header->nlmsg_type != socket_state.family)
                continue;
            error = melodi_genl_parse(header, header->nlmsg_len, &message);
            if (!error)
                error = melodi_print_peer(&message);
            if (error)
                goto out;
        }
        if (remaining)
            error = -EPROTO;
    }
out:
    melodi_socket_close(&socket_state);
    return error;
}

static int melodi_monitor(const char *interface_name)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    uint8_t response[8192];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message message;
    struct melodi_socket socket_state;
    const uint8_t *frame;
    struct nlmsghdr *header;
    ssize_t received;
    size_t index;
    int remaining;
    int error;

    error = melodi_interface_attributes(interface_name, &attributes,
                                        attributes_buffer,
                                        sizeof(attributes_buffer));
    if (error)
        return error;
    error = melodi_socket_open(&socket_state);
    if (error)
        return error;
    error = melodi_socket_command(
        &socket_state, MELODI_CMD_MONITOR_BIND,
        melodi_attributes_data(&attributes),
        melodi_attributes_length(&attributes), false, &message,
        reply_buffer, sizeof(reply_buffer));
    while (!error) {
        received = recv(socket_state.descriptor, response, sizeof(response), 0);
        if (received < 0) {
            error = -errno;
            break;
        }
        remaining = received;
        for (header = (struct nlmsghdr *)response;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type != socket_state.family)
                continue;
            error = melodi_genl_parse(header, header->nlmsg_len, &message);
            if (error)
                goto out;
            if (message.command != MELODI_CMD_MONITOR_FRAME)
                continue;
            frame = message.attributes[MELODI_A_FRAME];
            if (!frame || !message.attributes[MELODI_A_MONITOR_DIRECTION]) {
                error = -EPROTO;
                goto out;
            }
            printf("%s ",
                   *(const uint8_t *)
                       message.attributes[MELODI_A_MONITOR_DIRECTION] ==
                           MELODI_MONITOR_RX ? "rx" : "tx");
            for (index = 0; index < message.lengths[MELODI_A_FRAME]; index++)
                printf("%02x", frame[index]);
            putchar('\n');
            fflush(stdout);
        }
        if (remaining)
            error = -EPROTO;
    }
out:
    melodi_socket_close(&socket_state);
    return error;
}

static void melodi_usage(FILE *stream)
{
    fprintf(stream,
            "usage:\n"
            "  melodi status -i INTERFACE\n"
            "  melodi setup -i INTERFACE FILE\n"
            "  melodi link set -i INTERFACE --usb-serial SERIAL\n"
            "  melodi tty scan\n"
            "  melodi tty release\n"
            "  melodi id -i INTERFACE\n"
            "  melodi identity generate FILE\n"
            "  melodi identity load -i INTERFACE --generation N FILE\n"
            "  melodi identity load -i INTERFACE --generation N "
            "--migrate-policy-from OLD_NODE_ID --confirm-node-id "
            "NEW_NODE_ID FILE\n"
            "  melodi identity tpm provision DIRECTORY --parent-handle "
            "HANDLE --nv-index INDEX --owner-auth-file FILE\n"
            "  melodi identity tpm load -i INTERFACE DIRECTORY\n"
            "  melodi identity tpm load -i INTERFACE DIRECTORY "
            "--migrate-policy-from OLD_NODE_ID --confirm-node-id "
            "NEW_NODE_ID\n"
            "  melodi identity tpm reserve DIRECTORY\n"
            "  melodi peers -i INTERFACE\n"
            "  melodi discover -i INTERFACE\n"
            "  melodi trust|block|clear|reverify -i INTERFACE NODE_ID\n"
            "  melodi policy -i INTERFACE [authenticated|trusted]\n"
            "  melodi policy -i INTERFACE reset\n"
            "  melodi policy -i INTERFACE service SERVICE allow|deny|clear\n"
            "  melodi policy -i INTERFACE broadcast allow|deny\n"
            "  melodi stats -i INTERFACE\n"
            "  melodi monitor -i INTERFACE\n");
}

int main(int argc, char **argv)
{
    int error = -EINVAL;

    if (argc == 4 && strcmp(argv[1], "status") == 0 &&
        strcmp(argv[2], "-i") == 0)
        error = melodi_status(argv[3]);
    else if (argc == 5 && strcmp(argv[1], "setup") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_setup_command(argv[3], argv[4]);
    else if (argc == 7 && strcmp(argv[1], "link") == 0 &&
             strcmp(argv[2], "set") == 0 && strcmp(argv[3], "-i") == 0 &&
             strcmp(argv[5], "--usb-serial") == 0)
        error = melodi_set_radio(argv[4], argv[6]);
    else if (argc == 3 && strcmp(argv[1], "tty") == 0 &&
             strcmp(argv[2], "scan") == 0)
        error = melodi_tty_scan();
    else if (argc == 3 && strcmp(argv[1], "tty") == 0 &&
             strcmp(argv[2], "release") == 0)
        error = melodi_tty_release();
    else if (argc == 4 && strcmp(argv[1], "id") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_show_identity(argv[3]);
    else if (argc == 4 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "generate") == 0)
        error = melodi_write_identity(argv[3]);
    else if (argc == 8 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "load") == 0 && strcmp(argv[3], "-i") == 0 &&
             strcmp(argv[5], "--generation") == 0)
        error = melodi_identity_load_command(argv[4], argv[7], argv[6],
                                             NULL, NULL);
    else if (argc == 12 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "load") == 0 && strcmp(argv[3], "-i") == 0 &&
             strcmp(argv[5], "--generation") == 0 &&
             strcmp(argv[7], "--migrate-policy-from") == 0 &&
             strcmp(argv[9], "--confirm-node-id") == 0)
        error = melodi_identity_load_command(argv[4], argv[11], argv[6],
                                             argv[8], argv[10]);
    else if (argc == 11 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "tpm") == 0 &&
             strcmp(argv[3], "provision") == 0 &&
             strcmp(argv[5], "--parent-handle") == 0 &&
             strcmp(argv[7], "--nv-index") == 0 &&
             strcmp(argv[9], "--owner-auth-file") == 0)
        error = melodi_tpm_provision_identity(argv[4], argv[6], argv[8],
                                              argv[10]);
    else if (argc == 7 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "tpm") == 0 && strcmp(argv[3], "load") == 0 &&
             strcmp(argv[4], "-i") == 0)
        error = melodi_tpm_load_command(argv[5], argv[6], NULL, NULL);
    else if (argc == 11 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "tpm") == 0 && strcmp(argv[3], "load") == 0 &&
             strcmp(argv[4], "-i") == 0 &&
             strcmp(argv[7], "--migrate-policy-from") == 0 &&
             strcmp(argv[9], "--confirm-node-id") == 0)
        error = melodi_tpm_load_command(argv[5], argv[6], argv[8], argv[10]);
    else if (argc == 5 && strcmp(argv[1], "identity") == 0 &&
             strcmp(argv[2], "tpm") == 0 &&
             strcmp(argv[3], "reserve") == 0)
        error = melodi_tpm_reserve_identity(NULL, argv[4], NULL, NULL);
    else if (argc == 4 && strcmp(argv[1], "peers") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_peers(argv[3]);
    else if (argc == 4 && strcmp(argv[1], "discover") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_simple_interface(MELODI_CMD_DISCOVER, argv[3]);
    else if (argc == 5 && strcmp(argv[1], "policy") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = strcmp(argv[4], "reset") == 0 ?
                melodi_policy_reset_command(argv[3]) :
                melodi_policy(argv[3], argv[4]);
    else if (argc == 7 && strcmp(argv[1], "policy") == 0 &&
             strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[4], "service") == 0)
        error = melodi_policy_service(argv[3], argv[5], argv[6]);
    else if (argc == 6 && strcmp(argv[1], "policy") == 0 &&
             strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[4], "broadcast") == 0)
        error = melodi_policy_broadcast(argv[3], argv[5]);
    else if (argc == 4 && strcmp(argv[1], "policy") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_policy(argv[3], NULL);
    else if (argc == 5 && strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[1], "trust") == 0)
        error = melodi_peer_command(MELODI_CMD_PEER_TRUST, argv[3], argv[4]);
    else if (argc == 5 && strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[1], "block") == 0)
        error = melodi_peer_command(MELODI_CMD_PEER_BLOCK, argv[3], argv[4]);
    else if (argc == 5 && strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[1], "clear") == 0)
        error = melodi_peer_command(MELODI_CMD_PEER_CLEAR, argv[3], argv[4]);
    else if (argc == 5 && strcmp(argv[2], "-i") == 0 &&
             strcmp(argv[1], "reverify") == 0)
        error = melodi_peer_command(MELODI_CMD_PEER_REVERIFY, argv[3], argv[4]);
    else if (argc == 4 && strcmp(argv[1], "stats") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_stats(argv[3]);
    else if (argc == 4 && strcmp(argv[1], "monitor") == 0 &&
             strcmp(argv[2], "-i") == 0)
        error = melodi_monitor(argv[3]);
    else {
        melodi_usage(stderr);
        return 2;
    }
    if (error) {
        fprintf(stderr, "melodi: %s\n", strerror(-error));
        return 1;
    }
    return 0;
}
