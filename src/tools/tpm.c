/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "tpm.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MELODI_TPM_PARENT_MIN UINT32_C(0x81000000)
#define MELODI_TPM_PARENT_MAX UINT32_C(0x81ffffff)
#define MELODI_TPM_COUNTER_MIN UINT32_C(0x01000000)
#define MELODI_TPM_COUNTER_MAX UINT32_C(0x01ffffff)

static const uint8_t melodi_tpm_magic[8] = {
    'M', 'E', 'L', 'O', 'T', 'P', 'M', '1',
};

static const uint8_t melodi_tpm_seal_magic[8] = {
    'M', 'E', 'L', 'O', 'S', 'E', 'A', 'L',
};

static int melodi_tpm_write_all(int descriptor, const void *data,
                                size_t length)
{
    const uint8_t *bytes = data;

    while (length) {
        ssize_t written = write(descriptor, bytes, length);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (!written)
            return -EIO;
        bytes += written;
        length -= (size_t)written;
    }
    return 0;
}

static int melodi_tpm_read_output(int descriptor, uint8_t *output,
                                  size_t capacity, size_t *length)
{
    uint8_t discard[64] = { 0 };
    size_t used = 0;
    int error = 0;

    for (;;) {
        uint8_t *destination = used < capacity ? output + used : discard;
        size_t available = used < capacity ? capacity - used : sizeof(discard);
        ssize_t received = read(descriptor, destination, available);

        if (received < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (!received)
            break;
        if (used < capacity)
            used += (size_t)received;
        else
            error = -EOVERFLOW;
    }
    *length = used;
    return error;
}

static int melodi_tpm_run(char *const arguments[], const uint8_t *input,
                          size_t input_length, uint8_t *output,
                          size_t output_capacity, size_t *output_length)
{
    struct sigaction ignored = { .sa_handler = SIG_IGN };
    struct sigaction previous;
    int input_pipe[2] = { -1, -1 };
    int output_pipe[2] = { -1, -1 };
    int status;
    int error = 0;
    pid_t child;

    if (input && pipe2(input_pipe, O_CLOEXEC) < 0)
        return -errno;
    if (output && pipe2(output_pipe, O_CLOEXEC) < 0) {
        error = -errno;
        goto close_pipes;
    }
    child = fork();
    if (child < 0) {
        error = -errno;
        goto close_pipes;
    }
    if (!child) {
        if (input && dup2(input_pipe[0], STDIN_FILENO) < 0)
            _exit(126);
        if (output && dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(126);
        if (!output) {
            int null_descriptor = open("/dev/null", O_WRONLY);

            if (null_descriptor < 0 ||
                dup2(null_descriptor, STDOUT_FILENO) < 0)
                _exit(126);
            close(null_descriptor);
        }
        close(input_pipe[0]);
        close(input_pipe[1]);
        close(output_pipe[0]);
        close(output_pipe[1]);
        setenv("TPM2TOOLS_AUTOFLUSH", "yes", 0);
        execvp(arguments[0], arguments);
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (input) {
        close(input_pipe[0]);
        input_pipe[0] = -1;
        sigaction(SIGPIPE, &ignored, &previous);
        error = melodi_tpm_write_all(input_pipe[1], input, input_length);
        sigaction(SIGPIPE, &previous, NULL);
        close(input_pipe[1]);
        input_pipe[1] = -1;
    }
    if (output) {
        int read_error;

        close(output_pipe[1]);
        output_pipe[1] = -1;
        read_error = melodi_tpm_read_output(output_pipe[0], output,
                                            output_capacity, output_length);
        if (!error)
            error = read_error;
        close(output_pipe[0]);
        output_pipe[0] = -1;
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            if (!error)
                error = -errno;
            goto close_pipes;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        error = error ? error : -EIO;
close_pipes:
    if (input_pipe[0] >= 0)
        close(input_pipe[0]);
    if (input_pipe[1] >= 0)
        close(input_pipe[1]);
    if (output_pipe[0] >= 0)
        close(output_pipe[0]);
    if (output_pipe[1] >= 0)
        close(output_pipe[1]);
    return error;
}

static int melodi_tpm_path(char path[PATH_MAX], const char *directory,
                           const char *name)
{
    int length = snprintf(path, PATH_MAX, "%s/%s", directory, name);

    return length < 0 || length >= PATH_MAX ? -ENAMETOOLONG : 0;
}

static void melodi_tpm_store_u32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint32_t melodi_tpm_load_u32(const uint8_t bytes[4])
{
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
           (uint32_t)bytes[2] << 8 | bytes[3];
}

static int melodi_tpm_secure_directory(const char *directory)
{
    struct stat status;

    if (lstat(directory, &status) < 0)
        return -errno;
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0077))
        return -EACCES;
    return 0;
}

static int melodi_tpm_secure_file(const char *path)
{
    struct stat status;

    if (lstat(path, &status) < 0)
        return -errno;
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0077))
        return -EACCES;
    return 0;
}

static int melodi_tpm_write_config(const char *path, uint32_t parent,
                                   uint32_t counter)
{
    uint8_t config[16];
    int descriptor;
    int error;

    memcpy(config, melodi_tpm_magic, sizeof(melodi_tpm_magic));
    melodi_tpm_store_u32(config + 8, parent);
    melodi_tpm_store_u32(config + 12, counter);
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0)
        return -errno;
    error = melodi_tpm_write_all(descriptor, config, sizeof(config));
    if (!error && fsync(descriptor) < 0)
        error = -errno;
    if (close(descriptor) < 0 && !error)
        error = -errno;
    if (error)
        unlink(path);
    return error;
}

static int melodi_tpm_read_config(const char *path, uint32_t *parent,
                                  uint32_t *counter)
{
    uint8_t config[17];
    size_t used = 0;
    int descriptor;
    int error;

    error = melodi_tpm_secure_file(path);
    if (error)
        return error;
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0)
        return -errno;
    while (used < sizeof(config)) {
        ssize_t received = read(descriptor, config + used,
                                sizeof(config) - used);

        if (received < 0) {
            if (errno == EINTR)
                continue;
            error = -errno;
            goto out;
        }
        if (!received)
            break;
        used += (size_t)received;
    }
    if (used != 16 || memcmp(config, melodi_tpm_magic,
                             sizeof(melodi_tpm_magic))) {
        error = -EINVAL;
        goto out;
    }
    *parent = melodi_tpm_load_u32(config + 8);
    *counter = melodi_tpm_load_u32(config + 12);
    if (*parent < MELODI_TPM_PARENT_MIN ||
        *parent > MELODI_TPM_PARENT_MAX ||
        *counter < MELODI_TPM_COUNTER_MIN ||
        *counter > MELODI_TPM_COUNTER_MAX)
        error = -EINVAL;
out:
    close(descriptor);
    return error;
}

static int melodi_tpm_format_handle(char text[11], uint32_t handle)
{
    int length = snprintf(text, 11, "0x%08x", handle);

    return length == 10 ? 0 : -EINVAL;
}

static void melodi_tpm_remove_parent(const char *parent, const char *owner_auth)
{
    char *const arguments[] = {
        "tpm2_evictcontrol", "-Q", "-C", "o", "-c", (char *)parent,
        "-P", (char *)owner_auth, NULL,
    };

    melodi_tpm_run(arguments, NULL, 0, NULL, 0, NULL);
}

static void melodi_tpm_remove_counter(const char *counter,
                                      const char *owner_auth)
{
    char *const arguments[] = {
        "tpm2_nvundefine", "-Q", "-C", "o", "-P", (char *)owner_auth,
        (char *)counter, NULL,
    };

    melodi_tpm_run(arguments, NULL, 0, NULL, 0, NULL);
}

int melodi_tpm_provision(const char *directory, uint32_t parent_handle,
                         uint32_t counter_handle, const char *owner_auth_path,
                         const uint8_t private_key[32])
{
    uint8_t sealed_identity[48] = { 0 };
    char config_path[PATH_MAX];
    char context_path[PATH_MAX];
    char private_path[PATH_MAX];
    char public_path[PATH_MAX];
    char parent[11];
    char counter[11];
    char owner_auth[PATH_MAX + 6];
    char *create_primary[] = {
        "tpm2_createprimary", "-Q", "-C", "o", "-G", "ecc", "-g",
        "sha256", "-c", context_path, "-P", owner_auth, NULL,
    };
    char *persist_parent[] = {
        "tpm2_evictcontrol", "-Q", "-C", "o", "-c", context_path,
        "-P", owner_auth, parent, NULL,
    };
    char *create_identity[] = {
        "tpm2_create", "-Q", "-C", parent, "-g", "sha256", "-i", "-",
        "-u", public_path, "-r", private_path, NULL,
    };
    char *define_counter[] = {
        "tpm2_nvdefine", "-Q", "-C", "o", "-s", "8", "-a",
        "ownerread|ownerwrite|authread|authwrite|nt=counter", "-P",
        owner_auth, counter, NULL,
    };
    int directory_descriptor = -1;
    mode_t previous_umask;
    bool parent_created = false;
    bool counter_created = false;
    int error;

    if (!directory || !owner_auth_path || !private_key ||
        parent_handle < MELODI_TPM_PARENT_MIN ||
        parent_handle > MELODI_TPM_PARENT_MAX ||
        counter_handle < MELODI_TPM_COUNTER_MIN ||
        counter_handle > MELODI_TPM_COUNTER_MAX)
        return -EINVAL;
    error = melodi_tpm_secure_file(owner_auth_path);
    if (!error) {
        int length = snprintf(owner_auth, sizeof(owner_auth), "file:%s",
                              owner_auth_path);

        if (length < 0 || (size_t)length >= sizeof(owner_auth))
            error = -ENAMETOOLONG;
    }
    if (!error)
        error = melodi_tpm_format_handle(parent, parent_handle);
    if (!error)
        error = melodi_tpm_format_handle(counter, counter_handle);
    if (!error)
        error = melodi_tpm_path(config_path, directory, "config");
    if (!error)
        error = melodi_tpm_path(context_path, directory, ".primary.ctx");
    if (!error)
        error = melodi_tpm_path(private_path, directory, "identity.priv");
    if (!error)
        error = melodi_tpm_path(public_path, directory, "identity.pub");
    if (error)
        return error;
    previous_umask = umask(0077);
    if (mkdir(directory, 0700) < 0) {
        umask(previous_umask);
        return -errno;
    }
    directory_descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (directory_descriptor < 0) {
        error = -errno;
        goto out;
    }
    memcpy(sealed_identity, melodi_tpm_seal_magic,
           sizeof(melodi_tpm_seal_magic));
    melodi_tpm_store_u32(sealed_identity + 8, parent_handle);
    melodi_tpm_store_u32(sealed_identity + 12, counter_handle);
    memcpy(sealed_identity + 16, private_key, 32);
    error = melodi_tpm_run(create_primary, NULL, 0, NULL, 0, NULL);
    if (error)
        goto out;
    error = melodi_tpm_run(persist_parent, NULL, 0, NULL, 0, NULL);
    if (error)
        goto out;
    parent_created = true;
    error = melodi_tpm_run(create_identity, sealed_identity,
                           sizeof(sealed_identity), NULL, 0, NULL);
    if (error)
        goto out;
    if (chmod(private_path, 0600) < 0 || chmod(public_path, 0600) < 0) {
        error = -errno;
        goto out;
    }
    error = melodi_tpm_run(define_counter, NULL, 0, NULL, 0, NULL);
    if (error)
        goto out;
    counter_created = true;
    error = melodi_tpm_write_config(config_path, parent_handle,
                                    counter_handle);
    if (!error && fsync(directory_descriptor) < 0)
        error = -errno;
out:
    unlink(context_path);
    if (error) {
        if (counter_created)
            melodi_tpm_remove_counter(counter, owner_auth);
        if (parent_created)
            melodi_tpm_remove_parent(parent, owner_auth);
        unlink(config_path);
        unlink(private_path);
        unlink(public_path);
    }
    if (directory_descriptor >= 0)
        close(directory_descriptor);
    if (error)
        rmdir(directory);
    explicit_bzero(sealed_identity, sizeof(sealed_identity));
    umask(previous_umask);
    return error;
}

int melodi_tpm_reserve(const char *directory, uint8_t private_key[32],
                       uint32_t *generation)
{
    uint8_t counter_bytes[8];
    uint8_t sealed_identity[48] = { 0 };
    char config_path[PATH_MAX];
    char context_path[PATH_MAX];
    char private_path[PATH_MAX];
    char public_path[PATH_MAX];
    char parent[11];
    char counter[11];
    char *increment[] = {
        "tpm2_nvincrement", "-Q", "-C", counter, counter, NULL,
    };
    char *read_counter[] = {
        "tpm2_nvread", "-Q", "-C", counter, "-s", "8", "-o",
        "/dev/stdout", counter, NULL,
    };
    char *load_identity[] = {
        "tpm2_load", "-Q", "-C", parent, "-u", public_path, "-r",
        private_path, "-c", context_path, NULL,
    };
    char *unseal[] = {
        "tpm2_unseal", "-Q", "-c", context_path, "-o", "/dev/stdout",
        NULL,
    };
    uint64_t reserved = 0;
    uint32_t parent_handle = 0;
    uint32_t counter_handle = 0;
    size_t output_length = 0;
    int temporary;
    int error;
    unsigned int index;

    if (!directory || !private_key || !generation)
        return -EINVAL;
    error = melodi_tpm_secure_directory(directory);
    if (!error)
        error = melodi_tpm_path(config_path, directory, "config");
    if (!error)
        error = melodi_tpm_path(private_path, directory, "identity.priv");
    if (!error)
        error = melodi_tpm_path(public_path, directory, "identity.pub");
    if (error)
        return error;
    error = melodi_tpm_read_config(config_path, &parent_handle,
                                   &counter_handle);
    if (!error)
        error = melodi_tpm_secure_file(private_path);
    if (!error)
        error = melodi_tpm_secure_file(public_path);
    if (!error)
        error = melodi_tpm_format_handle(parent, parent_handle);
    if (!error)
        error = melodi_tpm_format_handle(counter, counter_handle);
    if (error)
        return error;
    error = melodi_tpm_run(increment, NULL, 0, NULL, 0, NULL);
    if (error)
        return error;
    error = melodi_tpm_run(read_counter, NULL, 0, counter_bytes,
                           sizeof(counter_bytes), &output_length);
    if (error || output_length != sizeof(counter_bytes))
        return error ? error : -EPROTO;
    for (index = 0; index < sizeof(counter_bytes); index++)
        reserved = reserved << 8 | counter_bytes[index];
    if (!reserved || reserved > UINT32_MAX)
        return -EOVERFLOW;
    error = melodi_tpm_path(context_path, directory, ".identity.ctx.XXXXXX");
    if (error)
        return error;
    temporary = mkstemp(context_path);
    if (temporary < 0)
        return -errno;
    close(temporary);
    unlink(context_path);
    error = melodi_tpm_run(load_identity, NULL, 0, NULL, 0, NULL);
    if (!error) {
        output_length = 0;
        error = melodi_tpm_run(unseal, NULL, 0, sealed_identity,
                               sizeof(sealed_identity),
                               &output_length);
        if (!error &&
            (output_length != sizeof(sealed_identity) ||
             memcmp(sealed_identity, melodi_tpm_seal_magic,
                    sizeof(melodi_tpm_seal_magic)) ||
             melodi_tpm_load_u32(sealed_identity + 8) != parent_handle ||
             melodi_tpm_load_u32(sealed_identity + 12) != counter_handle))
            error = -EPROTO;
    }
    unlink(context_path);
    if (error)
        memset(private_key, 0, 32);
    else {
        memcpy(private_key, sealed_identity + 16, 32);
        *generation = (uint32_t)reserved;
    }
    explicit_bzero(sealed_identity, sizeof(sealed_identity));
    return error;
}
