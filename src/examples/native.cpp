/* SPDX-License-Identifier: GPL-2.0-only */
extern "C" {
#include "client.h"
}

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <net/if.h>
#include <string_view>

int main(int argc, char **argv)
{
    unsigned char buffer[8192];
    melodi_received_message received{};
    melodi_node_id destination{};
    melodi_socket socket_state{};
    char source[MELODI_NODE_ID_STRING_SIZE];
    char *end;
    int error;

    socket_state.descriptor = -1;

    if (argc != 6)
        return 2;
    unsigned int ifindex = if_nametoindex(argv[1]);
    unsigned long local_service = std::strtoul(argv[2], &end, 10);
    if (!ifindex || *end || local_service == 0 ||
        local_service >= MELODI_SERVICE_ECHO)
        return 2;
    error = melodi_nodeid_parse(argv[3], std::strlen(argv[3]), &destination);
    unsigned long destination_service = std::strtoul(argv[4], &end, 10);
    if (error || *end || destination_service == 0 ||
        destination_service >= MELODI_SERVICE_ECHO)
        return 2;
    error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, local_service);
    if (!error)
        error = melodi_client_send(&socket_state, &destination,
                                   destination_service, argv[5],
                                   std::strlen(argv[5]),
                                   MELODI_F_AUTH_REQUIRED, 1);
    if (!error)
        error = melodi_client_receive(&socket_state, buffer, sizeof(buffer),
                                      &received);
    if (!error)
        error = melodi_nodeid_format(&received.source, source);
    if (!error)
        std::cout << source << ' ' << received.source_service << ": "
                  << std::string_view(
                         reinterpret_cast<const char *>(received.payload),
                         received.payload_length)
                  << '\n';
    melodi_socket_close(&socket_state);
    if (error)
        std::cerr << argv[0] << ": " << std::strerror(-error) << '\n';
    return error ? 1 : 0;
}
