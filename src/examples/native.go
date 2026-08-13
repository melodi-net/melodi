// SPDX-License-Identifier: GPL-2.0-only
package main

/*
#include <stdlib.h>
#include <net/if.h>
#include "client.h"
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"
)

func run(arguments []string) int {
	if len(arguments) != 6 {
		return 2
	}
	interfaceName := C.CString(arguments[1])
	destinationText := C.CString(arguments[3])
	defer C.free(unsafe.Pointer(interfaceName))
	defer C.free(unsafe.Pointer(destinationText))
	local, localError := strconv.ParseUint(arguments[2], 10, 16)
	destinationService, destinationError := strconv.ParseUint(arguments[4], 10, 16)
	if localError != nil || destinationError != nil || local == 0 ||
		destinationService == 0 || local == 65535 || destinationService == 65535 {
		return 2
	}
	var destination C.struct_melodi_node_id
	var socket C.struct_melodi_socket
	socket.descriptor = -1
	var received C.struct_melodi_received_message
	buffer := make([]byte, 8192)
	errorCode := C.melodi_nodeid_parse(destinationText, C.size_t(len(arguments[3])),
		&destination)
	if errorCode == 0 {
		ifindex := C.if_nametoindex(interfaceName)
		if ifindex == 0 {
			errorCode = -19
		} else {
			errorCode = C.melodi_socket_open(&socket)
			if errorCode == 0 {
				errorCode = C.melodi_client_bind(&socket, C.uint32_t(ifindex),
					C.uint16_t(local))
			}
			if errorCode == 0 {
				message := []byte(arguments[5])
				var payload unsafe.Pointer
				if len(message) != 0 {
					payload = unsafe.Pointer(&message[0])
				}
				errorCode = C.melodi_client_send(&socket, &destination,
					C.uint16_t(destinationService), payload,
					C.size_t(len(message)), C.uint32_t(1<<2), 1)
			}
			if errorCode == 0 {
				errorCode = C.melodi_client_receive(&socket, unsafe.Pointer(&buffer[0]),
					C.size_t(len(buffer)), &received)
			}
		}
	}
	var source [55]C.char
	if errorCode == 0 {
		errorCode = C.melodi_nodeid_format(&received.source, &source[0])
	}
	if errorCode == 0 {
		payload := C.GoBytes(unsafe.Pointer(received.payload),
			C.int(received.payload_length))
		fmt.Printf("%s %d: %s\n", C.GoString(&source[0]),
			uint16(received.source_service), payload)
	}
	C.melodi_socket_close(&socket)
	if errorCode != 0 {
		fmt.Fprintf(os.Stderr, "melodi-example-go: error %d\n", int(errorCode))
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args))
}
