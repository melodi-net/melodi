// SPDX-License-Identifier: GPL-2.0-only
const std = @import("std");
const c = @cImport({
    @cInclude("client.h");
    @cInclude("net/if.h");
});

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 6) return error.InvalidArguments;
    const local = try std.fmt.parseInt(u16, arguments[2], 10);
    const destination_service = try std.fmt.parseInt(u16, arguments[4], 10);
    if (local == 0 or local == 65535 or destination_service == 0 or
        destination_service == 65535) return error.InvalidService;
    const interface = try allocator.dupeZ(u8, arguments[1]);
    defer allocator.free(interface);
    const ifindex = c.if_nametoindex(interface.ptr);
    if (ifindex == 0) return error.InterfaceNotFound;
    var destination: c.struct_melodi_node_id = std.mem.zeroes(c.struct_melodi_node_id);
    if (c.melodi_nodeid_parse(arguments[3].ptr, arguments[3].len,
        &destination) != 0) return error.InvalidNodeId;
    var socket: c.struct_melodi_socket = std.mem.zeroes(c.struct_melodi_socket);
    socket.descriptor = -1;
    if (c.melodi_socket_open(&socket) != 0) return error.SocketOpenFailed;
    defer c.melodi_socket_close(&socket);
    if (c.melodi_client_bind(&socket, ifindex, local) != 0)
        return error.BindFailed;
    if (c.melodi_client_send(&socket, &destination, destination_service,
        arguments[5].ptr, arguments[5].len, 1 << 2, 1) != 0)
        return error.SendFailed;
    var buffer: [8192]u8 = undefined;
    var received: c.struct_melodi_received_message =
        std.mem.zeroes(c.struct_melodi_received_message);
    if (c.melodi_client_receive(&socket, &buffer, buffer.len, &received) != 0)
        return error.ReceiveFailed;
    var source: [55]u8 = undefined;
    if (c.melodi_nodeid_format(&received.source, &source) != 0)
        return error.InvalidSource;
    const source_text = std.mem.sliceTo(&source, 0);
    const payload: [*]const u8 = @ptrCast(received.payload);
    std.debug.print("{s} {d}: {s}\n", .{
        source_text, received.source_service, payload[0..received.payload_length],
    });
}
