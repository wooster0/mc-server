// parse/get the config using std.zig.Ast.parse("{}", .zon) or @import("cfg.zon") depending on a comptime flag on how the user wants to do it (perf vs ease of use) (and apply both to a common Config struct so code is the same for both)
// or use JSON simply because MC uses it too and it's well known (in that case still do this; just parse JSON at comptime. @embedFile or read file depending on how the user wants it)
// so, advanced users can boost the server performance by recompiling the server using *comptime-known config values*. this is a unique possibility offered only really by zig.

// for text, it'd be cool if color can be abstracted to work on the terminal as well as in the game using ampersands and or section signs

const std = @import("std");

const net = std.net;
const log = std.log;
const leb = std.leb;
const testing = std.testing;
const assert = std.debug.assert;
const meta = std.meta;
const math = std.math;
const json = std.json;
const compress = std.compress;
const mem = std.mem;
const io = std.io;
const time = std.time;

/// https://wiki.vg/Protocol_version_numbers
const ProtocolVersion = enum(i32) {
    /// https://wiki.vg/Protocol&oldid=7368
    @"1.8" = 47,

    /// https://wiki.vg/Protocol
    _,

    pub fn jsonStringify(
        value: ProtocolVersion,
        options: json.StringifyOptions,
        out_stream: anytype,
    ) !void {
        _ = options;
        try out_stream.print("{d}", .{@enumToInt(value)});
    }
};

/// https://wiki.vg/Server_List_Ping
const Status = struct {
    version: struct { name: []const u8, protocol: ProtocolVersion },
    players: struct { max: u32, online: u32, sample: ?[]const struct { name: []const u8, id: []const u8 } },
    description: struct { text: []const u8 },
    favicon: ?[]const u8,
};

pub fn main() !void {
    var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    var server = Server{};
    try server.run(allocator.allocator());
}

threadlocal var json_buffer = std.BoundedArray(u8, 2048){};

fn JSONStringify(writer: anytype, value: anytype) !void {
    try json.stringify(
        value,
        .{ .whitespace = null, .emit_null_optional_fields = false, .string = .{ .String = .{} } },
        writer,
    );
}

const Server = struct {
    const Client = struct {
        stream: net.Stream,
        state: State = .handshake,
        packet_buffer: std.ArrayListUnmanaged(u8) = .{},
        protocol_version: ProtocolVersion = undefined,
        keep_alive_send_timer: time.Timer,
        keep_alive_receive_timer: time.Timer,
        keep_alive_id: i32 = 0, //std.math.minInt(i32),

        const State = enum(u2) {
            /// https://wiki.vg/Protocol#Handshake
            handshake,
            /// https://wiki.vg/Protocol_FAQ#What_does_the_normal_status_ping_sequence_look_like.3F
            status = 1,
            /// 1.8: https://wiki.vg/index.php?title=Protocol_FAQ&oldid=8231#What.27s_the_normal_login_sequence_for_a_client.3F
            /// Other: https://wiki.vg/Protocol_FAQ#What.27s_the_normal_login_sequence_for_a_client.3F
            login = 2,
            play,
        };

        const KeepOrTerminate = enum { keep, terminate };

        fn init(stream: net.Stream) !Client {
            return .{
                .stream = stream,
                // we should perhaps move this into a play() and then start these timers.
                .keep_alive_send_timer = time.Timer.start() catch {
                    // this can be made more user-friendly
                    @panic("unsupported environment");
                },
                .keep_alive_receive_timer = time.Timer.start() catch {
                    // this can be made more user-friendly
                    @panic("unsupported environment");
                },
            };
        }

        fn handle(client: *Client, allocator: mem.Allocator) void {
            while (true) {
                var keep_or_terminate = client.receivePacket(allocator) catch |err| {
                    log.err("handling packet: {}", .{err});
                    continue;
                };
                switch (keep_or_terminate) {
                    .keep => {},
                    .terminate => {
                        client.stream.close();
                        break;
                    },
                }
                keep_or_terminate = client.handleKeepAlive(allocator) catch |err| {
                    log.err("sending Keep Alive: {}", .{err});
                    continue;
                };
                switch (keep_or_terminate) {
                    .keep => {},
                    .terminate => {
                        client.stream.close();
                        break;
                    },
                }
            }
        }

        fn handleKeepAlive(client: *Client, allocator: mem.Allocator) !KeepOrTerminate {
            if (client.state != .play) return .keep;

            // this timer should perhaps be started only after the first keep alive is sent. use null.
            if (client.keep_alive_receive_timer.read() > 30 * time.ns_per_s) {
                log.warn("kicking client. for example their internet connection might've died", .{});
                return .terminate;
            }

            // If the server does not send any keep-alives for 20 seconds, the client will disconnect and yields a "Timed out" exception.
            if (client.keep_alive_send_timer.read() >= 10 * time.ns_per_s) {
                defer client.keep_alive_send_timer.reset();
                // We should figure out what is preventing us here from just sending 0 as the Keep Alive ID every time.
                // and what's the benefit of sending the millisecond timestamp instead of just incrementing an ID every time?
                // What's the best kind of ID to send?
                //const keep_alive_id = @truncate(i32, try math.absInt(time.milliTimestamp()));
                log.info("sending Keep Alive with ID {d}", .{client.keep_alive_id});
                const packet_writer = client.packet_buffer.writer(allocator);
                try writeVarInt(packet_writer, client.keep_alive_id); // Keep Alive ID
                client.keep_alive_id +%= 1;
                try client.sendPacket(0x00);
            }

            return .keep;
        }

        fn receivePacket(client: *Client, allocator: mem.Allocator) !KeepOrTerminate {
            // The meaning of a packet depends both on its packet ID and the current state of the connection.

            // not supporting or handling compression for now
            const packet_reader = client.stream.reader();

            std.debug.print("\n", .{});
            log.debug("receiving packet...", .{});
            const length = readVarInt(packet_reader) catch |err| {
                if (err == error.EndOfStream) {
                    // The player probably disconnected.
                    return .terminate;
                }
                return err;
            }; // Length
            if (length == 0xfe) { // Legacy Server List Ping
                // Only clients before 1.7.0 send this.
                log.info("legacy packet received", .{});
                log.info("{s}", .{try packet_reader.readBytesNoEof(100)});
                return .terminate;
            }
            log.debug("length: {}", .{length});
            // Packets cannot be larger than 2097151 bytes (the maximum that can be sent in a 3-byte VarInt).
            if (length > std.math.maxInt(u21)) return error.PacketTooBig;

            const packet_id = try readVarInt(packet_reader); // Packet ID
            log.debug("Packet ID: 0x{x:0>2}", .{math.cast(u31, packet_id) orelse return error.InvalidPacketID});

            switch (client.state) {
                .play => return client.handlePlay(allocator, packet_id, length),
                .login => return client.handleLogin(allocator, packet_id),
                .status => return client.handleStatus(allocator, packet_id),
                .handshake => return client.handleHandshake(packet_id),
            }
        }

        fn handleHandshake(client: *Client, packet_id: i32) !KeepOrTerminate {
            const packet_reader = client.stream.reader();
            switch (packet_id) {
                0x00 => { // Handshake
                    log.info("handling Handshake", .{});

                    const protocol_version = @intToEnum(ProtocolVersion, try readVarInt(packet_reader)); // Protocol Version
                    client.protocol_version = protocol_version;
                    log.debug("protocol_version: {}", .{protocol_version});

                    var buf: [255]u8 = undefined;
                    const server_address = try readString(packet_reader, &buf); // Server Address
                    log.debug("server_address: {s}", .{server_address});
                    if (mem.endsWith(u8, server_address, "FML\x00")) log.debug("Forge Mod Loader in use", .{});

                    const server_port = try readUnsignedShort(packet_reader); // Server Port
                    log.debug("server_port: {}", .{server_port});

                    const next_state = try meta.intToEnum(State, try readVarInt(packet_reader)); // Next State
                    log.debug("next_state: {}", .{next_state});
                    client.state = next_state;

                    return .keep;
                },
                else => return error.UnexpectedHandshakePacketID,
            }
        }

        fn handleStatus(client: *Client, allocator: mem.Allocator, packet_id: i32) !KeepOrTerminate {
            const packet_reader = client.stream.reader();
            const packet_writer = client.packet_buffer.writer(allocator);
            switch (packet_id) {
                0x00 => { // Status Request
                    log.info("handling Status Request", .{});

                    const section_sign = "§";

                    // Status Response
                    try JSONStringify(
                        json_buffer.writer(),
                        Status{
                            .version = .{ .name = "1.8", .protocol = .@"1.8" },
                            .players = .{ .max = 420, .online = 69, .sample = null },
                            .description = .{ .text = std.fmt.comptimePrint("hi {s}4wow this is red", .{section_sign}) },
                            .favicon = null,
                        },
                    );
                    defer json_buffer.len = 0;
                    try writeString(packet_writer, json_buffer.constSlice()); // JSON Response
                    try client.sendPacket(0x00);

                    return .keep;
                },
                0x01 => { // Ping Request
                    log.info("handling Ping Request", .{});

                    // Ping Response
                    const payload = try readLong(packet_reader); // Payload
                    try writeLong(packet_writer, payload); // Payload
                    try client.sendPacket(0x01);

                    return .terminate;
                },
                else => return error.UnexpectedStatusPacketID,
            }
        }

        fn handleLogin(client: *Client, allocator: mem.Allocator, packet_id: i32) !KeepOrTerminate {
            const packet_reader = client.stream.reader();
            const packet_writer = client.packet_buffer.writer(allocator);
            switch (packet_id) {
                0x00 => { // Login Start
                    log.info("handling Login Start", .{});

                    var buf: [16]u8 = undefined;
                    const name = try readString(packet_reader, &buf); // Name
                    log.info("> {s} wants to join the minecraft server", .{name});

                    if (client.protocol_version != .@"1.8") {
                        // Disconnect
                        try writeChat(packet_writer, .{ .text = "Please use 1.8.X to join the Minecraft server." }); // Reason
                        try client.sendPacket(0x00);

                        return .terminate;
                    } else {
                        // Login Success (no encryption/authentication for now)
                        try writeString(packet_writer, "00000000-0000-0000-0000-000000000000"); // UUID (not sure what I'm supposed to pass here; are we supposed to make this up?)
                        try writeString(packet_writer, name); // Username
                        try client.sendPacket(0x02);

                        client.state = .play;

                        // Join Game
                        try writeInt(packet_writer, 1337); // Entity ID
                        try writeUnsignedByte(packet_writer, 0); // Gamemode
                        try writeByte(packet_writer, 0); // Dimension
                        try writeUnsignedByte(packet_writer, 2); // Difficulty
                        try writeUnsignedByte(packet_writer, 2); // Max Players (can't be more than 255? what's up with that? clamp to 255?)
                        try writeString(packet_writer, "default"); // Level Type
                        try writeBoolean(packet_writer, false); // Reduced Debug Info
                        try client.sendPacket(0x01);

                        // Spawn Position
                        try writePosition(packet_writer, .{ .x = 0, .y = 0, .z = 0 }); // Location
                        try client.sendPacket(0x05);

                        // Player Abilities
                        try writeByte(packet_writer, 0b0000_0000); // Flags
                        try writeFloat(packet_writer, 0); // Flying Speed
                        try writeFloat(packet_writer, 10); // Field of View Modifier
                        try client.sendPacket(0x39);

                        // Player Position And Look
                        try writeDouble(packet_writer, 0); // X
                        try writeDouble(packet_writer, 0); // Y
                        try writeDouble(packet_writer, 0); // Z
                        try writeFloat(packet_writer, 0); // Yaw
                        try writeFloat(packet_writer, 0); // Pitch
                        try writeByte(packet_writer, 0b0000_0000); // Flags
                        try client.sendPacket(0x08);

                        return .keep;
                    }
                },
                else => return error.UnexpectedLoginPacketID,
            }
        }

        fn handlePlay(client: *Client, allocator: mem.Allocator, packet_id: i32, packet_length: i32) !KeepOrTerminate {
            const packet_reader = client.stream.reader();
            const packet_writer = client.packet_buffer.writer(allocator);
            _ = packet_writer;
            switch (packet_id) {
                0x00 => { // Keep Alive
                    const keep_alive_id = try readVarInt(packet_reader); // Keep Alive ID
                    log.info("received Keep Alive with ID {d}", .{keep_alive_id});

                    if (keep_alive_id != client.keep_alive_id - 1)
                        log.warn("the received Keep Alive ID is probably not the one we sent", .{});

                    client.keep_alive_receive_timer.reset();

                    return .keep;
                },
                0x03 => { // Player
                    log.info("received Player", .{});

                    const on_ground = try readBoolean(packet_reader); // On Ground
                    log.info("player On Ground: {}", .{on_ground});

                    return .keep;
                },
                0x04 => { // Player Position
                    log.info("received Player Position", .{});

                    const x = try readDouble(packet_reader); // X
                    log.info("player X: {d}", .{x});
                    const feet_y = try readDouble(packet_reader); // Feet Y
                    log.info("player Feet Y: {d}", .{feet_y});
                    const z = try readDouble(packet_reader); // Z
                    log.info("player Z: {d}", .{z});
                    const on_ground = try readBoolean(packet_reader); // On Ground
                    log.info("player On Ground: {}", .{on_ground});

                    return .keep;
                },
                0x05 => { // Player Look
                    log.info("received Player Look", .{});

                    const yaw = try readFloat(packet_reader); // Yaw
                    log.info("player Yaw: {d}", .{yaw});
                    const pitch = try readFloat(packet_reader); // Pitch
                    log.info("player Pitch: {d}", .{pitch});
                    const on_ground = try readBoolean(packet_reader); // On Ground
                    log.info("player On Ground: {}", .{on_ground});

                    return .keep;
                },
                0x06 => { // Player Position And Look
                    log.info("received Player Position And Look", .{});

                    const x = try readDouble(packet_reader); // X
                    log.info("player X: {d}", .{x});
                    const feet_y = try readDouble(packet_reader); // Feet Y
                    log.info("player Feet Y: {d}", .{feet_y});
                    const z = try readDouble(packet_reader); // Z
                    log.info("player Z: {d}", .{z});
                    const yaw = try readFloat(packet_reader); // Yaw
                    log.info("player Yaw: {d}", .{yaw});
                    const pitch = try readFloat(packet_reader); // Pitch
                    log.info("player Pitch: {d}", .{pitch});
                    const on_ground = try readBoolean(packet_reader); // On Ground
                    log.info("player On Ground: {}", .{on_ground});

                    return .keep;
                },
                0x15 => { // Client Settings
                    var buf: [16]u8 = undefined;
                    const locale = try readString(packet_reader, &buf); // Locale
                    log.info("player uses this language for their client: {s}", .{locale});
                    const view_distance = try readByte(packet_reader); // View Distance
                    log.info("this is their view distance: {}", .{view_distance});
                    const chat_mode = try readByte(packet_reader); // Chat Mode
                    log.info("Chat Mode: {}", .{chat_mode});
                    const chat_colors = try readBoolean(packet_reader); // Chat Colors
                    log.info("can the person see colors in chat? {}", .{chat_colors});
                    const displayed_skin_parts = try readUnsignedByte(packet_reader); // Displayed Skin Parts
                    log.info("displayed_skin_parts: {}", .{displayed_skin_parts});

                    return .keep;
                },
                0x17 => { // Plugin Message
                    var buf: [1024]u8 = undefined; // not sure about this buf size
                    var counting_packet_reader = io.countingReader(packet_reader);
                    const channel = try readString(counting_packet_reader.reader(), &buf); // Channel
                    log.info("Plugin Message channel: {s}", .{channel});
                    log.warn("ignoring Plugin Message content. also see length above", .{});
                    // we still need to look at all bytes of this Byte Array before we can continue.
                    // this is not very elegant.
                    var packet_id_bytes = std.BoundedArray(u8, 5){};
                    try writeVarInt(packet_id_bytes.writer(), packet_id);
                    const data_length = ((math.cast(u64, packet_length) orelse return error.NegativePacketLength) - counting_packet_reader.bytes_read - packet_id_bytes.len);
                    try packet_reader.skipBytes(data_length, .{}); // Data

                    return .keep;
                },
                else => return error.UnexpectedPlayPacketID,
            }
        }

        /// Sends off all data in `packet_buffer` to the client.
        fn sendPacket(client: *Client, id: i32) !void {
            var id_bytes = std.BoundedArray(u8, 5){};
            try writeVarInt(id_bytes.writer(), id);
            const stream_writer = client.stream.writer();
            try writeVarInt(stream_writer, @intCast(i32, id_bytes.len + client.packet_buffer.items.len)); // Length of Packet ID + Data
            try stream_writer.writeAll(id_bytes.constSlice()); // Packet ID
            try stream_writer.writeAll(client.packet_buffer.items); // Data (they call this a Byte Array)
            client.packet_buffer.items.len = 0;
        }
    };

    fn run(server: *Server, allocator: mem.Allocator) !void {
        _ = server;
        var tcp_server = net.StreamServer.init(.{ .reuse_address = true });
        defer tcp_server.deinit();
        const address = net.Address.initIp4(
            .{ 127, 0, 0, 1 },
            // see "Minecraft (Java Edition) multiplayer server" on https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
            25565,
            // this port should later only be used as a fallback/default. it allows the user to access the server with just "localhost" in the game
        );
        try tcp_server.listen(address);
        log.info("listening on {}", .{address});
        while (true) {
            // `accept` is thread-safe and accepting clients can be parallelized.
            // and we should pair that with async/await to process another client while waiting for something in a different client.
            const connection = tcp_server.accept() catch |err| {
                log.err("accepting connection: {}", .{err});
                continue;
            };
            log.info("new client: {}", .{connection});
            var client = try Client.init(connection.stream);
            client.handle(allocator);
        }
    }
};

//
// 1.8: https://wiki.vg/index.php?title=Data_types&oldid=7250
// Other: https://wiki.vg/Data_types
//

fn readBoolean(reader: anytype) !bool {
    return switch (try reader.readByte()) {
        0 => false,
        1 => true,
        else => error.UnexpectedBooleanValue,
    };
}
fn writeBoolean(writer: anytype, value: bool) !void {
    try writer.writeByte(@boolToInt(value));
}

// there is readByteSigned in the std but not writeByteSigned...
fn readByte(reader: anytype) !i8 {
    return @bitCast(i8, try reader.readByte());
}
fn writeByte(writer: anytype, value: i8) !void {
    try writer.writeByte(@bitCast(u8, value));
}

fn readUnsignedByte(reader: anytype) !u8 {
    return try reader.readByte();
}
fn writeUnsignedByte(writer: anytype, value: u8) !void {
    try writer.writeByte(value);
}

fn readUnsignedShort(reader: anytype) !u16 {
    return try reader.readIntBig(u16);
}

fn writeInt(writer: anytype, value: i32) !void {
    try writer.writeIntBig(i32, value);
}

fn readLong(reader: anytype) !i64 {
    return try reader.readIntBig(i64);
}
fn writeLong(writer: anytype, value: i64) !void {
    try writer.writeIntBig(i64, value);
}

fn readFloat(reader: anytype) !f32 {
    return @bitCast(f32, try reader.readIntBig(u32));
}
fn writeFloat(writer: anytype, value: f32) !void {
    try writer.writeIntBig(u32, @bitCast(u32, value));
}

fn readDouble(reader: anytype) !f64 {
    return @bitCast(f64, try reader.readIntBig(u64));
}
fn writeDouble(writer: anytype, value: f64) !void {
    try writer.writeIntBig(u64, @bitCast(u64, value));
}

fn readString(reader: anytype, buf: []u8) ![]const u8 {
    // would be nice if math cast returned error.Underflow and error.Overflow
    const len: u15 = math.cast(u15, try readVarInt(reader)) orelse return error.StringTooBig; // Maximum length is 32767.
    for (0..len) |i| {
        buf[i] = try reader.readByte();
    }
    return buf[0..len];
}
fn writeString(writer: anytype, buf: []const u8) !void {
    try writeVarInt(writer, @intCast(u15, buf.len)); // Maximum length is 32767.
    try writer.writeAll(buf);
}

const Chat = struct {
    text: []const u8,
};

fn writeChat(writer: anytype, chat: Chat) !void {
    try JSONStringify(json_buffer.writer(), chat);
    defer json_buffer.len = 0;
    try writeString(writer, json_buffer.constSlice()); // JSON Response
}

const segment_bits = 0x7F;
const continue_bit = 0x80;

fn readVarInt(reader: anytype) !i32 {
    var value: i32 = 0;
    var position: u5 = 0;
    while (true) {
        const byte = try reader.readByte();
        value |= (@intCast(i32, byte) & segment_bits) << position;
        if ((byte & continue_bit) == 0) break;
        position = math.add(u5, position, 7) catch return error.VarIntTooBig;
    }
    return value;
}
fn writeVarInt(writer: anytype, value: i32) !void {
    var value_unsigned = @bitCast(u32, value);
    while (true) {
        if (value_unsigned & ~@as(u32, segment_bits) == 0) {
            try writer.writeByte(@intCast(u8, value_unsigned));
            break;
        }
        try writer.writeByte(@intCast(u8, (value_unsigned & segment_bits) | continue_bit));
        value_unsigned >>= 7;
    }
}

fn readVarLong(reader: anytype) !i64 {
    var value: i64 = 0;
    var position: u6 = 0;
    while (true) {
        const byte = try reader.readByte();
        value |= (@intCast(i64, byte) & segment_bits) << position;
        if ((byte & continue_bit) == 0) break;
        position = math.add(u6, position, 7) catch return error.VarLongTooBig;
    }
    return value;
}
fn writeVarLong(writer: anytype, value: i64) !void {
    var value_unsigned = @bitCast(u64, value);
    while (true) {
        if (value_unsigned & ~@as(u64, segment_bits) == 0) {
            try writer.writeByte(@intCast(u8, value_unsigned));
            break;
        }
        try writer.writeByte(@intCast(u8, (value_unsigned & segment_bits) | continue_bit));
        value_unsigned >>= 7;
    }
}

const Position = packed struct(u64) {
    x: i26,
    y: i12,
    z: i26,
};

fn writePosition(writer: anytype, position: Position) !void {
    try writer.writeStruct(position);
}

fn readUUID(reader: anytype) !u128 {
    return try reader.readIntBig(u128);
}
fn writeUUID(writer: anytype, value: u128) !void {
    try writer.writeIntBig(u128, value);
}

fn testReadVarInt(bytes: []const u8, expected: i32) !void {
    var buf = io.FixedBufferStream([]const u8){ .buffer = bytes, .pos = 0 };
    try testing.expectEqual(expected, try readVarInt(buf.reader()));
}

test readVarInt {
    try testReadVarInt(&.{0x00}, 0);
    try testReadVarInt(&.{0x01}, 1);
    try testReadVarInt(&.{0x02}, 2);
    try testReadVarInt(&.{0x7f}, 127);
    try testReadVarInt(&.{ 0x80, 0x01 }, 128);
    try testReadVarInt(&.{ 0xff, 0x01 }, 255);
    try testReadVarInt(&.{ 0xdd, 0xc7, 0x01 }, 25565);
    try testReadVarInt(&.{ 0xff, 0xff, 0x7f }, 2097151);
    try testReadVarInt(&.{ 0xff, 0xff, 0xff, 0xff, 0x07 }, 2147483647);
    try testReadVarInt(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f }, -1);
    try testReadVarInt(&.{ 0x80, 0x80, 0x80, 0x80, 0x08 }, -2147483648);
}

fn testReadVarLong(bytes: []const u8, expected: i64) !void {
    var buf = io.FixedBufferStream([]const u8){ .buffer = bytes, .pos = 0 };
    try testing.expectEqual(expected, try readVarLong(buf.reader()));
}

test readVarLong {
    try testReadVarLong(&.{0x00}, 0);
    try testReadVarLong(&.{0x01}, 1);
    try testReadVarLong(&.{0x02}, 2);
    try testReadVarLong(&.{0x7f}, 127);
    try testReadVarLong(&.{ 0x80, 0x01 }, 128);
    try testReadVarLong(&.{ 0xff, 0x01 }, 255);
    try testReadVarLong(&.{ 0xff, 0xff, 0xff, 0xff, 0x07 }, 2147483647);
    try testReadVarLong(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 9223372036854775807);
    try testReadVarLong(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }, -1);
    try testReadVarLong(&.{ 0x80, 0x80, 0x80, 0x80, 0xf8, 0xff, 0xff, 0xff, 0xff, 0x01 }, -2147483648);
    try testReadVarLong(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }, -9223372036854775808);
}
