//! The Named Binary Tag format.
//! https://minecraft.fandomtype_id.com/wiki/NBT_format
//! https://wiki.vg/NBT#level.dat
//! https://web.archive.org/web/20110723210920/http://www.minecraft.net/docs/NBT.txt

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
const fs = std.fs;
const fmt = std.fmt;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var nbt_file = try fs.cwd().openFile("im a flat earther/level.dat", .{ .mode = .read_only });
    //try nbt_file.do(gpa.allocator());
    std.debug.print("{any}\n", .{extractNBT(Level, gpa.allocator(), nbt_file)});
}

const Level = struct {
    // after https://github.com/ziglang/zig/issues/14534 is fixed, we should change this to @"" instead of having this special representation "empty" for empty strings
    empty: struct {
        Data: struct {
            hardcore: i8,
        },
    },
};

/// Extracts the NBT data into a struct.
/// Extracts only fields present in the struct type.
/// Field order does not matter.
pub fn extractNBT(comptime Type: type, allocator: mem.Allocator, file: fs.File) !Type {
    const file_reader = file.reader();
    // we should handle the case of the NBT data perhaps not actually being gzip'd (servers.dat for ex. is never gzip'd)
    var decompress = try compress.gzip.decompress(allocator, file_reader);
    defer decompress.deinit();
    const reader = decompress.reader();
    return try parseTag(Type, allocator, reader, true);
    //switch (try parseTag(allocator, reader, null)) {
    //    .End => {},
    //    .Compound => {
    //        //const length = try reader.readIntBig(u16);
    //        //// we should free this at some point
    //        //const string = try allocator.alloc(u8, length);
    //        // defer here?
    ////        for (0..length) |i|
    ////            string[i] = try reader.readByte();
    ////            log.info("tag name: \"{s}\"",.{string});
    ////
    //           var value: Type = undefined;
    //           while (true) {
    //               const length = try reader.readIntBig(u16);
    //               std.debug.print("length: {}\n", .{length});
    //               const name = try allocator.alloc(u8, length);
    //               defer allocator.free(name);
    //               for (0..length) |i|
    //                   name[i] = try reader.readByte();

    //               inline for (@"struct".fields) |field| {
    //                   std.debug.print("\"{s}\", \"{s}\"\n", .{ field.name, name });
    //                   // after https://github.com/ziglang/zig/issues/14534 is fixed, remove this special case of having this representation "empty" for empty strings
    //                   if (mem.eql(u8, field.name, name) or (mem.eql(u8, field.name, "empty") and name.len == 0)) {
    //                       @field(value, field.name) = try parse(field.type, allocator, reader, true);
    //                   } else {
    //                       // Ignore the value.
    //                       try parse(null, allocator, reader, true);
    //                   }
    //               }
    //           }
    //    },
    //    else => {},
    //}
    //return undefined;
    //switch (Type) {
    //    .i8 => {
    //        return try reader.readByteSigned();
    //    },
    //}
    //inline for (@typeInfo(Type).Struct.fields) |field| {
    //    @compileLog(field.type);
    //    //switch (field.type) {
    //    //    .struct => {},
    //    //}
    //}
}

//fn parse(comptime Type: type,allocator: mem.Allocator, reader: anytype) !Type {
//    switch (Type) {
//        i8 => return (try parseTag(allocator,reader,.Byte)).Byte,
//        i16 => return (try parseTag(allocator,reader,.Short)).Short,
//        i32 => return (try parseTag(allocator,reader,.Int)).Int,
//        i64 => return (try parseTag(allocator,reader,.Long)).Long,
//        f32 => return (try parseTag(allocator, reader, .Float)).Float,
//        f64 => return (try parseTag(allocator, reader, .Double)).Double,
//        []const i8 => return (try parseTag(allocator, reader, .ByteArray)).ByteArray,
//        []const u8 => return (try parseTag(allocator, reader, .String)).String,
//        []const i32 => return (try parseTag(allocator, reader, .IntArray)).IntArray,
//        []const i64 => return (try parseTag(allocator, reader, .LongArray)).LongArray,
//        else => {
//            switch (@typeInfo(Type)) {
//                .Pointer => |pointer| {
//                    switch (pointer.size) {
//                        .Slice => { // List
//                            //try expect(reader, .List);
//                            //try expectTagType(pointer.child, reader);
//_ = (try parseTag(allocator, reader, .List)).List;
//                            const length = try reader.readIntBig(i32);
//                            if (length <= 0) {
//                                //  If the length of the list is 0 or negative, the type may be 0 (TAG_End) but otherwise it must be any other type. (The notchian implementation uses TAG_End in that situation, but another reference implementation by Mojang uses 1 instead; parsers should accept any type if the length is <= 0).
//                                unreachable;
//                            }
//                            const slice = allocator.alloc(pointer.child, length);
//                            for (0..length) |i|
//                                slice[i] = try parse(pointer.child, allocator, reader, false);
//                            return slice;
//                        },
//                        else => comptime unreachable,
//                    }
//                },
//                .Struct => |@"struct"| { // Compound
//                    //@compileLog(@"struct");
//                    //try expect(reader, .Compound);
//                    //const tag_type = try meta.intToEnum(Tag,try reader.readByte());
//                    //std.debug.print("a: {}\n",.{tag_type});
//
//                    var value: Type = undefined;
//
//                    while (true) {
//                        const length = try reader.readIntBig(u16);
//                        std.debug.print("length: {}\n", .{length});
//                        const name = try allocator.alloc(u8, length);
//                        defer allocator.free(name);
//                        for (0..length) |i|
//                            name[i] = try reader.readByte();
//
//                        inline for (@"struct".fields) |field| {
//                            std.debug.print("\"{s}\", \"{s}\"\n", .{ field.name, name });
//                            // after https://github.com/ziglang/zig/issues/14534 is fixed, remove this special case of having this special representation "empty" for empty strings
//                            if (mem.eql(u8, field.name, name) or (mem.eql(u8, field.name, "empty") and name.len == 0)) {
//                                @field(value, field.name) = try parse(field.type, allocator, reader);
//                            } else {
//                                // Ignore the value.
//                                try parse(null, allocator, reader, true);
//                            }
//                        }
//                    }
//
//                    return value;
//                },
//                else => @compileError("bad type " ++ @typeName(Type)),
//            }
//        },
//    }
//    //switch (try parseTag(allocator, reader, null)) {
//    //    //.End => {},
//    //    .Compound => {
//    //        //const length = try reader.readIntBig(u16);
//    //        //// we should free this at some point
//    //        //const string = try allocator.alloc(u8, length);
//    //        // defer here?
//    ////        for (0..length) |i|
//    ////            string[i] = try reader.readByte();
//    ////            log.info("tag name: \"{s}\"",.{string});
//    ////
//    //           var value: Type = undefined;
//    //           while (true) {
//    //               const length = try reader.readIntBig(u16);
//    //               std.debug.print("length: {}\n", .{length});
//    //               const name = try allocator.alloc(u8, length);
//    //               defer allocator.free(name);
//    //               for (0..length) |i|
//    //                   name[i] = try reader.readByte();
//
//    //               inline for (@"struct".fields) |field| {
//    //                   std.debug.print("\"{s}\", \"{s}\"\n", .{ field.name, name });
//    //                   // after https://github.com/ziglang/zig/issues/14534 is fixed, remove this special case of having this representation "empty" for empty strings
//    //                   if (mem.eql(u8, field.name, name) or (mem.eql(u8, field.name, "empty") and name.len == 0)) {
//    //                       @field(value, field.name) = try parse(field.type, allocator, reader, true);
//    //                   } else {
//    //                       // Ignore the value.
//    //                       try parse(null, allocator, reader, true);
//    //                   }
//    //               }
//    //           }
//    //    },
//    //    else => return error.UnexpectedTag,
//    //}
//}

const TagType = enum(u8) {
    End,
    Byte,
    Short,
    Int,
    Long,
    Float,
    Double,
    ByteArray,
    String,
    List,
    Compound,
    IntArray,
    LongArray,
};

//const Tag = union(TagType) {
//    End,
//    Byte: i8,
//    Short: i16,
//    Int: i32,
//    Long: i64,
//    Float: f32,
//    Double: f64,
//    ByteArray: []const i8,
//    String: []const u8,
//    //List: []const Tag,
//    List,
//    Compound,
//    IntArray: []const i32,
//    LongArray: []const i64,
//};
//
//
//fn parseTag(allocator: mem.Allocator, reader: anytype, maybe_tag_type: ?TagType) !Tag {
//    const tag_type = maybe_tag_type orelse try meta.intToEnum(TagType, try reader.readByte());
//    log.info("parsing tag of type {}", .{tag_type});
//    switch (tag_type) {
//        .End => return .End,
//        .Byte => return .{ .Byte = try reader.readByteSigned() },
//        .Short => return .{ .Short = try reader.readIntBig(i16) },
//        .Int => return .{ .Int = try reader.readIntBig(i32) },
//        .Long => return .{ .Long = try reader.readIntBig(i64) },
//        .Float => return .{ .Float = @bitCast(f32, try reader.readIntBig(u32)) },
//        .Double => return .{ .Double = @bitCast(f64, try reader.readIntBig(u64)) },
//        .ByteArray => {
//            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
//            // we should free this at some point
//            const byte_array = try allocator.alloc(i8, length);
//            for (0..length) |i|
//                byte_array[i] = try reader.readByteSigned();
//            return .{ .ByteArray = byte_array };
//        },
//        .String => {
//            const length = try reader.readIntBig(u16);
//            // we should free this at some point
//            const string = try allocator.alloc(u8, length);
//            for (0..length) |i|
//                string[i] = try reader.readByte();
//            return .{ .String = string };
//        },
//        .List => return .List,
//        //.List => {
//        //    const list_tag_type = try meta.intToEnum(TagType, try reader.readByte());
//        //    const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
//        //    if (length <= 0) {
//        //        //  If the length of the list is 0 or negative, the type may be 0 (TAG_End) but otherwise it must be any other type. (The notchian implementation uses TAG_End in that situation, but another reference implementation by Mojang uses 1 instead; parsers should accept any type if the length is <= 0).
//        //        unreachable;
//        //    }
//        //    const list = try allocator.alloc(Tag, length);
//        //    for (0..length) |i|
//        //        list[i] = try parseTag(allocator, reader, list_tag_type);
//        //    return .{ .List = list };
//        //},
//        .Compound => return .Compound,
//        .IntArray => {
//            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
//            // we should free this at some point
//            const int_array = try allocator.alloc(i32, length);
//            for (0..length) |i|
//                int_array[i] = try reader.readIntBig(i32);
//            return .{ .IntArray = int_array };
//        },
//        .LongArray => {
//            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
//            // we should free this at some point
//            const long_array = try allocator.alloc(i64, length);
//            for (0..length) |i|
//                long_array[i] = try reader.readIntBig(i64);
//            return .{ .LongArray = long_array };
//        },
//    }
//}

fn expectTagType(comptime Type: type, reader: anytype) !void {
    const expect = struct {
        fn expect(expect_reader: anytype, expect_tag_type: TagType) !void {
            if (try expect_reader.readByte() != @intFromEnum(expect_tag_type)) return error.UnexpectedTagID;
        }
    }.expect;
    switch (Type) {
        i8 => try expect(reader, .Byte),
        i16 => try expect(reader, .Short),
        i32 => try expect(reader, .Int),
        i64 => try expect(reader, .Long),
        f32 => try expect(reader, .Float),
        f64 => try expect(reader, .Double),
        []const i8 => try expect(reader, .ByteArray),
        []const u8 => try expect(reader, .String),
        []const i32 => try expect(reader, .IntArray),
        []const i64 => try expect(reader, .LongArray),
        else => switch (@typeInfo(Type)) {
            .Pointer => |pointer| switch (pointer.size) {
                .Slice => {
                    try expect(reader, .List);
                },
                else => @compileError("bad type " ++ @typeName(Type)),
            },
            .Struct => try expect(reader, .Compound),
            else => @compileError("bad type " ++ @typeName(Type)),
        },
    }
}

// it seems like it may be possible for there to be a negative length (for example for List) but for now we assume that never happens
fn skipTag(reader: anytype, maybe_tag_type: ?TagType) !void {
    const tag_type = maybe_tag_type orelse try meta.intToEnum(TagType, try reader.readByte());
    log.info("tag type to skip: {}", .{tag_type});
    switch (tag_type) {
        .End => {
            unreachable;
        },
        .Byte => try reader.skipBytes(1, .{}),
        .Short => try reader.skipBytes(2, .{}),
        .Int => try reader.skipBytes(4, .{}),
        .Long => try reader.skipBytes(8, .{}),
        .Float => try reader.skipBytes(4, .{}),
        .Double => try reader.skipBytes(8, .{}),
        .ByteArray => {
            const length = math.cast(u64, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            try reader.skipBytes(length * @sizeOf(i8), .{});
        },
        .String => {
            const length = try reader.readIntBig(u16);
            try reader.skipBytes(length * @sizeOf(u8), .{});
        },
        .List => {
            const list_tag_type = try meta.intToEnum(TagType, try reader.readByte());
            log.info("list tag type to skip: {}", .{list_tag_type});
            const length = math.cast(u64, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            log.info("list length: {}", .{length});
            if (length > 0 and list_tag_type == .End) return error.InvalidListTagType;
            for (0..length) |_| try skipTag(reader, list_tag_type);
        },
        .Compound => {
            const length = try reader.readIntBig(u16);
            for (0..length) |_| {
                log.info("skipping {c}", .{try reader.readByte()});
            }
            //try reader.skipBytes(length, .{});
            try skipTag(reader, null);
            unreachable;
        },
        .IntArray => {
            const length = math.cast(u64, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            try reader.skipBytes(length * @sizeOf(i32), .{});
        },
        .LongArray => {
            const length = math.cast(u64, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            try reader.skipBytes(length * @sizeOf(i64), .{});
        },
    }
}

// it seems like it may be possible for there to be a negative length (for example for List) but for now we assume that never happens (and error if it does)
fn parseTag(comptime Type: type, allocator: mem.Allocator, reader: anytype, expect_tag_type: bool) !Type {
    std.debug.print("parsing {}\n", .{Type});
    if (expect_tag_type) try expectTagType(Type, reader);
    switch (Type) {
        i8 => return try reader.readByteSigned(), // Byte
        i16 => return try reader.readIntBig(i16), // Short
        i32 => return try reader.readIntBig(i32), // Int
        i64 => return try reader.readIntBig(i64), // Long
        f32 => return @as(f32, @bitCast(try reader.readIntBig(u32))), // Float
        f64 => return @as(f64, @bitCast(try reader.readIntBig(u64))), // Double
        []const i8 => { // Byte Array
            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            // we should free this at some point
            const slice = try allocator.alloc(i8, length);
            for (0..length) |i|
                slice[i] = try reader.readByteSigned();
            return slice;
        },
        // I would like to use a distinct type String for this which is []const u8 but so that []const u8 wouldn't work here and I have to use String
        // https://github.com/ziglang/zig/issues/1595
        // (and maybe for all other types too in this context)
        []const u8 => { // String
            const length = try reader.readIntBig(u16);
            // we should free this at some point
            const slice = try allocator.alloc(u8, length);
            for (0..length) |i|
                slice[i] = try reader.readByte();
            return slice;
        },
        []const i32 => { // Int Array
            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            _ = length;
            comptime unreachable;
        },
        []const i64 => { // Long Array
            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
            _ = length;
            comptime unreachable;
        },
        else => {
            switch (@typeInfo(Type)) {
                .Pointer => |pointer| {
                    switch (pointer.size) {
                        .Slice => { // List
                            //try expect(reader, .List);
                            try expectTagType(pointer.child, reader);
                            const length = math.cast(usize, try reader.readIntBig(i32)) orelse return error.NegativeLength;
                            // Here we should ensure the tag type is not End if the length is > 0 but that's already handled by the expectTagType above and because we don't map End to any type.
                            const slice = allocator.alloc(pointer.child, length);
                            for (0..length) |i|
                                slice[i] = try parseTag(pointer.child, allocator, reader, false);
                            return slice;
                        },
                        else => comptime unreachable,
                    }
                },
                .Struct => |@"struct"| { // Compound
                    var value: Type = undefined;

                    while (true) {
                        const length = try reader.readIntBig(u16);
                        std.debug.print("length: {}\n", .{length});
                        const name = try allocator.alloc(u8, length);
                        defer allocator.free(name);
                        for (0..length) |i|
                            name[i] = try reader.readByte();

                        inline for (@"struct".fields) |field| {
                            std.debug.print("\"{s}\", \"{s}\"\n", .{ field.name, name });
                            // after https://github.com/ziglang/zig/issues/14534 is fixed, remove this special case of having this representation "empty" for empty strings
                            if (mem.eql(u8, field.name, name) or (mem.eql(u8, field.name, "empty") and name.len == 0)) {
                                @field(value, field.name) = try parseTag(field.type, allocator, reader, true);
                            } else {
                                // Ignore the value.
                                try skipTag(reader, null);
                            }
                        }
                    }

                    return value;
                },
                else => @compileError("bad type " ++ @typeName(Type)),
            }
        },
    }
}
