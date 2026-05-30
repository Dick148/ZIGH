// ZIGH — Unix Domain Socket IPC
// Binary TLV framing: [u16 msgType][u32 payloadLen][payload bytes]
// Payload is JSON

const std = @import("std");
const linux = std.os.linux;

const sockaddr_un = extern struct {
    family: linux.sa_family_t = linux.AF.UNIX,
    path: [108]u8 = [_]u8{0} ** 108,
};

pub const MsgType = enum(u16) {
    req_status = 0x01,
    req_lock_add = 0x10,
    req_lock_remove = 0x11,
    req_lock_list = 0x12,
    req_write = 0x20,
    req_read = 0x21,
    req_cheat_load = 0x30,
    req_cheat_start = 0x31,
    req_cheat_stop = 0x32,
    req_call = 0x40,
    req_inject = 0x50,
    req_ping = 0xFE,
    req_shutdown = 0xFF,
    res_ok = 0x80,
    res_err = 0x81,
    res_status = 0x82,
    res_read = 0x83,
    _,
};

pub const Header = packed struct {
    msg_type: u16,
    payload_len: u32,
};

const HEADER_SIZE = @sizeOf(Header);
const MAX_PAYLOAD = 65536;

pub fn Server(comptime Handler: type) type {
    return struct {
        fd: i32,
        path: [:0]const u8,
        handler: Handler,
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, path: [:0]const u8, handler: Handler) !Self {
            const fd = try createSocket(path);
            return Self{ .fd = fd, .path = path, .handler = handler, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            _ = linux.close(self.fd);
            _ = linux.unlink(self.path);
        }

        pub fn acceptOne(self: *Self) !void {
            const client_fd = linux.accept(self.fd, null, null);
            if (@as(isize, @bitCast(client_fd)) < 0) return;
            defer _ = linux.close(@intCast(client_fd));

            var buf: [MAX_PAYLOAD]u8 = undefined;
            const n = linux.read(@intCast(client_fd), &buf, buf.len);
            if (n < HEADER_SIZE) return;

            const header = std.mem.bytesAsValue(Header, buf[0..@sizeOf(Header)]);
            if (header.payload_len > MAX_PAYLOAD - HEADER_SIZE) return;

            const payload: []const u8 = buf[HEADER_SIZE..][0..header.payload_len];
            const msg_type: MsgType = @enumFromInt(header.msg_type);

            const response = try self.handler.handle(self.allocator, msg_type, payload);
            defer self.allocator.free(response);

            const resp_header = Header{
                .msg_type = @intFromEnum(MsgType.res_ok),
                .payload_len = @intCast(response.len),
            };
            var resp_buf: [HEADER_SIZE]u8 = undefined;
            @memcpy(&resp_buf, std.mem.asBytes(&resp_header));
            _ = linux.write(@intCast(client_fd), &resp_buf, resp_buf.len);
            _ = linux.write(@intCast(client_fd), response.ptr, response.len);
        }

        pub fn serve(self: *Self) !void {
            while (true) {
                self.acceptOne() catch |err| {
                    std.debug.print("[socket] accept error: {}\n", .{err});
                };
            }
        }
    };
}

pub const Client = struct {
    fd: i32,

    pub fn connect(path: [:0]const u8) !Client {
        const raw = linux.socket(@as(u32, linux.AF.UNIX), @as(u32, linux.SOCK.STREAM), 0);
        if (@as(isize, @bitCast(raw)) < 0) return error.ConnectFailed;
        const fd: i32 = @intCast(raw);

        var addr: sockaddr_un = undefined;
        @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(sockaddr_un)], 0);
        addr.family = linux.AF.UNIX;
        @memcpy(addr.path[0..path.len], path);
        const addr_len: linux.socklen_t = @intCast(@sizeOf(sockaddr_un));

        const rc = linux.connect(fd, @ptrCast(&addr), addr_len);
        if (@as(isize, @bitCast(rc)) < 0) {
            _ = linux.close(fd);
            return error.ConnectFailed;
        }
        return Client{ .fd = fd };
    }

    pub fn deinit(self: *Client) void {
        _ = linux.close(self.fd);
    }

    pub fn send(self: *Client, allocator: std.mem.Allocator, msg_type: MsgType, payload: []const u8) ![]u8 {
        const header = Header{
            .msg_type = @intFromEnum(msg_type),
            .payload_len = @intCast(payload.len),
        };
        var header_bytes: [HEADER_SIZE]u8 = undefined;
        @memcpy(&header_bytes, std.mem.asBytes(&header));
        _ = linux.write(self.fd, &header_bytes, header_bytes.len);
        if (payload.len > 0) {
            _ = linux.write(self.fd, payload.ptr, payload.len);
        }

        var resp_header: Header = undefined;
        const hn = linux.read(self.fd, @ptrCast(&resp_header), HEADER_SIZE);
        if (hn < HEADER_SIZE) return error.ReadFailed;

        const buf = try allocator.alloc(u8, resp_header.payload_len);
        var total: usize = 0;
        while (total < resp_header.payload_len) {
            const n = linux.read(self.fd, buf.ptr + total, resp_header.payload_len - total);
            if (n == 0) break;
            total += n;
        }
        return buf[0..total];
    }
};

fn createSocket(path: [:0]const u8) !i32 {
    const raw = linux.socket(@as(u32, linux.AF.UNIX), @as(u32, linux.SOCK.STREAM), 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.SocketCreateFailed;
    const fd: i32 = @intCast(raw);

    var addr: sockaddr_un = undefined;
    @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(sockaddr_un)], 0);
    addr.family = linux.AF.UNIX;
    @memcpy(addr.path[0..path.len], path);

    _ = linux.unlink(path);
    const addr_len: linux.socklen_t = @intCast(@sizeOf(sockaddr_un));
    const rc = linux.bind(fd, @ptrCast(&addr), addr_len);
    if (@as(isize, @bitCast(rc)) < 0) {
        _ = linux.close(fd);
        return error.BindFailed;
    }

    const lr = linux.listen(fd, 5);
    if (@as(isize, @bitCast(lr)) < 0) {
        _ = linux.close(fd);
        return error.ListenFailed;
    }

    return fd;
}
