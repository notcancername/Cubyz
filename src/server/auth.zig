const std = @import("std");

var socket: std.net.Stream = undefined;
var mutex: std.Thread.Mutex = .{};

pub fn globalInit() !void {
	var buf: [512 << 10]u8 = undefined;
	var fba = std.heap.FixedBufferAllocator.init(&buf);
	socket = try std.net.tcpConnectToHost(fba.allocator(), "127.0.0.1", 42071);
}

pub fn globalDeinit() void {
	socket.close();
	socket = undefined;
}

fn globalReinit() !void {
	globalDeinit();
	try globalInit();
}

const AuthResponse = enum(u8) {
	/// The password is correct.
	success = 0,
	/// The password is incorrect.
	failure = 1,
	/// The username does not exist.
	unregistered = 2,
	_,
};


/// Verifies that `password` is correct for `user`.
pub fn verify(username: []const u8, password: []const u8) !void {
	if(@max(username.len, password.len) > std.math.maxInt(u16))
		return error.DataTooLong;
	var buf: [4]u8 = undefined;

	std.mem.writeInt(u16, buf[0..2], @intCast(username.len), .little);
	std.mem.writeInt(u16, buf[2..][0..2], @intCast(password.len), .little);

	mutex.lock();
	defer mutex.unlock();

	var iovecs: [3]std.posix.iovec_const = .{
		.{.base = &buf, .len = buf.len},
		.{.base = username.ptr, .len = username.len},
		.{.base = password.ptr, .len = password.len},
	};
	socket.writevAll(&iovecs) catch |err| {
		std.log.err("password verify send failed: {}", .{err});
		try globalReinit();
		return err;
	};

	var res: AuthResponse = undefined;
	const n = socket.readAtLeast(std.mem.asBytes(&res), @sizeOf(AuthResponse)) catch |err| {
		std.log.err("password verify recv failed: {}", .{err});
		try globalReinit();
		return err;
	};

	if (n == 0) {
		std.log.err("password verify recv read zero bytes", .{});
		try globalReinit();
		return error.Disconnected;
	}
	
	return switch(res) {
		.success => {},
		.failure => error.IncorrectPassword,
		.unregistered => error.Unregistered,
		else => |v| {
			std.log.err("server sent unknown auth response: 0x{x}", .{@intFromEnum(v)});
			try globalReinit();
			return error.Unexpected;
		},
	};
}
