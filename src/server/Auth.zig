const std = @import("std");
const Auth = @This();

// this style gives me cancer
const globalAllocator = @import("main").globalAllocator;

pub const Request = extern struct {
	usernameLenLe: u16 = 0,
	passwordLenLe: u16 = 0,
	username: [256 - @sizeOf(u16)]u8 = undefined,
	password: [256 - @sizeOf(u16)]u8 = undefined,

	pub fn getUsernameLen(req: *const Request) u16 {
		return std.mem.littleToNative(u16, req.usernameLenLe);
	}

	pub fn getPasswordLen(req: *const Request) u16 {
		return std.mem.littleToNative(u16, req.passwordLenLe);
	}

	pub fn totalLen(req: *const Request) usize {
		return @sizeOf(u16) * 2 + req.getUsernameLen() + req.getPasswordLen();
	}
	
	pub fn fromSlices(req: *Request, username: []const u8, password: []const u8) error{TooLong}!void {
		if(username.len > req.username.len or password.len > req.password.len)
			return error.TooLong;

		@memcpy(req.username[0..username.len], username);
		@memcpy(req.password[0..password.len], password);
		req.usernameLenLe = std.mem.nativeTo(u16, @intCast(username.len), .little);
		req.passwordLenLe = std.mem.nativeTo(u16, @intCast(password.len), .little);
	}
	
	pub fn asIovecs(req: *Request) [4]std.posix.iovec_const {
		const username_len = req.getUsernameLen();
		const password_len = req.getPasswordLen();
		
		const usernameLenLeBytes = std.mem.asBytes(&req.usernameLenLe);
		const passwordLenLeBytes = std.mem.asBytes(&req.passwordLenLe);

		return .{
			.{.base = usernameLenLeBytes, .len = usernameLenLeBytes.len},
			.{.base = passwordLenLeBytes, .len = passwordLenLeBytes.len},
			.{.base = &req.username, .len = username_len},
			.{.base = &req.password, .len = password_len},
		};
	}
};

const Response = enum(u8) {
	/// The password is correct.
	success = 0,
	/// The password is incorrect.
	failure = 1,
	/// The username does not exist.
	unregistered = 2,
	_,

	pub fn unwrap(res: Response) error{Unregistered, IncorrectPassword, Unexpected}!void {
		return switch(res) {
			.success => {},
			.failure => error.IncorrectPassword,
			.unregistered => error.Unregistered,
			else => |v| {
				std.log.err("server sent unknown auth response: 0x{x}", .{@intFromEnum(v)});
				return error.Unexpected;
			},
		};
	}
};

pub const QueueItem = struct {
	pub const Callback = fn (promise: *QueueItem) void;
	context: ?*anyopaque,
	/// Callback may be called from a different thread than
	/// `beginVerify`. Therefore, it must be thread-safe.
	callback: *const Callback,

	request: Request,
	request_byte_count_written: usize = 0,
	response: Response,
};

mutex: std.Thread.Mutex = .{},
socket: std.net.Stream = undefined,
queue: @import("main").ListUnmanaged(*QueueItem) = .{},

/// This must be passed a default-initialized `Auth`.
pub fn init(auth: *Auth) !void {
	var buf: [512 << 10]u8 = undefined;
	var fba = std.heap.FixedBufferAllocator.init(&buf);
	auth.socket = try std.net.tcpConnectToHost(fba.allocator(), "127.0.0.1", 42071);
	const old_flags = std.posix.fcntl(auth.socket.handle, std.posix.F.GETFL, 0) catch unreachable;
	_ = std.posix.fcntl(
		auth.socket.handle,
		std.posix.F.SETFL,
		old_flags | @as(u32, @bitCast(std.posix.O{.NONBLOCK = true})),
	) catch unreachable;
}

pub fn deinit(auth: *Auth) void {
	auth.socket.close();
	auth.socket = undefined;
}

fn reconnect(auth: *Auth) !void {
	auth.socket.close();
	try auth.init();
}

/// Verifies that `password` is correct for `user`.
pub fn beginVerify(auth: *Auth, context: ?*anyopaque, callback: *const QueueItem.Callback, username: []const u8, password: []const u8) error{TooLong}!void {
	auth.mutex.lock();
	defer auth.mutex.unlock();

	const item = globalAllocator.create(QueueItem);
	item.* = .{
		.context = context,
		.callback = callback,
		.request = undefined,
		.response = undefined,
	};
	try item.request.fromSlices(username, password);
	auth.queue.append(globalAllocator, item);
}

fn offsetIovecs(iovecs: []std.posix.iovec_const, n: usize) ?usize {
        var remaining: usize = n;
	var i: usize = 0;

	while (remaining >= iovecs[i].len) {
		remaining -= iovecs[i].len;
		i += 1;
		if (i >= iovecs.len) return null;
	}

	iovecs[i].base += remaining;
	iovecs[i].len -= remaining;

	return i;
}

pub fn drain(auth: *Auth) !void {
	auth.mutex.lock();
	defer auth.mutex.unlock();

	while (auth.queue.items.len > 0) {
		const last = auth.queue.items[auth.queue.items.len - 1];
		var req_iovecs = last.request.asIovecs();

		
		if (offsetIovecs(&req_iovecs, last.request_byte_count_written)) |start_index| {
			const n = auth.socket.writev(req_iovecs[start_index..]) catch |err| switch(err) {
				error.WouldBlock => {
					std.log.info("write would block", .{});
					break;
				},
				else => |e| {
					std.log.err("{} while writing auth packet", .{e});
					try auth.reconnect();
					last.request_byte_count_written = 0;
					continue;
				},
			};
			
			last.request_byte_count_written += n;

			if (offsetIovecs(&req_iovecs, n) != null)
				continue;
		}

		const n = auth.socket.readAll(std.mem.asBytes(&last.response)) catch |err| switch(err) {
			error.WouldBlock => {
				std.log.info("read would block", .{});
				break;
			},
			else => |e| {
				std.log.err("{} while reading auth packet", .{e});
				try auth.reconnect();
				last.request_byte_count_written = 0;
				continue;
			},
		};

		if (n != 1) {
			std.log.err("EOF while reading auth packet, retrying", .{});
			try auth.reconnect();
			last.request_byte_count_written = 0;
			continue;
		}

		_ = auth.queue.pop();
		last.callback(last);
		globalAllocator.destroy(last);
	}
}
