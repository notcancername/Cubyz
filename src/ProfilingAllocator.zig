// TODO: check lengths and alignments
// TODO: use generics for compile-time constants
// TODO: save and check allocating threads
const std = @import("std");
const Allocator = std.mem.Allocator;
const ProfilingAllocator = @This();

const nb_stack_frames = 4;

pub const AllocInfo = struct {
	len: usize,
	// stack trace of the invocation with the largest length
	stackTrace: [nb_stack_frames:0]usize,
};

/// Must be thread-safe for the profiling allocator to be thread-safe.
backingAllocator: std.mem.Allocator,
/// Need not be thread-safe.
metadataAllocator: std.mem.Allocator,
baseToAllocInfo: std.AutoArrayHashMapUnmanaged(usize, AllocInfo),
mutex: std.Thread.Mutex,
/// Allocations below this length will not have their call stacks recorded.
///
/// This value cannot be changed thread-safely, set it once before any
/// allocations.
stackTraceLowBound: usize = 16 << 10,
/// Allocations below this length will not be tracked at all.
///
/// This value cannot be changed thread-safely, set it once before any
/// allocations.
trackLowBound: usize = 512,
/// Whether to avoid checking for memory errors. Much faster in highly
/// contended scenarios.
///
/// This value cannot be changed thread-safely, set it once before any
/// allocations.
ignoreMemoryErrors: bool = false,
/// The total number of bytes allocated at any given time, not
/// including allocations smaller than `trackLowBound`. This value may
/// be read without locking the mutex.
totalBytesAllocated: std.atomic.Value(usize) = .init(0),


pub const vtable: Allocator.VTable = .{
	.alloc = alloc,
	.resize = resize,
	.remap = remap,
	.free = free,
};

pub fn allocator(pa: *ProfilingAllocator) Allocator {
	return .{
		.ptr = @ptrCast(pa),
		.vtable = &vtable,
	};
}

pub fn init(backingAllocator: std.mem.Allocator, metadataAllocator: std.mem.Allocator) ProfilingAllocator {
	return .{
		.backingAllocator = backingAllocator,
		.metadataAllocator = metadataAllocator,
		.baseToAllocInfo = .{},
		.mutex = .{},
	};
}

pub fn deinit(pa: *ProfilingAllocator) void {
	std.debug.assert(pa.mutex.tryLock()); // not thread-safe
	pa.baseToAllocInfo.deinit(pa.metadataAllocator);
	pa.mutex.unlock(); // crash contended threads
	pa.* = undefined;
}

pub fn alloc(
	ctx: *anyopaque,
	len: usize,
	alignment: std.mem.Alignment,
	retAddr: usize,
) ?[*]u8 {
	const traceAddr = if(retAddr == 0) @returnAddress() else retAddr;
	const pa: *ProfilingAllocator = @ptrCast(@alignCast(ctx));

	var allocInfo: AllocInfo = .{
		.len = len,
		.stackTrace = undefined,
	};

	var trace: std.builtin.StackTrace = .{
		.index = 0,
		.instruction_addresses = &allocInfo.stackTrace,
	};

	if(len >= pa.trackLowBound and len >= pa.stackTraceLowBound) {
		std.debug.captureStackTrace(traceAddr, &trace);
		allocInfo.stackTrace[trace.index] = 0;
	} else {
		allocInfo.stackTrace[0] = traceAddr;
		allocInfo.stackTrace[1] = 0;
	}

	if (!pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (!pa.ignoreMemoryErrors) pa.mutex.unlock();

	const res = pa.backingAllocator.rawAlloc(
		len,
		alignment,
		traceAddr,
	) orelse return null;

	if(len < pa.trackLowBound) return res;

	_ = pa.totalBytesAllocated.fetchAdd(len, .monotonic);
	
	if (pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (pa.ignoreMemoryErrors) pa.mutex.unlock();

	pa.baseToAllocInfo.put(pa.metadataAllocator, @intFromPtr(res), allocInfo) catch |err| {
		std.log.err("failed to put allocation profile metadata, expect incorrect warnings: {}", .{err});
	};

	return res;
}

pub fn resize(
	ctx: *anyopaque,
	memory: []u8,
	alignment: std.mem.Alignment,
	newLen: usize,
	retAddr: usize,
) bool {
	const traceAddr = if(retAddr == 0) @returnAddress() else retAddr;
	const pa: *ProfilingAllocator = @ptrCast(@alignCast(ctx));

	var traceBuf: [nb_stack_frames:0]usize = undefined;
	var trace: std.builtin.StackTrace = .{
		.index = 0,
		.instruction_addresses = &traceBuf,
	};

	if(memory.len < newLen) {
		if (newLen >= pa.trackLowBound and newLen >= pa.stackTraceLowBound) {
			std.debug.captureStackTrace(traceAddr, &trace);
			traceBuf[trace.index] = 0;
		} else {
			traceBuf[0] = traceAddr;
			traceBuf[1] = 0;
		}
	}

	if (!pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (!pa.ignoreMemoryErrors) pa.mutex.unlock();

	const res = pa.backingAllocator.rawResize(
		memory,
		alignment,
		newLen,
		traceAddr,
	);
	if(!res) return res;

	if(newLen < pa.trackLowBound) return res;

	// TODO: replace with cmpxchg
	_ = pa.totalBytesAllocated.fetchSub(memory.len, .monotonic);
	_ = pa.totalBytesAllocated.fetchAdd(newLen, .monotonic);

	if (pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (pa.ignoreMemoryErrors) pa.mutex.unlock();

	const gop = pa.baseToAllocInfo.getOrPutAssumeCapacity(@intFromPtr(memory.ptr));
	if(!gop.found_existing and !pa.ignoreMemoryErrors and memory.len >= pa.trackLowBound) {
		std.debug.panic("resize after free / wild resize of {x}[0..{d}]", .{@intFromPtr(memory.ptr), memory.len});
	}
	gop.value_ptr.len = newLen;
	if(memory.len < newLen)
		gop.value_ptr.stackTrace = traceBuf;

	return res;
}

pub fn remap(
	ctx: *anyopaque,
	memory: []u8,
	alignment: std.mem.Alignment,
	newLen: usize,
	retAddr: usize,
) ?[*]u8 {
	const traceAddr = if(retAddr == 0) @returnAddress() else retAddr;
	const pa: *ProfilingAllocator = @ptrCast(@alignCast(ctx));

	var traceBuf: [nb_stack_frames:0]usize = undefined;
	var trace: std.builtin.StackTrace = .{
		.index = 0,
		.instruction_addresses = &traceBuf,
	};

	if(newLen >= pa.trackLowBound and newLen >= pa.stackTraceLowBound) {
		std.debug.captureStackTrace(traceAddr, &trace);
		traceBuf[trace.index] = 0;
	} else {
		traceBuf[0] = traceAddr;
		traceBuf[1] = 0;
	}

	if (!pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (!pa.ignoreMemoryErrors) pa.mutex.unlock();

	const res = pa.backingAllocator.rawRemap(
		memory,
		alignment,
		newLen,
		traceAddr,
	) orelse return null;

	if(newLen < pa.trackLowBound) return res;

	_ = pa.totalBytesAllocated.fetchSub(memory.len, .monotonic);
	_ = pa.totalBytesAllocated.fetchAdd(newLen, .monotonic);
	
	if (pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (pa.ignoreMemoryErrors) pa.mutex.unlock();

	if(memory.len >= pa.trackLowBound and !pa.ignoreMemoryErrors and !pa.baseToAllocInfo.swapRemove(@intFromPtr(memory.ptr))) {
		std.debug.panic("remap after free / wild remap of {x}[0..{d}]", .{@intFromPtr(memory.ptr), memory.len});
	}
	pa.baseToAllocInfo.putAssumeCapacity(@intFromPtr(res), .{
		.len = newLen,
		.stackTrace = traceBuf,
	});

	return res;
}

pub fn free(
	ctx: *anyopaque,
	memory: []u8,
	alignment: std.mem.Alignment,
	retAddr: usize
) void {
	const traceAddr = if(retAddr == 0) @returnAddress() else retAddr;
	const pa: *ProfilingAllocator = @ptrCast(@alignCast(ctx));

	if (!pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (!pa.ignoreMemoryErrors) pa.mutex.unlock();

	pa.backingAllocator.rawFree(memory, alignment, traceAddr);

	if(memory.len < pa.trackLowBound) return;

	_ = pa.totalBytesAllocated.fetchSub(memory.len, .monotonic);

	if (pa.ignoreMemoryErrors) pa.mutex.lock();
	defer if (pa.ignoreMemoryErrors) pa.mutex.unlock();

	if(!pa.baseToAllocInfo.swapRemove(@intFromPtr(memory.ptr)) and !pa.ignoreMemoryErrors) {
		std.debug.panic("double free / wild free of {x}[0..{d}]", .{@intFromPtr(memory.ptr), memory.len});
	}
}

pub const Aggregation = enum {
	full_trace,
	first_addr,
};

/// Aggregate the total number of bytes allocated in `by` and put the
/// result to `into`. Returns the total number of bytes allocated.
pub fn aggregate(
	pa: *ProfilingAllocator,
	by: []const Aggregation,
	into: []std.StringArrayHashMapUnmanaged(usize),
	aggregationAllocator: std.mem.Allocator,
) !usize {
	const initialGuess = get_guess: {
		pa.mutex.lock();
		pa.mutex.unlock();
		break :get_guess pa.baseToAllocInfo.entries.len;
	};
	var copiedInfos: std.ArrayListUnmanaged(AllocInfo) = .empty;
	defer copiedInfos.deinit(aggregationAllocator);
	try copiedInfos.ensureTotalCapacity(aggregationAllocator, initialGuess);

	{
		pa.mutex.lock();
		pa.mutex.unlock();
		try copiedInfos.ensureTotalCapacity(aggregationAllocator, pa.baseToAllocInfo.entries.len);
		copiedInfos.appendSliceAssumeCapacity(pa.baseToAllocInfo.values());
	}

	@memset(into, .{});

	for(copiedInfos.items) |info| {
		for (into, by) |*dest, agg| {
			const key = switch (agg) {
				.full_trace => dupe: {
					const bytes = std.mem.sliceAsBytes(std.mem.span(info.stackTrace[0..].ptr));
					const duped = try aggregationAllocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(@alignOf(usize)), bytes.len);
					@memcpy(duped, bytes);
					break :dupe duped;
				},
				.first_addr => @panic("TODO"),
			};
			const gop = try dest.getOrPut(aggregationAllocator, key);
			if (gop.found_existing) {
				aggregationAllocator.free(key);
			} else {
				gop.value_ptr.* = 0;
			}
			gop.value_ptr.* += info.len;
		}
	}
	
	return pa.totalBytesAllocated.load(.monotonic);
}

pub const SortContext = struct {
	hashes: []u32,
	keys: [][]const u8,
	vals: []usize,

	pub fn lessThan(ctx: SortContext, a: usize, b: usize) bool {
		return ctx.vals[a] > ctx.vals[b];
	}

	pub fn swap(ctx: SortContext, a: usize, b: usize) void {
		std.mem.swap(u32, &ctx.hashes[a], &ctx.hashes[b]);
		std.mem.swap([]const u8, &ctx.keys[a], &ctx.keys[b]);
		std.mem.swap(usize, &ctx.vals[a], &ctx.vals[b]);
	}
};

pub fn dumpAggregates(pa: *ProfilingAllocator, aggregationAllocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
	var agg: std.StringArrayHashMapUnmanaged(usize) = .{};
	defer agg.deinit(aggregationAllocator);
	defer for(agg.keys()) |k| {
		aggregationAllocator.free(k);
	};

	const total_bytes_allocated = try pa.aggregate(&.{.full_trace}, @ptrCast(&agg), aggregationAllocator);

	std.sort.insertionContext(0, agg.entries.len, SortContext{
		.hashes = agg.entries.items(.hash),
		.keys = agg.keys(),
		.vals = agg.values(),
	});
	try agg.reIndex(aggregationAllocator);

	try writer.print("Total memory allocated: {Bi}\nMemory consumption by call stack:\n", .{total_bytes_allocated});

	for (agg.keys(), agg.values(), 0..) |key, val, i| {
		const addrs = std.mem.bytesAsSlice(usize, key);
		const trace: std.builtin.StackTrace = .{
			.index = addrs.len,
			.instruction_addresses = @alignCast(@constCast(addrs)),
		};

		try writer.print("#{d}: {Bi}\n{f}\n", .{i, val, trace});
	}
}
