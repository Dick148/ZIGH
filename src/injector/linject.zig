// ZIGH — Linux-style function-hijack injector
// Inspired by namazso/linux_injector (MIT license).
//
// This injector uses /proc/PID/mem to patch a remote libc function with
// mmap+spin shellcode. When the hijacked function is next called by any
// thread, the shellcode allocates rwx memory, signals completion via an
// atomically modified variable, then spins. The host detects completion,
// writes the real dlopen payload into the rwx allocation, and the
// shellcode exits its spin loop and executes the payload.
//
// Advantages over ptrace-based injection:
//   - No ptrace at all — works alongside GDB
//   - Uses the target's own mmap (no NX page search)
//   - Self-synchronizing across all threads via lock btsq spin
//   - Atomic restore of hijacked function

const std = @import("std");
const linux = std.os.linux;
const mem_mod = @import("../mem/mod.zig");
const util = @import("../util.zig");

// ─── Shellcode (x86_64 Linux) ─────────────────────────────────────────────

/// Phase 1 shellcode: mmap rwx, signal completion, spin until payload ready.
/// Written directly to a hijacked function body.
///
/// Layout (roughly):
///   lock btsq $0, <completion_var>     ; CAS lock
///   jc spin_begin                      ; retry if someone else has lock
///   push regs                          ; save ABI regs
///   xor edi, edi                       ; addr = 0
///   mov esi, <PATCH: alloc_len>        ; length
///   mov edx, 7                         ; PROT_READ|PROT_WRITE|PROT_EXEC
///   mov r10d, 0x22                     ; MAP_PRIVATE|MAP_ANONYMOUS
///   xor r8d, r8d                       ; fd = 0
///   xor r9d, r9d                       ; offset = 0
///   mov eax, 9                         ; __NR_mmap
///   syscall
///   or al, 1                           ; mark allocated
///   mov <PATCH: var>, rax              ; store allocation
///   xor al, al                         ; clear lock
///   mov word [rax], 0xfeeb            ; write jmp $ to allocation
///   jmp rax                            ; jump to allocation (spins)
///
/// The host then writes the real payload over the jmp $ and the spin exits.

const mmap_shell: [96]u8 = blk: {
    var buf: [96]u8 = [_]u8{0} ** 96;
    var p: usize = 0;

    // lock btsq $0, [rip+disp] — 10 bytes
    buf[p] = 0xf0; p += 1;
    buf[p] = 0x48; p += 1;
    buf[p] = 0x0f; p += 1;
    buf[p] = 0xba; p += 1;
    buf[p] = 0x2d; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 0, .little); p += 4; // PATCH: disp

    // jc rel8 — jump back to lock btsq (offset 0, jc ends at 12, rel8 = -12 = 0xf4)
    buf[p] = 0x72; p += 1;
    buf[p] = 0xf4; p += 1;

    // push rax,rdi,rsi,rdx,r10,r8,r9
    for ([_]u8{0x50, 0x57, 0x56, 0x52, 0x41, 0x52, 0x41, 0x50, 0x41, 0x51}) |b| {
        buf[p] = b; p += 1;
    }

    // xor edi,edi
    buf[p] = 0x31; p += 1;
    buf[p] = 0xff; p += 1;

    // mov esi, <alloc_len>
    buf[p] = 0xbe; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 0x10000, .little); p += 4; // PATCH

    // mov edx, 7
    buf[p] = 0xba; p += 1;
    std.mem.writeInt(u32, buf[p..][0..4], 7, .little); p += 4;

    // mov r10d, 0x22
    buf[p] = 0x41; p += 1;
    buf[p] = 0xba; p += 1;
    std.mem.writeInt(u32, buf[p..][0..4], 0x22, .little); p += 4;

    // xor r8d,r8d
    buf[p] = 0x45; p += 1;
    buf[p] = 0x31; p += 1;
    buf[p] = 0xc0; p += 1;

    // xor r9d,r9d
    buf[p] = 0x45; p += 1;
    buf[p] = 0x31; p += 1;
    buf[p] = 0xc9; p += 1;

    // mov eax, 9
    buf[p] = 0xb8; p += 1;
    std.mem.writeInt(u32, buf[p..][0..4], 9, .little); p += 4;

    // syscall
    buf[p] = 0x0f; p += 1;
    buf[p] = 0x05; p += 1;

    // or al, 1
    buf[p] = 0x0c; p += 1;
    buf[p] = 0x01; p += 1;

    // mov [rip+disp], rax
    buf[p] = 0x48; p += 1;
    buf[p] = 0x89; p += 1;
    buf[p] = 0x05; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 0, .little); p += 4; // PATCH

    // xor al, al
    buf[p] = 0x30; p += 1;
    buf[p] = 0xc0; p += 1;

    // mov word [rax], 0xfeeb
    buf[p] = 0x66; p += 1;
    buf[p] = 0xc7; p += 1;
    buf[p] = 0x00; p += 1;
    buf[p] = 0xeb; p += 1;
    buf[p] = 0xfe; p += 1;

    // jmp rax
    buf[p] = 0xff; p += 1;
    buf[p] = 0xe0; p += 1;

    while (p < buf.len) : (p += 1) { buf[p] = 0xcc; }

    break :blk buf;
};

/// Phase 2 shellcode: dlopen a .so from within the remote process.
/// Written into the mmap'd rwx region after Phase 1 completes.
///
/// Params are embedded inline after shellcode:
///   +0x00: p_dlopen (u64)
///   +0x08: p_oldfun (u64)
///   +0x10: flags (u64 = RTLD_NOW)
///   +0x18: path (NUL-terminated string)

const dlopen_shell: [44]u8 = blk: {
    var buf: [44]u8 = [_]u8{0} ** 44;
    var p: usize = 0;

    // nop; nop (alignment spacer)
    buf[p] = 0x66; p += 1;
    buf[p] = 0x90; p += 1;

    // mov rsi, [rip + 50]  — flags (rip=10, params+16=60, disp=50)
    buf[p] = 0x48; p += 1;
    buf[p] = 0x8b; p += 1;
    buf[p] = 0x35; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 50, .little); p += 4;

    // lea rdi, [rip + 50]  — path (rip=18, params+24=68, disp=50)
    buf[p] = 0x48; p += 1;
    buf[p] = 0x8d; p += 1;
    buf[p] = 0x3d; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 50, .little); p += 4;

    // call [rip + 20]  — dlopen (rip=24, params+0=44, disp=20)
    buf[p] = 0xff; p += 1;
    buf[p] = 0x15; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 20, .little); p += 4;

    // pop r9; r8; r10; rdx; rsi; rdi; rax
    for ([_]u8{ 0x41, 0x59, 0x41, 0x58, 0x41, 0x5a, 0x5a, 0x5e, 0x5f, 0x58 }) |b| {
        buf[p] = b; p += 1;
    }

    // jmp [rip + 10]  — p_oldfun (rip=42, params+8=52, disp=10)
    buf[p] = 0xff; p += 1;
    buf[p] = 0x25; p += 1;
    std.mem.writeInt(i32, buf[p..][0..4], 10, .little); p += 4;

    break :blk buf;
};

const PARAMS_SIZE = 8 + 8 + 8; // p_dlopen + p_oldfun + flags
const DLOPEN_HEADER_SIZE = dlopen_shell.len + PARAMS_SIZE;
const SHELL_MAX = mmap_shell.len;

// ─── Helpers ──────────────────────────────────────────────────────────────

fn openProcMem(pid: u32) !linux.fd_t {
    var buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buf, "/proc/{d}/mem", .{pid});
    const raw = linux.open(path, linux.O{ .ACCMODE = .RDWR }, 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.OpenFailed;
    return @intCast(raw);
}

/// Parse ELF from remote process to find a symbol.
fn remoteDlsym(pid: u32, elf_base: usize, name: []const u8) !?usize {
    const fd = try openProcMem(pid);
    defer _ = std.c.close(fd);

    var ehdr: [64]u8 = undefined;
    mem_mod.readRaw(fd, elf_base, ehdr[0..64]) catch return null;
    if (!std.mem.eql(u8, ehdr[0..4], "\x7fELF")) return null;

    const e_phoff = std.mem.readInt(u64, ehdr[32..40], .little);
    const e_phentsize = std.mem.readInt(u16, ehdr[54..56], .little);
    const e_phnum = std.mem.readInt(u16, ehdr[56..58], .little);

    var dyn_rva: usize = 0;
    var dyn_vsz: usize = 0;
    var phdr: [56]u8 = undefined;

    var i: u16 = 0;
    while (i < e_phnum) : (i += 1) {
        const pa = elf_base + e_phoff + @as(usize, e_phentsize) * i;
        mem_mod.readRaw(fd, pa, &phdr) catch return null;
        if (std.mem.readInt(u32, phdr[0..4], .little) == 2) { // PT_DYNAMIC
            dyn_rva = @intCast(std.mem.readInt(u64, phdr[16..24], .little));
            dyn_vsz = @intCast(std.mem.readInt(u64, phdr[40..48], .little));
            break;
        }
    }
    if (dyn_rva == 0 or dyn_vsz == 0) return null;

    var strtab: usize = 0;
    var symtab: usize = 0;
    var syment: usize = 0;
    var dynb: [16]u8 = undefined;

    var j: usize = 0;
    while (j < dyn_vsz) : (j += 16) {
        mem_mod.readRaw(fd, elf_base + dyn_rva + j, &dynb) catch return null;
        switch (std.mem.readInt(u64, dynb[0..8], .little)) {
            5 => strtab = std.mem.readInt(u64, dynb[8..16], .little),
            6 => symtab = std.mem.readInt(u64, dynb[8..16], .little),
            11 => syment = std.mem.readInt(u64, dynb[8..16], .little),
            else => {},
        }
    }
    if (symtab == 0 or strtab == 0 or syment == 0) return null;
    if (strtab < elf_base) strtab += elf_base;
    if (symtab < elf_base) symtab += elf_base;

    var symb: [24]u8 = undefined;
    var nb: [256]u8 = undefined;
    const nl = @min(name.len + 1, 256);

    var k: usize = symtab;
    while (k < strtab) : (k += syment) {
        mem_mod.readRaw(fd, k, &symb) catch return null;
        const st_name = std.mem.readInt(u32, symb[0..4], .little);
        const st_value = std.mem.readInt(u64, symb[8..16], .little);
        if (st_name == 0 or st_value == 0) continue;
        mem_mod.readRaw(fd, strtab + st_name, nb[0..nl]) catch continue;
        nb[nl - 1] = 0;
        if (std.mem.eql(u8, nb[0..name.len], name)) return elf_base + st_value;
    }
    return null;
}

const LibcSyms = struct {
    libc_base: usize,
    p_fun: usize,    // function to hijack
    p_var: usize,    // completion-signal variable
    p_dlopen: usize, // dlopen address
};

/// Find a libc mapping in the remote process and resolve symbols.
fn findRemoteLibc(allocator: std.mem.Allocator, pid: u32) !?LibcSyms {
    var buf: [64]u8 = undefined;
    const mp = try std.fmt.bufPrintZ(&buf, "/proc/{d}/maps", .{pid});
    const raw = linux.open(mp, linux.O{}, 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.OpenFailed;
    defer _ = std.c.close(@intCast(raw));

    const content = try util.readAllFd(@intCast(raw), allocator, 2 << 20);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOf(u8, line, "libc") == null) continue;
        if (std.mem.indexOf(u8, line, "r-xp") == null) continue;

        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const base = std.fmt.parseUnsigned(usize, line[0..dash], 16) catch continue;

        const p_dlopen = (try remoteDlsym(pid, base, "dlopen")) orelse
            (try remoteDlsym(pid, base, "__libc_dlopen_mode"));
        if (p_dlopen == null) continue;

        var p_var = try remoteDlsym(pid, base, "__environ");
        if (p_var == null) p_var = try remoteDlsym(pid, base, "optind");
        if (p_var == null) continue;

        var p_fun = try remoteDlsym(pid, base, "nanosleep");
        if (p_fun == null) p_fun = try remoteDlsym(pid, base, "usleep");
        if (p_fun == null) p_fun = try remoteDlsym(pid, base, "malloc");
        if (p_fun == null) continue;

        return LibcSyms{
            .libc_base = base,
            .p_fun = p_fun.?,
            .p_var = p_var.?,
            .p_dlopen = p_dlopen.?,
        };
    }
    return null;
}

/// Write code with careful in-flight-call synchronization.
/// For code > 2 bytes: write jmp $ at start, wait 100ms, write rest,
/// then write first 2 bytes last.
fn carefulWriteCode(fd: linux.fd_t, addr: usize, code: []const u8) !void {
    if (code.len <= 2) return mem_mod.writeRaw(fd, addr, code);

    const ebfe = [_]u8{ 0xeb, 0xfe };
    try mem_mod.writeRaw(fd, addr, &ebfe);

    var ts: linux.timespec = .{ .sec = 0, .nsec = 100_000_000 };
    _ = linux.nanosleep(&ts, null);

    if (code.len > 2) try mem_mod.writeRaw(fd, addr + 2, code[2..]);
    try mem_mod.writeRaw(fd, addr, code[0..2]);
}

// ─── Public API ───────────────────────────────────────────────────────────

/// Inject a shared library into a remote process using function hijacking.
///
/// Strategy:
///   1. Find libc + symbols (dlopen, malloc, __environ) in remote process
///   2. Save original function code + variable value
///   3. Zero the completion variable
///   4. Write Phase 1 shellcode (mmap+spin) into the hijacked function
///   5. Wait for any thread to call the function → mmap → completion var set
///   6. Write Phase 2 payload (dlopen) into the mmap'd rwx region
///   7. The spinning thread breaks out and executes dlopen
///   8. Restore original function code + variable value
pub fn injectSo(
    allocator: std.mem.Allocator,
    pid: u32,
    so_path: [:0]const u8,
    alloc_len: u32,
) !void {
    const page_size: u32 = 0x1000;
    const padded_len = (alloc_len + page_size - 1) / page_size * page_size;

    const syms = try findRemoteLibc(allocator, pid) orelse return error.LibcNotFound;
    const fd = try openProcMem(pid);
    defer _ = std.c.close(fd);

    // Save original function code
    var old_code: [SHELL_MAX]u8 = undefined;
    try mem_mod.readRaw(fd, syms.p_fun, &old_code);

    // Save original variable
    var old_var: u64 = undefined;
    {
        var vb: [8]u8 = undefined;
        try mem_mod.readRaw(fd, syms.p_var, &vb);
        old_var = std.mem.readInt(u64, &vb, .little);
    }

    // Zero completion variable
    {
        const zero: u64 = 0;
        var zb: [8]u8 = undefined;
        std.mem.writeInt(u64, &zb, zero, .little);
        try mem_mod.writeRaw(fd, syms.p_var, &zb);
    }

    // Build and patch Phase 1 shellcode
    var shell1: [SHELL_MAX]u8 = undefined;
    @memcpy(&shell1, &mmap_shell);

    const vd1: i64 = @as(i64, @intCast(syms.p_var)) - @as(i64, @intCast(syms.p_fun)) - 10;
    std.mem.writeInt(i32, shell1[6..10], @intCast(vd1), .little);
    std.mem.writeInt(i32, shell1[22..26], @intCast(padded_len), .little);
    const vd2: i64 = @as(i64, @intCast(syms.p_var)) - @as(i64, @intCast(syms.p_fun)) - 75;
    std.mem.writeInt(i32, shell1[76..80], @intCast(vd2), .little);

    // Write Phase 1
    try carefulWriteCode(fd, syms.p_fun, &shell1);

    // Wait for completion
    var new_var: u64 = 0;
    var vb: [8]u8 = undefined;
    const start = util.timestampMs();
    while (true) {
        try mem_mod.readRaw(fd, syms.p_var, &vb);
        new_var = std.mem.readInt(u64, &vb, .little);
        if (new_var & 1 != 0 and new_var & ~@as(u64, 1) != 0) break;
        if (util.timestampMs() - start > 30000) return error.InjectTimeout;
        var ts: linux.timespec = .{ .sec = 0, .nsec = 20_000_000 };
        _ = linux.nanosleep(&ts, null);
    }

    const rwx_base: usize = @intCast(new_var & ~@as(u64, 1));

    // Build Phase 2 payload
    const path_len = so_path.len + 1;
    const payload_size = DLOPEN_HEADER_SIZE + path_len;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);

    @memcpy(payload[0..dlopen_shell.len], &dlopen_shell);
    std.mem.writeInt(u64, payload[dlopen_shell.len..][0..8], @intCast(syms.p_dlopen), .little);
    std.mem.writeInt(u64, payload[dlopen_shell.len + 8 .. dlopen_shell.len + 16], @intCast(syms.p_fun), .little);
    std.mem.writeInt(u64, payload[dlopen_shell.len + 16 .. dlopen_shell.len + 24], 2, .little); // RTLD_NOW
    @memcpy(payload[dlopen_shell.len + 24 .. dlopen_shell.len + 24 + path_len], so_path);
    payload[DLOPEN_HEADER_SIZE + path_len - 1] = 0;

    // Restore original function FIRST (before writing dlopen payload).
    // The spinning thread will break out when we overwrite jmp $, then:
    // dlopen → restore regs → jmp p_oldfun. p_oldfun must be restored by then.
    try mem_mod.writeRaw(fd, syms.p_fun, old_code[0..SHELL_MAX]);

    // Write payload to rwx allocation (spinning thread is at jmp $ here)
    try mem_mod.writeRaw(fd, rwx_base, payload);

    // Give time for dlopen to execute
    {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 100_000_000 };
        _ = linux.nanosleep(&ts, null);
    }

    // Restore original variable
    {
        var ovb: [8]u8 = undefined;
        std.mem.writeInt(u64, &ovb, old_var, .little);
        try mem_mod.writeRaw(fd, syms.p_var, &ovb);
    }
}
