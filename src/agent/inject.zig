// ZIGH — Runtime agent injector: ptrace call + hook patching (trampoline in agent.so)

const std = @import("std");
const linux = std.os.linux;
const util = @import("../util.zig");
const mem_mod = @import("../mem/mod.zig");

const user_regs_struct = extern struct {
    r15:u64,r14:u64,r13:u64,r12:u64,rbp:u64,rbx:u64,r11:u64,r10:u64,
    r9:u64,r8:u64,rax:u64,rcx:u64,rdx:u64,rsi:u64,rdi:u64,orig_rax:u64,
    rip:u64,cs:u64,eflags:u64,rsp:u64,
    ss:u64,fs_base:u64,gs_base:u64,ds:u64,es:u64,fs:u64,gs:u64,
};

const PTRACE_ATTACH = std.os.linux.PTRACE.ATTACH;
const PTRACE_DETACH = std.os.linux.PTRACE.DETACH;
const PTRACE_GETREGS = std.os.linux.PTRACE.GETREGS;
const PTRACE_SETREGS = std.os.linux.PTRACE.SETREGS;
const PTRACE_CONT = std.os.linux.PTRACE.CONT;

fn findRemoteFn(pid: u32, name: []const u8) !?u64 {
    // Parse remote libc ELF to find symbol (like remoteDlsym in linject.zig)
    var buf: [64]u8 = undefined;
    const mp = try std.fmt.bufPrintZ(&buf, "/proc/{d}/maps", .{pid});
    const r = linux.open(mp, linux.O{}, 0);
    if (@as(isize, @bitCast(r)) < 0) return error.OpenFailed;
    defer _ = std.c.close(@intCast(r));
    const c = try readAll(@intCast(r), std.heap.page_allocator, 2 << 20);
    defer std.heap.page_allocator.free(c);

    var lines = std.mem.splitScalar(u8, c, '\n');
    while (lines.next()) |l| {
        if (std.mem.indexOf(u8, l, "libc") == null) continue;
        if (std.mem.indexOf(u8, l, "r-xp") == null) continue;
        const d = std.mem.indexOfScalar(u8, l, '-') orelse continue;
        const base = std.fmt.parseUnsigned(usize, l[0..d], 16) catch continue;

        // Parse remote ELF
        const fd = try openProcMem(pid);
        defer _ = std.c.close(fd);

        var ehdr: [64]u8 = undefined;
        mem_mod.readRaw(fd, base, ehdr[0..64]) catch continue;
        if (!std.mem.eql(u8, ehdr[0..4], "\x7fELF")) continue;

        const e_phoff = std.mem.readInt(u64, ehdr[32..40], .little);
        const e_phentsize = std.mem.readInt(u16, ehdr[54..56], .little);
        const e_phnum = std.mem.readInt(u16, ehdr[56..58], .little);

        var dyn_rva: usize = 0;
        var dyn_vsz: usize = 0;
        var phdr: [56]u8 = undefined;
        var i: u16 = 0;
        while (i < e_phnum) : (i += 1) {
            const pa = base + e_phoff + @as(usize, e_phentsize) * i;
            mem_mod.readRaw(fd, pa, &phdr) catch continue;
            if (std.mem.readInt(u32, phdr[0..4], .little) == 2) {
                dyn_rva = @intCast(std.mem.readInt(u64, phdr[16..24], .little));
                dyn_vsz = @intCast(std.mem.readInt(u64, phdr[40..48], .little));
                break;
            }
        }
        if (dyn_rva == 0 or dyn_vsz == 0) continue;

        var strtab: usize = 0;
        var symtab: usize = 0;
        var syment: usize = 0;
        var dynb: [16]u8 = undefined;
        var j: usize = 0;
        while (j < dyn_vsz) : (j += 16) {
            mem_mod.readRaw(fd, base + dyn_rva + j, &dynb) catch continue;
            switch (std.mem.readInt(u64, dynb[0..8], .little)) {
                5 => strtab = std.mem.readInt(u64, dynb[8..16], .little),
                6 => symtab = std.mem.readInt(u64, dynb[8..16], .little),
                11 => syment = std.mem.readInt(u64, dynb[8..16], .little),
                else => {},
            }
        }
        if (symtab == 0 or strtab == 0 or syment == 0) continue;
        if (strtab < base) strtab += base;
        if (symtab < base) symtab += base;

        var symb: [24]u8 = undefined;
        var nb: [256]u8 = undefined;
        const nl = @min(name.len + 1, 256);

        var k: usize = symtab;
        while (k < strtab) : (k += syment) {
            mem_mod.readRaw(fd, k, &symb) catch continue;
            const st_name = std.mem.readInt(u32, symb[0..4], .little);
            const st_value = std.mem.readInt(u64, symb[8..16], .little);
            if (st_name == 0 or st_value == 0) continue;
            mem_mod.readRaw(fd, strtab + st_name, nb[0..nl]) catch continue;
            nb[nl - 1] = 0;
            if (std.mem.eql(u8, nb[0..name.len], name)) return @intCast(base + st_value);
        }
        // symbol not in this libc — won't be in another, break
        break;
    }
    return null;
}

fn findAgentTail(a: std.mem.Allocator, pid: u32, size: usize) !?usize {
    var b:[64]u8=undefined;
    const mp=try std.fmt.bufPrintZ(&b,"/proc/{d}/maps",.{pid});
    const r=linux.open(mp,linux.O{},0);
    if(@as(isize,@bitCast(r))<0) return error.OpenFailed;
    defer _=std.c.close(@intCast(r));
    const c=try readAll(@intCast(r),a,2<<20); defer a.free(c);
    var ls=std.mem.splitScalar(u8,c,'\n');
    // Try any r-xp region that's big enough (prefer main binary or libc)
    var best:usize=0;
    while(ls.next())|l|{
        if(std.mem.indexOf(u8,l,"r-xp")!=null){
            const d=std.mem.indexOfScalar(u8,l,'-') orelse continue;
            const sp=std.mem.indexOfScalarPos(u8,l,d+1,' ') orelse continue;
            const start=std.fmt.parseUnsigned(usize,l[0..d],16) catch continue;
            const end=std.fmt.parseUnsigned(usize,l[d+1..sp],16) catch continue;
            if(end-start>=size){best=end-size;break;}  // take first big enough region
        }
    }
    if(best!=0) return best;
    return null;
}

fn findStackTop(a: std.mem.Allocator, pid: u32) !?usize {
    var b:[64]u8=undefined;
    const mp=try std.fmt.bufPrintZ(&b,"/proc/{d}/maps",.{pid});
    const r=linux.open(mp,linux.O{},0);
    if(@as(isize,@bitCast(r))<0) return error.OpenFailed;
    defer _=std.c.close(@intCast(r));
    const c=try readAll(@intCast(r),a,1<<20); defer a.free(c);
    var ls=std.mem.splitScalar(u8,c,'\n');
    while(ls.next())|l|{
        if(std.mem.indexOf(u8,l,"[stack]")!=null){
            const sp=std.mem.indexOfScalar(u8,l,' ') orelse continue;
            const d=std.mem.indexOfScalar(u8,l,'-') orelse continue;
            return std.fmt.parseUnsigned(usize,l[d+1..sp],16) catch continue;
        }
    }
    return null;
}

fn wmem(pid: u32, addr: usize, data: []const u8) !void {
    var b:[32]u8=undefined;
    const mp=try std.fmt.bufPrintZ(&b,"/proc/{d}/mem",.{pid});
    const r=linux.open(mp,linux.O{.ACCMODE=.WRONLY},0);
    if(@as(isize,@bitCast(r))<0) return error.OpenFailed;
    defer _=std.c.close(@intCast(r));
    _=linux.pwrite(@intCast(r),data.ptr,data.len,@intCast(addr));
}

fn rmem(pid: u32, addr: usize, data: []u8) !void {
    var b:[32]u8=undefined;
    const mp=try std.fmt.bufPrintZ(&b,"/proc/{d}/mem",.{pid});
    const r=linux.open(mp,linux.O{},0);
    if(@as(isize,@bitCast(r))<0) return error.OpenFailed;
    defer _=std.c.close(@intCast(r));
    _=linux.pread(@intCast(r),data.ptr,data.len,@intCast(addr));
}

fn openProcMem(pid: u32) !linux.fd_t {
    var b: [64]u8 = undefined;
    const mp = try std.fmt.bufPrintZ(&b, "/proc/{d}/mem", .{pid});
    const r = linux.open(mp, linux.O{ .ACCMODE = .RDWR }, 0);
    if (@as(isize, @bitCast(r)) < 0) return error.OpenFailed;
    return @intCast(r);
}

fn readAll(fd: linux.fd_t, a: std.mem.Allocator, max: usize) ![]u8 {
    return util.readAllFd(fd, a, max);
}

fn ptraceCall(pid: u32, fn_addr: u64, rdi_val: u64, rsi_val: u64, bp_addr: usize, stack_top: usize) !u64 {
    const ss=(stack_top-256)&~@as(usize,0xf);
    var regs: user_regs_struct=undefined;
    _=linux.ptrace(PTRACE_GETREGS,@intCast(pid),0,@intFromPtr(&regs),0);
    var ret:[8]u8=undefined; std.mem.writeInt(u64,&ret,@intCast(bp_addr),.little);
    try wmem(pid,ss,&ret);
    regs.rsp=ss; regs.rdi=rdi_val; regs.rsi=rsi_val; regs.rip=fn_addr;
    _=linux.ptrace(PTRACE_SETREGS,@intCast(pid),0,@intFromPtr(&regs),0);
    _=linux.ptrace(PTRACE_CONT,@intCast(pid),0,0,0);
    var st:u32=0; _=linux.wait4(@intCast(pid),&st,0,null);
    var rs: user_regs_struct=undefined;
    _=linux.ptrace(PTRACE_GETREGS,@intCast(pid),0,@intFromPtr(&rs),0);
    return rs.rax;
}

fn buildTrampoline(tick_addr: u64, hook_addr: usize, orig: [5]u8) [64]u8 {
    var o:[64]u8=undefined; var p:usize=0;
    o[p]=0x9c;p+=1;
    for([_]u8{0x50,0x51,0x52,0x56,0x57})|b|{o[p]=b;p+=1;}
    for([_]u8{0x50,0x51,0x52,0x53})|b|{o[p]=0x41;o[p+1]=b;p+=2;}
    o[p]=0x48;o[p+1]=0xb8;p+=2;
    std.mem.writeInt(u64,o[p..][0..8],tick_addr,.little);p+=8;
    o[p]=0xff;o[p+1]=0xd0;p+=2;
    for([_]u8{0x5b,0x5a,0x59,0x58})|b|{o[p]=0x41;o[p+1]=b;p+=2;}
    for([_]u8{0x5f,0x5e,0x5a,0x59,0x58})|b|{o[p]=b;p+=1;}
    o[p]=0x9d;p+=1;
    @memcpy(o[p..][0..5],&orig);p+=5;
    o[p]=0x48;o[p+1]=0xb8;p+=2;
    std.mem.writeInt(u64,o[p..][0..8],@intCast(hook_addr+5),.little);p+=8;
    o[p]=0xff;o[p+1]=0xe0;p+=2;
    return o;
}

pub fn inject(a: std.mem.Allocator, pid: u32, so_path: [:0]const u8, hook_addr: ?usize) !void {
    std.debug.print("[inject] Finding dlopen/dlsym...\n",.{});
    const dlopen_a=try findRemoteFn(pid,"dlopen") orelse return error.DlopenNotFound;
    const dlsym_a=try findRemoteFn(pid,"dlsym") orelse return error.DlsymNotFound;
    const st=try findStackTop(a,pid) orelse return error.NoStack;
    const sa=st-512; const na=sa+so_path.len+1;
    // Find executable region for breakpoint (stack is NX on modern systems)
    const bp = try findAgentTail(a, pid, 16) orelse return error.NoAgentSpace;
    try wmem(pid,sa,so_path[0..so_path.len]);
    try wmem(pid,sa+so_path.len,&[_]u8{0});
    try wmem(pid,na,"agent_init"); try wmem(pid,na+10,&[_]u8{0});
    try wmem(pid,bp,&[_]u8{0xcc});

    _=linux.ptrace(PTRACE_ATTACH,@intCast(pid),0,0,0);
    var status:u32=0; _=linux.wait4(@intCast(pid),&status,0,null);
    var orig: user_regs_struct=undefined;
    _=linux.ptrace(PTRACE_GETREGS,@intCast(pid),0,@intFromPtr(&orig),0);

    // Pre-load libm (needed by agent.so via link_libc)
    var libm_buf: [64]u8 = undefined;
    const libm_path = try std.fmt.bufPrintZ(&libm_buf, "/lib64/libm.so.6", .{});
    const libm_sa = st - 1024;
    try wmem(pid, libm_sa, libm_path[0..libm_path.len]);
    try wmem(pid, libm_sa + libm_path.len, &[_]u8{0});
    const lm: u64 = try ptraceCall(pid, dlopen_a, @intCast(libm_sa), 0x101, bp, st); // RTLD_NOW|RTLD_GLOBAL=0x101
    _ = lm; // ignore return — agent.so will use it via global symbol table

    const h=try ptraceCall(pid,dlopen_a,@intCast(sa),2,bp,st);
    if(h==0) return error.DlopenFailed;
    const init_a=try ptraceCall(pid,dlsym_a,h,@intCast(na),bp,st);
    if(init_a==0) return error.DlsymFailed;
    std.debug.print("[inject] Calling agent_init...\n",.{});
    _=try ptraceCall(pid,init_a,0,0,bp,st);

    if(hook_addr)|hk|{
        std.debug.print("[inject] Hook at 0x{x}\n",.{hk});
        // Get agent_tick via dlsym
        var tb:[16]u8=undefined;
        std.mem.copyForwards(u8,&tb,"agent_tick");tb[10]=0;
        const ta=sa+so_path.len+24;
        try wmem(pid,ta,"agent_tick");try wmem(pid,ta+10,&[_]u8{0});
        const tick_a=try ptraceCall(pid,dlsym_a,h,@intCast(ta),bp,st);
        if(tick_a==0) return error.NoTick;
        // Build trampoline in agent.so's r-xp tail
        const tr=try findAgentTail(a,pid,64) orelse return error.NoAgentSpace;
        var orig5:[5]u8=undefined; try rmem(pid,hk,&orig5);
        const tramp=buildTrampoline(tick_a,hk,orig5);
        try wmem(pid,tr,&tramp);
        // Write JMP at hook point
        const jo:i32=@intCast(@as(i64,@intCast(tr))-@as(i64,@intCast(hk))-5);
        var j:[5]u8=undefined;j[0]=0xe9;
        std.mem.writeInt(i32,j[1..5],jo,.little);
        try wmem(pid,hk,&j);
        std.debug.print("[inject] Hook installed: 0x{x} -> tramp at 0x{x} -> agent_tick at 0x{x}\n",.{hk,tr,tick_a});
    }

    // With hook: resume from hook point. Without: restore original state.
    if (hook_addr) |hk| {
        var regs: user_regs_struct = undefined;
        _ = linux.ptrace(PTRACE_GETREGS, @intCast(pid), 0, @intFromPtr(&regs), 0);
        regs.rip = @intCast(hk);
        _ = linux.ptrace(PTRACE_SETREGS, @intCast(pid), 0, @intFromPtr(&regs), 0);
    } else {
        _ = linux.ptrace(PTRACE_SETREGS, @intCast(pid), 0, @intFromPtr(&orig), 0);
    }
    _ = linux.ptrace(PTRACE_DETACH, @intCast(pid), 0, 0, 0);
    std.debug.print("[inject] Done.\n", .{});
}
