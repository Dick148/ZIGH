// C wrapper: provides a proper ELF .init_array entry for agent.so
// Without this, Zig's shared lib doesn't auto-run agent_init on dlopen.
// Required for both LD_PRELOAD and ptrace+dlopen injection paths.

__attribute__((constructor))
static void zigh_constructor(void) {
    extern void agent_init(void);
    agent_init();
}
