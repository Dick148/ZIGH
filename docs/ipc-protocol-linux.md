# ZIGH IPC 通信协议 v2.0 — Linux 原生版

> 本文档定义 ZIGH (ZIGH Is Game Hacker) 前端 CLI 与后端守护进程之间的
> 进程间通信协议。基于 v1.0 (Windows) 改写，替换所有 Windows API 为
> Linux 等价系统调用。
>
> 设计目标：零序列化开销、无锁同步、单一守护进程管理所有锁定项、
> 支持多引擎。

---

## 1. 总体架构

### 1.1 进程模型

```
┌─────────────────────────────┐         ┌─────────────────────────────┐
│     ZIGH CLI (用户终端)       │         │     目标进程 (Wine/原生)      │
│                             │         │                             │
│  命令解析 (Zig builtin)      │  sock   │  ZIGH Daemon → LD_PRELOAD   │
│    ↕                        │  ↕      │    ↕                        │
│  Unix Domain Socket Client  │  IPC    │  工作线程 (agent.so)         │
│    ↕                        │  ↕      │    ↕                        │
│  共享内存 (写入端)            │ ────→  │  共享内存 (读取端)            │
└─────────────────────────────┘         └─────────────────────────────┘
```

### 1.2 通信通道分工

| 通道 | 方向 | 用途 | Linux API |
|------|------|------|-----------|
| 共享内存 | CLI → Daemon → agent | 命令下发 + 数值回读 | `shm_open()` + `mmap(MAP_SHARED)` |
| Socket | 双向 | 初始握手、引擎特殊操作、远程调用 | `socketpair()` / Unix Domain |

### 1.3 数据流向约束

- **命令区**：只有 Daemon 写入，只有 agent.so 读取。单向写，无竞争。
- **回读区**：只有 agent.so 写入，只有 Daemon 读取。单向写，无竞争。
- **version 字段**：Daemon 原子递增，agent 原子读取。
- **因此**：整个协议不需要 Mutex、Semaphore 等同步原语。

---

## 2. 共享内存布局 (与 v1.0 兼容)

### 2.1 总体结构

```
偏移        大小        名称              访问方向
─────────────────────────────────────────────────────
0x0000      4           version           Daemon 写 (原子++), agent 读
0x0004      4           cmdCount          Daemon 写, agent 读
0x0008      4           lockIntervalMs    Daemon 写, agent 读
0x000C      4           engineType        Daemon 写, agent 读
0x0010      4           agentStatus      agent 写, Daemon 读
0x0014      4           reserved          -
0x0018      48          initParams        Daemon 写, agent 读 (一次性)
─────────────────────────────────────────────────────
0x0048      1280        cmdSlots[16]      Daemon 写, agent 读
            (16×80B)
─────────────────────────────────────────────────────
0x0548      1024        readSlots[64]    agent 写, Daemon 读
            (64×16B)
─────────────────────────────────────────────────────
0x0948      256         engineExtData     引擎专用扩展区
─────────────────────────────────────────────────────
总计        3072 字节   (分配 4096 字节，页对齐)
```

### 2.2 共享内存命名规则

```
格式: /zigh_{pid}_{engineType}

示例:
  /zigh_12345_UE4       (PID 12345 的 UE4 游戏)
  /zigh_67890_GM        (PID 67890 的 GameMaker 游戏)
  /zigh_11111_UnityIL2CPP
```

- 位于 `/dev/shm/` 下（Linux tmpfs，纯内存，不落盘）
- `pid` 确保同一机器上多个游戏实例互不冲突
- `engineType` 让 agent 知道应该连接哪个共享内存

### 2.3 共享内存生命周期

```
1. Daemon:
   a. fd = shm_open("/zigh_{pid}_{engineType}", O_RDWR|O_CREAT, 0600)
   b. ftruncate(fd, 4096)
   c. shm = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
   d. 写入 initParams
   e. 注入 agent.so (LD_PRELOAD 或 ptrace/dlopen)

2. agent.so (constructor / 初始化函数):
   a. fd = shm_open("/zigh_{pid}_{engineType}", O_RDWR, 0)
   b. shm = mmap(...)
   c. 读取 initParams, 获取 moduleBase / pid
   d. 创建工作线程
   e. 创建 Unix socket 对等端 (通过 initParams.pipeName)
   f. 设置 agentStatus = STATUS_RUNNING (1)

3. Daemon:
   a. 轮询 agentStatus 直到变为 STATUS_RUNNING
   b. 开始下发命令

4. 退出时:
   a. Daemon 将所有 cmdSlot.mode 清零, version++
   b. Daemon 设置 agentStatus = STATUS_SHUTDOWN (3)
   c. agent 工作线程检测到 SHUTDOWN 后退出
   d. Daemon munmap + shm_unlink
```

---

## 3. 头部字段定义 (与 v1.0 完全兼容)

### 3.1 version (偏移 0x0000, 4 字节, uint32)

- Daemon 每次修改 cmdSlot 后原子递增
- agent 工作线程每轮循环开始时读取
- 使用 `@atomicStore` / `@atomicLoad` (Zig) 或 `std::atomic<uint32_t>` (C)

### 3.2 cmdCount (偏移 0x0004, 4 字节, uint32)

有效命令数量，0~16。

### 3.3 lockIntervalMs (偏移 0x0008, 4 字节, uint32)

全局锁定写入间隔（默认 16ms，约 60fps）。

### 3.4 engineType (偏移 0x000C, 4 字节, uint32)

```
0   Generic      5   Godot C#
1   UE4          6   Godot GDScript
2   UE5          7   GameMaker
3   Unity Mono   8   RPG Maker (文件 Hook，不走此协议)
4   Unity IL2CPP 9   Ren'Py (同上)
```

### 3.5 agentStatus (偏移 0x0010, 4 字节, uint32)

```
0   STATUS_UNINITIALIZED
1   STATUS_RUNNING
2   STATUS_ERROR
3   STATUS_SHUTDOWN
```

### 3.6 initParams (偏移 0x0018, 48 字节)

```
偏移    大小    字段名              说明
─────────────────────────────────────────────
+0x00   8       targetModuleBase   目标模块运行时基址
+0x08   4       targetPid          目标进程 PID
+0x0C   4       targetBit          32 或 64
+0x10   32      socketPath         Unix socket 路径 (null-terminated)
```

---

## 4. 命令槽位 (CmdSlot) — 与 v1.0 完全相同

### 4.1 结构 (80 字节 × 16)

```
偏移    大小    字段名
─────────────────────────────────────────────────────
+0x00   4       mode               (详见 mode 位段)
+0x04   4       valueType
+0x08   4       layerCount         指针解链层数 (0~8)
+0x0C   4       slotId             命令编号
+0x10   8       valueAsU64         要写入的值
+0x18   8       rva                相对模块基址偏移
+0x20   8       targetModuleBase   目标模块基址
+0x28   32      offsets[8]         指针解链偏移数组 (uint32)
+0x48   32      reserved
```

### 4.2 mode 位段

```
Bit 0:    ENABLED          1=启用
Bit 1:    LOCK             1=高频锁定, 0=单次
Bit 2:    READBACK         1=回读
Bit 3:    ENGINE_CALL      1=引擎原生调用
Bit 4:    NEED_CHAIN_RESOLVE 1=每轮重新解链 (Unity Mono GC)
Bit 5-7:  预留
Bit 8-11: LOCK_INTERVAL_INDEX 锁定间隔索引
Bit 12-15: 预留
Bit 16-31: engineSpecific
```

### 4.3 valueType

```
0=int8  1=uint8  2=int16   3=uint16
4=int32 5=uint32 6=int64   7=uint64
8=f32   9=f64    10=byte[8] 11=pointer
```

### 4.4 指针解链 (offsets 字段)

```
layerCount == 0:  targetAddr = base + rva
layerCount == N:  ptr = base + rva
                  for i=0..N-2: ptr = *(uintptr*)(ptr + offsets[i])
                  targetAddr = ptr + offsets[N-1]
```

---

## 5. 回读槽位 (ReadSlot) — 与 v1.0 完全相同

### 5.1 结构 (16 字节 × 64)

```
+0x00   8       valueAsU64
+0x08   4       slotId
+0x0C   4       flags
```

### 5.2 flags

```
Bit 0: VALID         Bit 1: READ_ERROR
Bit 2: WRITE_ERROR   Bit 3: CHAIN_BROKEN
```

---

## 6. Linux 特有：直接进程内存访问 (/proc/PID/mem)

ZIGH 在 Daemon 模式下可以通过 `/proc/PID/mem` 直接读写目标进程内存，
无需注入。（agent.so 注入模式用于高频锁定场景。）

```c
// 通过 /proc/PID/mem 读写（无需注入）
int fd = open("/proc/12345/mem", O_RDWR);
lseek(fd, targetAddr, SEEK_SET);
pread(fd, &value, 8, targetAddr);   // 读
pwrite(fd, &value, 8, targetAddr);  // 写
```

或者使用系统调用：

```c
// 向量化读写，一次 syscall 可操作多个不连续地址
#include <sys/uio.h>
process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
```

### 6.1 性能对比

| 模式 | 单次写入开销 | 锁定 10 值 @ 60fps |
|------|-------------|-------------------|
| agent.so 注入 + 共享内存 | 0 syscall（纯内存） | 0 syscall/s |
| /proc/PID/mem (逐地址) | 2 syscall/次 (lseek+write) | 1200 syscall/s |
| process_vm_writev (批量) | 1 syscall/帧 | 60 syscall/s |

**结论**：单次/临时操作用 `/proc/PID/mem` 即可；高频锁定必须走 agent.so 注入模式。

---

## 7. Unix Domain Socket 辅助通道

### 7.1 路径约定

```
/tmp/zigh_{pid}.sock
```

### 7.2 使用场景

| 场景 | 说明 |
|------|------|
| agent 初始化握手 | agent 就绪后通过 socket 通知 Daemon |
| 引擎原生调用 | 需要复杂参数或返回值的远程函数调用 |
| 错误上报 | agent 遇到致命错误时推送 |
| 调试信息 | agent 输出日志 |

### 7.3 消息格式 (TLV)

```
┌──────────┬──────────┬──────────────────────┐
│ uint16   │ uint16   │ byte[length]          │
│ msgType  │ length   │ payload               │
└──────────┴──────────┴──────────────────────┘
```

| msgType | 方向 | 说明 |
|---------|------|------|
| 0x01 | agent→Daemon | agent 就绪 |
| 0x02 | agent→Daemon | 错误报告 |
| 0x03 | agent→Daemon | 调试日志 |
| 0x10 | Daemon→agent | 引擎调用请求 |
| 0x11 | agent→Daemon | 引擎调用响应 |
| 0x20 | 双向 | Ping/Pong |
| 0xFF | 双向 | 断开 |

---

## 8. YAML cheat 文件格式

```yaml
# ~/.config/zigh/cheats/nier-automata.yaml
game: NieRAutomata
engine: generic
process: NieRAutomata.exe    # Wine 进程名

locks:
  - name: hp
    address: "game.exe+0x0123ABC0"
    chain: [0x10, 0x20, 0x8]
    type: f32
    default: 9999

  - name: mp
    address: "game.exe+0x0123ABC0"
    chain: [0x10, 0x28, 0x8]
    type: f32
    default: 9999

  - name: gil
    address: "game.exe+0x04567890"
    type: u32
    default: 9999999

remote_calls:
  - name: set_time_of_day
    address: "game.exe+0x00123456"
    args: [f32]

  - name: teleport
    address: "game.exe+0x00789012"
    args: [f32, f32, f32]
```

---

## 9. CLI 命令集

```
zigh daemon                            # 启动守护进程
zigh status                            # 查看锁定状态
zigh lock add <name> <val> [--type]   # 添加锁定
zigh lock remove <name>                # 取消锁定
zigh lock list                         # 列出全部锁定
zigh write <addr> <value> [--type]    # 单次写入
zigh read <addr> [--type]             # 单次读取
zigh call <func> [args...]            # 远程调用
zigh cheat load <file.yaml>           # 加载 cheat 定义
zigh cheat start [<name>]             # 启动全部/指定 cheat
zigh cheat stop                        # 停止所有锁定
zigh inject <pid> <agent.so>          # 注入 agent
```

---

## 10. 构建与依赖

- **语言**：Zig (≥0.14)
- **外部依赖**：无（纯 Zig 标准库 + Linux syscall）
- **目标二进制**：单一静态链接 ELF，无动态链接依赖
- **体积目标**：< 1 MiB (stripped)
- **运行要求**：Linux 5.4+, `/proc` 文件系统, `CONFIG_SHMEM=y`

---

## 附录 A: v1.0 → v2.0 变更摘要

| v1.0 (Windows) | v2.0 (Linux) |
|----------------|-------------|
| `CreateFileMapping` | `shm_open` + `mmap` |
| `Global\ModTool_*` | `/zigh_*` (位于 `/dev/shm/`) |
| `InterlockedIncrement` | `@atomicStore` / `std.atomic` |
| `\\.\pipe\ModTool_*` | `/tmp/zigh_*.sock` (Unix Domain) |
| DLL 注入 (CreateRemoteThread) | LD_PRELOAD / ptrace+dlopen |
| `WriteProcessMemory` | `/proc/PID/mem` / `process_vm_writev` |
| Electron 前端 | Zig 内置 CLI |
| `dllStatus` | `agentStatus`（仅字段名变更） |

**协议层（共享内存布局、命令槽位、回读槽位、mode/valueType 定义）完全不变。**
