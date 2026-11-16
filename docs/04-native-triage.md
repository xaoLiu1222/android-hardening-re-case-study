# 原生库检测分诊方法（Native Detection Triage）

面向「几十个 `.so`、只有少数携带安全检测」的现实场景，用一套可复现的流水线把「逐库通读」压缩成
「自动分诊 + 灰区逐函数核实」。

## 1. 流水线

```
APK ──解包──▶ 61 个 .so 条目 + sha256 台账
                    │
                    ▼
       idat.exe -A -B（每库建库，headless）
                    │
                    ▼
   triage_one.py：字符串指标 × xref 函数 + 敏感导入调用者
                    │
                    ▼
        人工判定：真检测 / 误报（逐条归因）
                    │
                    ▼
  灰区（真检测候选）──▶ Hex-Rays 逐函数核实（仅 IDA）
```

## 2. 字符串指标（10 类）

| 类别 | 指标示例 |
|---|---|
| root | `/system/bin/su`、`/system/xbin/su`、`which su`、`magisk`、`busybox`、`supersu` |
| 调试 | `ptrace`、`TracerPid`、`gdb`、`gdbserver`、`android_server` |
| Frida | `frida`、`27042`、`gum-js-loop`、`linjector`、`gadget` |
| Xposed | `xposed`、`XposedBridge`、`de.robv`、`lsposed` |
| 模拟器 | `goldfish`、`qemu`、`ranchu`、`vbox`、`genymotion`、`bluestacks`、`nox`、`ttVM` |
| proc | `/proc/self/maps`、`/proc/self/status`、`/proc/net/tcp`、`/proc/self/cgroup` |
| 属性 | `ro.debuggable`、`ro.secure`、`ro.boot.verifiedbootstate`、`ro.build.tags`、`getprop` |
| 路径 | `/data/local/tmp`、`/data/adb`、`/system/xbin`、`/dev/socket` |
| 端口 | `127.0.0.1`、`localhost`、`23946`、`5555` |
| 检测词 | `detect`、`risk`、`hook`、`trace`、`anti`、`isdebug` |

**命中不是结论**：每条命中都要回溯到引用它的函数，再由人判读代码语义。

## 3. 敏感导入（22 项）

`ptrace / prctl / fork / vfork / kill / waitpid / inotify_init / syscall / dl_iterate_phdr /
getauxval / __system_property_get / access / stat / readlink / opendir / readdir / fopen / popen /
getpid / gettid / uname / socket / connect`

分诊时统计**调用者集合**：导入存在但零调用者 = 模板残留；有调用者则进入灰区。

## 4. 误报分类表（本项目实测，按出现频次）

| 误报形态 | 实例 | 判别方法 |
|---|---|---|
| 子串碰撞 | `/su` 命中 `…Surface…)V` 方法签名 | 看命中串完整性 |
| 日期格式串 | `Friday` 命中 `frida` | 看所在函数是否时间格式化 |
| 语言/框架 API 名 | `xmlDocGetRootElement`（libxml）、`trustRoot`（TLS）、`rootpage`（SQLite）、`root_producer_manager`（WebRTC） | 看命名空间 |
| 崩溃收集器 | `LinuxPtraceDumper`（google-breakpad） | 查符号族是否全为 breakpad |
| 性能统计 | `/proc/cpuinfo`、`/proc/meminfo`、`/proc/self/statm` | 看是否只用于算 CPU/内存 |
| 自身进程自省 | `/proc/<pid>/maps` + `MapInfo::getMapInfoList` | 读自身 maps = 崩溃符号化，非反调试 |
| 埋点/日志 | `_trace_id`、`reportTraceEvent` | 是否为 APM SDK |

## 5. 局限（必须写进结论）

1. **无字符串写法的检测会漏**：纯数值比较、无字面量的 syscall 探针、动态拼串。
2. **单 ABI**：本流水线只覆盖运行时 ABI；另一 ABI 需单独建库。
3. **分诊 ≠ 全函数审计**：结论应表述为「未发现检测特征」，而非「不存在检测」。
4. **缓解手段**：对无命中库抽样 N 个函数做 Hex-Rays 复核；对每个「无检测」结论附归因表。

## 6. 产出结构

```
triage/
  <lib>.triage.json   # 分类命中 + xref 函数 + 导入调用者
  <lib>.triage.md     # 人读摘要
```
