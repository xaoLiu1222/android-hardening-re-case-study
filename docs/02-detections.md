# 检测面分析（26.10.135）

> **脱敏说明**：本文件由内部完整分析档抽取，已移除全部密钥/密钥构造参数/可操作函数偏移/解密工具；
> 保留检测项、判定条件、调用链与结论。内部档含完整证据，未随仓库发布。

## A6. UsbReceiver 行为完整还原（2026-11-14 23:30，第 28 轮）——老档案 unknown 项闭合

**源码（新版 recovered/classes2.dex，jadx 反编译，与对照版本行为一致）**：
```java
public class UsbReceiver extends BroadcastReceiver {
    class a implements Runnable { public void run() { System.exit(1); } }
    public void onReceive(Context ctx, Intent intent) {
        if (intent == null || intent.getExtras() == null
            || !intent.getExtras().getBoolean("connected")) return;   // 仅 USB 连接态
        Toast.makeText(ctx, "请不要连接电脑", 1).show();                // 提示
        new Handler().postDelayed(new a(), 10000L);                    // 10 秒延时
    }
}
```
**判定链**：manifest 注册 `android.hardware.usb.action.USB_STATE`（priority 1000）→ 收到 `connected=true` 广播 → Toast「请不要连接电脑」→ **10 秒后 `System.exit(1)`**。
**触发条件**：USB_STATE 广播仅在 USB 连接状态/功能配置**变化**时发送；常驻插线本身不重复触发。
**动态实证（observed）**：22:48:06.428 NotificationService「Toast already killed pkg=<app>」→ 22:48:17.437 AMS「Process (pid 23631) has died: fg TOP」= **11 秒间隔，无 tombstone/无 Fatal signal/无 ANR，与 System.exit(1) 特征完全一致**。挂 hook（22:47:59）与广播（~22:48:06）属时间巧合。
**观察注意**：该退出路径由 USB 状态**变化**触发，动态观察时需与其它退出原因区分（否则会把用户态正常退出误判为崩溃或检测命中）。

## A8. xiaojianbang ART 自保护框架（2026-11-14 23:50，第 30 轮）——运行时取证条目

**性质**：ART 层代码注入防护（非调试器/非常规反调试），日志 tag `xiaojianbang`，启动即激活。

**observed — hook 目标表（内存取证，`[anon:dalvik-main space]` +0x267601）**：
| 目标 | 方法 |
|---|---|
| `dalvik.system.DexFile` | `defineClass`、`defineClassNative`、`getClassNameList`、`loadDex`、`openDexFile`、`openDexFileNative`、`openInMemoryDexFiles`、`openInMemoryDexFilesNative`、`closeDexFile`、`save_method_code`、`setTrusted`、`verifyInBackground(Native)`、`getDexFileOptimizationInfo/Status`、`getDexFileOutputPaths`、`getDexOptNeeded`、`isDexOptNeeded`、`isBackedByOatFile`、`getStaticSizeOfDexFile`、`isValidCompilerFilter`、`isVerifiedCompilerFilter`、`isOptimizedCompilerFilter`、`isProfileGuidedCompilerFilter`、`isReadOnlyJavaDclEnforced`、`getMinimumSizeOfDexFile`… |
| `java.lang.ClassLoader` | `loadClass`、`loadClassBinaryName`、`findClass`…（另有 `java.lang.BootClassLoader`） |
| `android.app.ActivityThread` / `AppBindData` | `currentActivityThread`、`mBoundApplication`、`activityStart`、`LoadedApk.mApplication` |
| JNI 注册 | `ArtMethod::RegisterNative` 监视（日志输出 soName/soBaseAddr/funcName/funcAddr/**file offset**——该日志本身即给出 JNI 实现的文件偏移（本研究的偏移定位方法）） |

**observed — 行为特征**：
1. `forceInterpret` 调用：将受保护方法压入解释器模式（抗 inline/JIT hook）。
2. 线程 `xiaojianbang-Monitor-<pkg>`：启动后 ~1s 创建、随后退出（debuggerd 全线程快照中已不存在）。
3. 原生库搜索路径字面量 `/data/local/tmp/xiaojianbang/lib64`（设备上该目录**不存在**，为可选投放点）。
4. R8 合成访问器名（`-$$Nest$fgetmCookie` 等）证明其为**编译后 Java 代码**，且需要读 `DexFile.mCookie` 内部字段。

**unknown — 未定位项（明确标注）**：组件代码容器与字符串解密器。已排除 9 条路径（61 so 明文/单字节XOR、根 dex×3、payload dex×3、assets 指令表、运行时 dex zip（与 payload 同哈希）、arsc UTF-16、oat_primary、三库全映射段内存镜像）。
**跨层结论（inferred）**：其检查面为 **dex 注入 / ClassLoader / ActivityThread 替换**，**不覆盖** kernel 硬件断点（HWBP）——即：内核层硬件断点类观察手段不在其检查面内；本次退出事件与之无关（UsbReceiver 已实证，见 A6）。

**后续定位步骤（未执行）**：对 DPT 载体 `lib1f4392dc99afe4a4.so` 做 IDA 字符串解密器定位（其把明文写入 ART 堆而非自身数据段），或用 HWBP 挂 `pthread_setname_np` 于启动窗口抓监控线程 start_routine。

## A10. 监控组件宿主定位：强化取证与结论（2026-11-15 00:10，第 35 轮）

**新增排除证据（observed）**：
1. **dalvik-main-space 全量 dump 解析**：256MB（`0x14000000-0x24000000`）拉回后按 `dex\n035/037/038/039\0` 全变体扫描 → **候选 0**。ART 10+ 从 `base.vdex`（10MB rw-p 映射）与 `code_cache/i11111i111.zip`（4MB，成员哈希与恢复 payload 完全一致）加载 dex，**堆内无 dex 本体**。
2. **混淆模型扫描**：APK 内 64 二进制 × 4 目标串 × **766 变体**（反转/XOR 1-255/加 1-255/减 1-255）→ **零命中**。
3. **DPT 载体功能判定**（A9 之上补充）：`fork`/`waitpid`/`pthread_create`/`access` 在载体中**真实调用者=0**（仅模板导入）；载体与框架无关。
4. **HPROF 堆转储**：`am dumpheap` 被拒（non-debuggable，需 debuggable 属性，未在本研究环境达成）→ 类加载器级取证被系统策略阻断。

**结论**：框架字符串为**运行时构造**（非文件明文、非单/双字节编码、非内存 dex）；其类来自 vdex/zip 内某个 dex，代码级定位需以下任一尚未具备的能力：
- 带 **LR 输出**的断点捕获（现有 KPM CLI 仅输出 X0-X7/RET）；
- **堆对象遍历**（String→Class→DexFile 溯源）；
- 改 **debuggable** 后 HPROF（与"原始样本只读"原则冲突）。

**状态标注**：监控组件的**行为面**=observed（A8 目标表）；**代码逻辑**=unknown（能力缺口，非样本性质）；**是否检测 HWBP**=observed 否（其目标表中无调试寄存器/内核断点相关项，且 kernel HWBP 在 EL0 不可见）。

## A12. Eagle SDK native 检测（26.10.135，第 38 轮重做）——libeagle_sdk.so arm64

> 工具：`idat.exe -A -B` 建库（3.8MB，782 函数）→ `triage_one.py` 字符串/导入 triage → `export_eagle_detections.py` Hex-Rays 全量导出（产物 `_work/2610/eagle_native_detections.md` 23KB）。导出/命名符号：`Java_io_eagle_sdk_AntiEngine_info1`@0x6277、`info2`@0x629a。

### A12.1 判定入口：native 字符串返回（observed）
`AntiEngine.info1()` → `Java_io_eagle_sdk_AntiEngine_info1`（无参）；`info2(String)` → 传属性名，返回单值字符串。Java 侧 `AntiEngine.isSafe(String)` 判断字符串是否为 `"0:..."` 形式（详见 A13 Java 侧）。

### A12.2 ROOT 检测 `sub_144B8` @0x144B8（1100B，observed）
8 条固定路径，逐条 `sub_13F8C()`（access 封装）；命中即 `qword_56040 = strdup(命中路径)` 并返回 1：
```c
strcpy(v12, "/system/bin/su");
strcpy(v15, "/product/bin/su");
strcpy(v16, "$/data/local/bin"); strcpy((char*)&v16[2]+1, "su");   // /data/local/bin/su
strcpy(v18, "/system/xbin/su");
strcpy((char*)v19, "*/system/xbin/which/su");                       // /system/xbin/which/su
strcpy((char*)v20, "$/data/local/xin"); strcpy((char*)&v20[2]+1,"su"); // /data/local/xin/su
strcpy((char*)v21, "$/data/local/bin"); strcpy((char*)&v21[2]+1,"su"); // /data/local/bin/su
strcpy((char*)ptr, "/system/bin/failsafe/su");
... if (sub_13F8C(path) & 1) { qword_56040 = strdup(path); return 1; }  // 任一命中
return 0;
```
**行为**：仅记录命中路径（`qword_56040`），不主动退出；结果字符串由 info1() 汇总上抛 → 进入 A11 上报链。

### A12.3 mount 扫描 `sub_14910` @0x14910（1224B，observed）
依次读 `/proc/mounts` → 失败退 `/proc/self/mountstats` → `/proc/self/mountinfo` → `/proc/self/maps`（`sub_13FA8` 读文件成功判定），命中栈内关键字表后调用 `sub_15508()`（拼接结果串）：
```c
v10 = 0x757269722F0A;        // "\n/riru"
v13 = 0x2D757269720A;        // "\nriru-"
v16 = 0x707864652F0A;        // "\n/expd"
v19 = 0x6465736F70736C0E;    // "\nlsposed"（0x0E=长度前缀）
strcpy(v23, "magisk"); strcpy(v27, "Magisk");
strcpy(&v30[1], "/appwid"); strcpy(v31, "et");   // "/appwide t"? 组合串
```
**语义（inferred）**：扫描 mount 信息中的 Magisk/Riru/LSPosed/expd 等注入框架痕迹与可疑挂载点。

### A12.4 模块目录扫描 `sub_14DD8` @0x14DD8（1840B，observed）
固定目录字面量：`/data/adb/modules`、`/data/adb/`、`\n/riru`、`\n/expd`、`\nlsposed`（0x0E 长度前缀）；存在即记录（`opendir/readdir` 遍历）。
**语义**：检测 Magisk/Riru/LSPosed 模块目录。

### A12.5 模拟器特征 `sub_15684` @0x15684（1088B，observed）
按序 `sub_13F8C()` 探测并返回命中路径：
```c
"/system/bin/androVM-prop" → "/system/bin/microvirt-prop" → "/system/lib/libdroid4x.so"
→ "/system/bin/windroyed" → "/system/bin/nox-prop" → "system/lib/libnoxspeedup.so"
→ "/system/bin/ttVM-prop" → "/data/.bluestacks.prop" → "/system/lib/libc_malloc_debug_qemu.so"
```
**行为**：返回命中特征路径（长度前缀封装），供 info1() 汇总。

### A12.6 敏感导入（observed）
`prctl`@0x13AD0、`syscall`@0x13BE0、`dl_iterate_phdr`@0x13950、`__system_property_get`@0x13F00、`access`@0x139E0、`opendir`@0x13AF0、`readdir`@0x13D70（各 1 处调用者，均为独立检测子函数）。

### A12.7 同批 triage 结论：其余库无安全检测（observed）
| 库 | 函数数 | 命中 | 判定 |
|---|---|---|---|
| libmonitorhub.so | 2436 | 仅 "Friday"（日期格式串） | 无检测（阿里监控 SDK） |
| libdps.so | 4557 | root_path 日志串、TraceListener 类名 | 无检测（阿里 DPS） |
| libqueen.so | 2057 | "Friday"、人脸检测 API 名 | 无检测（淘宝 Queen） |
| libRtsSDK.so | — | 待读 triage | 待定 |

## A13. Eagle SDK Java 层检测（26.10.135，第 39 轮）——`io.eagle.sdk.AntiEngine.info0`

**入口**（observed）：`AntiEngine.info0(Context)` 汇总全部判定，返回 `"0:<详情串>"` 或 `"1:<详情串>"`；`isSafe(s)` 以 `"0:"` 前缀判安全。native 侧 `info1()`/`info2(String)` 见 A12。

**逐项检测（observed，jadx 反编译 `_work/2610/jadx/sources/io/eagle/sdk/AntiEngine.java`）**：
| 项 | 判定 | 阈值/常量 |
|---|---|---|
| native 汇总 | `info1()` 非 `0:` 则计入 | — |
| 风险包 | `io.eagle.sdk.a.a.a(ctx)`：`getPackageInfo("io.github.vvb2060.magisk")` 成功 → `1:发现当前环境存在风险App` | 包名数组 `{"io.github.vvb2060.magisk"}` |
| SELinux | 读 `/sys/fs/selinux/enforce` 首字节，`!=48('0')` → `1:SELinux已关闭` | 字节 48/49 |
| 指纹 | `Build.FINGERPRINT.contains` | `{"generic","vbox"}` |
| 型号 | `Build.MODEL.contains` | `{"google_sdk","emulator","android sdk built for","droid4x"}` |
| 厂商 | `Build.MANUFACTURER.contains` | `{"Genymotion"}` |
| 产品 | `Build.PRODUCT.toLowerCase().contains` | `{"google_sdk","sdk_phone","sdk_x86","vbox86p","nox"}` |
| 主板 | `Build.BOARD.toLowerCase().contains` | `{"nox"}` |
| Bootloader | `Build.BOOTLOADER.toLowerCase().contains` | `{"nox"}` |
| 硬件 | `Build.HARDWARE.equalsIgnoreCase` | `{"ranchu","vbox86","goldfish"}` |
| 网络 | 遍历 `NetworkInterface` 非回环地址收集 | （jadx 丢失具体 IP 比较，原判定见 A13 备注） |
| 系统特性缺失 | `hasSystemFeature` 为假 | `android.hardware.bluetooth`、`android.hardware.camera.flash`、`android.hardware.telephony` |
| 模拟器包 | `getPackageInfo` 查询 | `com.google.android.launcher.layouts.genymotion`、`com.bluestacks`、`com.bignox.app` |
| 传感器 | `getDefaultSensor(i)` 为 null 计数 | 索引 0..size-1 |
| 号码 | `getLine1Number()` 命中列表 | `15555215554` 起、步长 2、共 16 个到 `15555215584` |
| 相机 | `CameraManager.getCameraIdList().length`（需 `< 2`） | 2 |
| 机器码/attestation | `io.eagle.sdk.ext.attestation.h` + `ro.boot.verifiedbootstate` | 见 A12 info2 与 A13 备注 |

**返回聚合**（observed）：
```java
StringBuilder sb = new StringBuilder();
sb.append(z2 ? "0" : "1").append(":");
sb.append(stringJoiner);     // 每条命中项的细节，": " 分隔
return sb.toString();
```

**备注（unknown）**：网络判定段 jadx 反编译丢失了 `10.0.2.15/10.0.2.16` 一类具体比较（`arrayList.add(hostAddress)` 缺条件），需按 smali 复核；attestation 段（`ext.attestation.h`）本次未逐行复原，标 unknown。

## A14. Java 层模拟器/设备采集（26.10.135，第 39 轮）

### A14.1 `com.<vendor>.<app>.mvp.ui.utils.i`（observed）
| 判定 | 命令/API | 阈值 |
|---|---|---|
| 闪光灯特性 | `hasSystemFeature("android.hardware.camera.flash")` 为假 → 判模拟器 | — |
| 传感器数 | `getSensorList(-1).size()` | `<= 10` → 模拟器 |
| 用户安装软件数 | `pm list package -3` 的 `package:` 计数 | `<= 3` → 模拟器 |
| 进程组 | `cat /proc/self/cgroup` 结果为空 → 模拟器 | 空串 |
| 拨号能力 | `Intent(ACTION_DIAL, tel:123456).resolveActivity` 为 null | — |
| 名称加权 | 模拟器名称含 `ttvm`/`nox` → 直接 +10 分 | 10 |
**汇总**：各子项命中累加为风险分（`i3`），并生成 `模拟器渠道/名称/传感器数量/软件数量/进程组/拨号` 详情串。

### A14.2 `com.<vendor>.<app>.mvp.ui.utils.g`（observed）
- 读 `/proc/cpuinfo`（`FileReader` 逐行）
- 读 `/proc/meminfo`（`FileReader`）
→ 用于机型/CPU/内存信息展示与上报字段，**非安全判定**（inferred）。

### A14.3 `com.<vendor>.<app>.app.utils.f`（observed，非检测）
按 `Build.MANUFACTURER` 跳转各家权限页（HUAWEI/vivo/OPPO/Coolpad/Meizu/Xiaomi/samsung/Sony/LG），其中 Xiaomi 分支 `Runtime.exec("getprop ro.miui.ui.version.name")` 仅用于选择权限页 Intent —— **权限适配，不是检测**。

## A16. 原生库全量 triage 汇总（26.10.135，第 41 轮）——28 库判定表

**方法**（observed）：`idat -A -B` 全量建库（29 个 arm64 库）→ `triage_one.py` 对每库做
①10 类字符串指标（root/调试/frida/xposed/模拟器/proc/属性/路径/端口/检测词）× xref 函数
②22 项敏感导入调用者；随后对灰区逐函数 Hex-Rays 核实（R4）。

| 库 | 函数数 | 判定 | 依据 |
|---|---|---|---|
| **libeagle_sdk.so** | 782 | **有安全检测** | A12：su 8 路径 / mount 扫描 / /data/adb 模块 / 模拟器 9 特征 |
| libijkffmpeg.so | 7,343 | 无 | 命中全为 ffmpeg 日志串（"sample rate change detected…"、"root atom offset"） |
| libalivcffmpeg.so | 15,548 | 无 | 命中为 libxml（xmlDocGetRootElement 等）与 openssl DRBG |
| libgaea.so | 13,006 | 无 | `/proc/%d/maps` = `android::MapInfo::getMapInfoList()`（本进程 maps，崩溃符号化）；`is_root_separator` = boost::filesystem 断言；`__GetRootCAList` = 根 CA 列表；/proc/net/* = 网络统计 |
| libqueen.so | 2,057 | 无 | 仅人脸检测 API 名 / "Friday" |
| libdps.so | 4,557 | 无 | 仅 log4gaea/TraceListener 名称 |
| libmonitorhub.so | 2,436 | 无 | 仅 trace 埋点 API |
| libsaasCorePlayer.so | 11,273 | 无 | `GetProperty*` 为播放器 API；/proc/cpuinfo|meminfo|statm = 性能统计；`ro.product.model` 读取（设备信息） |
| libRtsSDK.so | 5,366 | 无 | webrtc `root_producer_manager`、ICE 127.0.0.1、trace 日志 |
| liblive-pusher.so | 8,861 | 无 | google_breakpad（崩溃收集，ptrace 属其内部）；`ro.product.model/brand/manufacturer` 设备信息采集 |
| libopenssl.so | 7,587 | 无 | trustRoot/root ca（TLS 语义） |
| libsqlite3.so | 1,245 | 无 | rootpage（SQL 字段）、sqlite3_trace/hook（API） |
| liblive-fdkaac.so | 1,564 | 无 | FDK-AAC 的 Detect 类算法名 |
| libchat/libdoc/liblive/librtc/libwb/libroom/libsceneclass/libscenelive/libsaasDownloader/libpl_droidsonroids_gif/libcicada_plugin_artcSource/libdmojo_support/libfml/liblive-rtmp | 203–3,608 | 无 | 无指标命中，或仅 API/日志名 |

**结论（observed）**：26.10.135 的**原生安全检测集中于 `libeagle_sdk.so`**（A12），其余 27 个 arm64 库无安全检测逻辑；`libijkplayer.so`（业务层，5,707 函数）含风控上报的 native 组装函数（A11.4）与 DRM 密钥链，但无安全检测分支。
**数据采集面（非检测，inferred）**：`ro.product.model/brand/manufacturer`（live-pusher、saasCorePlayer）、`/proc/cpuinfo|meminfo`（g、saasCorePlayer、live-pusher）、APK 路径与 ZIP 注释（A15）——均进入上报或统计通道。

### A11.6 触发条件与开关（第 42 轮补证，observed）
```java
// MainActivity L793-794：60 秒周期、60 秒初始延迟
long j2 = 60000;
new Timer().schedule(new t1(this, this), j2, j2);

// t1.run()：状态变化触发（N 标志）+ 隐私同意门槛
if (z5 != J) { J = z5; N = true; }      // z5 = 投屏判定
if (z6 != K) { K = z6; N = true; }      // z6 = UsbManager.getDeviceList().size() > 0
if (z7 != L) { L = z7; N = true; }      // z7 = BATTERY_CHANGED plugged == 2
if (N && pref.a("loginPrivacy", false)) {
    String strB    = g.b(ctx);           // 设备信息串
    String strInfo0= AntiEngine.info0(ctx);  // Eagle 检测汇总（A12/A13）
    int iA  = pref.a("key_screenshot2");          // 截屏检测开关
    int iA2 = pref.a("key_sounddeten");           // 声音检测
    int iA3 = pref.a("key_closesoftware");        // 关闭软件
    int iA4 = pref.a("key_closeprocess");         // 不关闭进程
    int iA5 = pref.a("key_capturecard");          // 采集卡
    int iA6 = pref.a("key_softwarerippingcheck"); // 软件撕裂检测
    d.a(ctx, strB + "--<Android虚拟机>" + strInfo0 + "--" + SOFTWARE_NAME + ...);
}
```
**投屏判定（observed，t1.run 内）**：`new Socket("localhost",7236)` 连通 → 投屏；否则 `new DatagramSocket(7236)` 绑定成功 → 投屏；否则 `ServerSocket(7236)` 状态异常 → 投屏；另有 IPv6/`173.` 前缀判断。
**含义（observed）**：上报只在「投屏/USB/充电 状态发生变化 且 已同意隐私」时触发；六个开关来自 SharedPreferences（`key_screenshot2/key_sounddeten/key_closesoftware/key_closeprocess/key_capturecard/key_softwarerippingcheck`），随字符串一并上报。
