# 风控上报链路

> 脱敏：上报内容的**结构**保留（采集字段、组装层次、传输与失败策略），
> 密钥材料构成、派生算法、真实域名与可用常量全部移除。

## A11. 风控上报链路（26.10.135，第 37 轮重做）——Java 采集 + native 组装 + AES + HTTP

### A11.1 上报入口（observed，jadx）
```java
RequestFeedback rf = new RequestFeedback();
rf.setUserId(king.d.a(j.b().b("user_id"), JniUtils.getInstance().keyMaterial()(789)));
String paths = JniUtils.getInstance().pathBlob()(789);              // native：路径串
String qm    = com.<vendor>.<app>.app.utils.b.a(MyApplication.c());  // APK 签名 SHA-256
String suffix = ";qm:" + qm;
rf.setContent(king.d.b(str + paths + suffix + JniUtils.getInstance().timeDelta()(789),
                       JniUtils.getInstance().keyMaterial()(789)));    // AES 加密内容
rf.setSoftwareType("LocalPlayer");
rf.setWeight(6);
rf.setType("J");
userService.feedbackInfo(rf)
  .retryWhen(... zipWith(Observable.range(1,3)) ... flatMap(o -> Observable.timer(3, SECONDS)))
  .subscribeOn(io).observeOn(main).subscribe(new b(...));
```
**失败路径**（observed）：`onError` 与 `!isSuccess` 都执行 `new h().start()`；`h.run()` = `Thread.sleep(15000)` → `MyApplication.c().b()`（进程退出）。**= 15 秒延时退出开关**。
**重试语义**（observed）：`d.a(Throwable,Integer)`：`num < 4` 返回 num，否则 rethrow → 最多 4 次、间隔 3 秒。

### A11.2 上报内容构造（observed，`MainActivity$t1.run()`）
```java
boolean usb = ((UsbManager)ctx.getSystemService("usb")).getDeviceList().size() > 0;
Intent it = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
boolean charging = it.getIntExtra("plugged", -1) == 2;
d.a(ctx, strB + "--<Android虚拟机>" + strInfo0 + "--" + SoftwareName.SOFTWARE_NAME
      + ",是否投屏：" + J + ";是否连接usb:" + K + ";是否充电:" + L + ";是否多屏幕：" + M
      + ";是否jiet:" + iA + ";声音是否检测:" + iA2 + ";不检查采集卡:" + iA3
      + ";不关闭进程:" + iA4 + ";超强cj卡:" + iA5 + ";软件fl检测:" + iA6);
```
**逐字段含义（inferred，依据命名与调用点）**：是否投屏 J（TCP/UDP 7236 探测结果）、是否连接usb K、是否充电 L、是否多屏幕 M、jiet/声音检测/采集卡/不关闭进程/超强cj卡/软件fl检测 = 配置开关与检测结果标志。

### A11.3 签名指纹 `com.<vendor>.<app>.app.utils.b.a(Context)`（observed）
取 `PackageManager.getPackageInfo(pkg, 0x8000000).signingInfo` → `apkContentsSigners`（空则 `signingCertificateHistory`）→ 每个证书 `SHA-256` 大写十六进制，逗号拼接并缓存到静态字段。**用途：上报字段 `;qm:` = 安装包签名指纹**。

### A11.4 native 组装（observed，IDA Hex-Rays，libijkplayer.so arm64）
`keyMaterial()()` @0x<redacted>（AES 密钥材料）：
```c
[长度派生已脱敏]&v2);
v0 = strcat((char*)&out1, (const char*)&<material-global>);   // <material-global> = 500B 全局材料
strcat(v0, (const char*)&v2);                       // 材料 + 计数器十进制
```
`pathBlob()()` @0x<redacted>（路径串，前 10 字节为字面量 "lujing1"/"lujing2"/"suiling"）：
```c
*(u64*)v0 = 0xEF31676E696A756C; strcat(s, (char*)&<material-global>);   // "lujing1" + <material-global>
*(u64*)v1 = 0xEF32676E696A756C; strcat(s, (char*)&<material-global>);   // "lujing2" + <material-global>
*(u64*)v2 = 0xEF676E61696C7573; [长度派生已脱敏]v5); strcat(s,(char*)v5); // "suiling"+计数
```
`timeDelta()()` @0x<redacted>（时间差）：
```c
TimeStamp = getTimeStamp(true);
[长度派生已脱敏];   // 当前时间戳 - 基线
if (strlen(s) >= 4) { strncpy(dest, &dest[strlen(s)+1], 3); dest[3]=0; }  // 取尾部 3 字符
```
**JNI 注册表（observed）**：上报链 5 个方法经 `RegisterNatives` 动态注册（材料推送 ×2、计数 ×1、时间差 ×1、密钥材料 ×1），另 1 个为静态导出符号；<注册偏移已脱敏>。
**全局材料**：`<material-global>`/`<material-global>`/`<material-global>`（各 500B）由 Java 侧 `<native-fn>`*(String,int)` 写入——即**服务端/本地下发的材料进入 native 全局**，再作为 AES 密钥与路径串参与上报。

### A11.5 端点（observed，dex 字符串）
`https://video.<redacted-domain>`（API 基域）、`https://rn.<redacted-domain>/`、`http://qiliu.prd.<redacted-domain>/`、`https://qiliuprd.<redacted-domain>/`；`feedbackInfo` 为 Retrofit 接口（UserService）。

**待续（unknown）**：`str` 传入处全部调用点；`iA/iA2..iA6` 六个开关的实际赋值来源；`<material-global>` 材料写入时机与内容；`pathBlob()` 中 lujing1/2 的实际路径值来源。


