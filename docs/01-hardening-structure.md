# 加固结构

> 脱敏：壳的密钥常量与加载器内部偏移已移除。

## A1. 保护结构剧变（observed）

1. **IJK YUND 层整体移除**：新 `libijkplayer.so` 无内嵌 LZMA 载荷（熵扫描验证，对照对照版本 0x109000 处 481KB 载荷）、无 YUND 魔数引用、无自定义 ELF loader；JNI_OnLoad 为标准 ijkplayer（RegisterNatives 37 标准方法）。
2. **业务 native（JniUtils/解密链/媒体状态机）明编译进 libijkplayer.so**，且**导出符号带名**（无 .symtab，.dynsym 3,908 定义符号可读）。
3. DPT 壳层布局不变：`lib1f4392dc99afe4a4.so` 11/11 布局断言通过（RC4 key 位/恒等置换块原址）；ABI 收缩 x86/x86_64 移除。
4. 57/61 so 字节级同对照版本（含 Eagle/ffmpeg/全部 SDK/普通库）→ 其检测结论继承，仅引用新哈希。
5. DEX 布局重构：壳 classes.dex(6 桩) + classes2(3,659 桩类混淆) + classes3(680)；业务 DEX 仍走指令表（`assets/OoooooOooo` 新 1,862,864B）+ `d_shell_data_001`（340B JSON 配置）。


