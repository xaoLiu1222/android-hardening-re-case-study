# Android 加固与风控逆向案例研究：DPT 壳、检测面与上报链路

> A Case Study in Android Hardening & Risk-Control Telemetry: DPT Shell, Detection Surface, and Upload Chain

**这是一份静态分析研究报告，不是破解工具。** 仓库只包含**方法论、结构与结论**（另附一个通用 IDA 分诊脚本）；
样本二进制、密钥、密钥构造参数、可操作函数偏移、解密工具与课程内容**全部未发布**。

---

## 研究什么

以一款商业课程播放器 App（Android，26.10.135）为对象，回答三个问题：

1. **它的加固是怎么搭的？** —— DPT 系壳（DEX 加密 + 指令表 XOR + 尾部 ZIP）、原生层 ABI 收缩与保护层移除
2. **它检测什么？** —— 反作弊 SDK 的 root / 注入框架 / 模拟器判定，以及 Java 层的设备与环境判定
3. **它上报什么、怎么处置？** —— 采集字段 → 原生组装 → 加密 → HTTP 上报 → **失败后的延时退出策略**

## 主要结论

| 面 | 结论 |
|---|---|
| 加固 | DPT 系壳三要素（加密载荷、指令表变换、尾部容器）+ 原生 ABI 收缩与保护层移除；业务 DEX 恢复流程见 [01](docs/01-hardening-structure.md) |
| 原生检测 | **仅 1 个库携带安全检测**（反作弊 SDK）：su 路径探测（7 个唯一路径）、挂载点扫描（magisk/riru/lsposed/expd）、模块目录、9 类模拟器特征；四个检测函数由同一 native 入口 `info1()` 调用 |
| Java 检测 | 反作弊 SDK 汇总入口逐项判定（包名/SELinux/Build 常量表/系统特性/模拟器包/传感器/号码段/相机/硬件证明）；另有独立的模拟器判定（传感器数、三方包数、cgroup、拨号能力） |
| 上报链路 | 状态变化触发（投屏/USB/充电）+ 隐私同意门槛；60 秒定时；内容 = 环境标志串 + 设备串 + 检测汇总 + 签名指纹 + 时间差；加密后走单一 HTTP 接口；**失败或服务端非成功 → 15 秒后进程自杀** |
| 其余 27 库 | 未发现安全检测（[A16 判定表](docs/02-detections.md)：28 库分诊，1 库命中）；命中项逐条归因（libxml/openssl/ffmpeg/breakpad/WebRTC/SQLite/APM 埋点等） |

详见 [`docs/`](docs/)。

## 目录

- [`docs/01-hardening-structure.md`](docs/01-hardening-structure.md) — 加固结构（壳、ABI、保护层）
- [`docs/02-detections.md`](docs/02-detections.md) — 检测面（原生 + Java + 退出策略 + ART 自保护框架行为面）
- [`docs/03-risk-control-chain.md`](docs/03-risk-control-chain.md) — 风控上报链路（结构级）
- [`docs/04-native-triage.md`](docs/04-native-triage.md) — 原生库检测分诊方法论（可复用）
- [`docs/05-timeline.md`](docs/05-timeline.md) — 研究阶段划分（七阶段 + 未闭合项）
- [`scripts/triage_one.py`](scripts/triage_one.py) — IDA 分诊脚本（字符串指标 + 敏感导入 xref）
- [`SECURITY.md`](SECURITY.md) — 安全政策（误披露 / 勘误 / 权利异议渠道）
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — 贡献指南（可贡献项、标注制度、禁止项）

## 方法论要点

- **只用 IDA** 做反编译（`idat -A -B` 建库，Hex-Rays 读码），其余环节用脚本做索引与统计
- **分诊 → 灰区核实**：先按 10 类字符串指标 + 22 项敏感导入定位候选，再对候选逐函数判读
- **逐条归因**：任何「无检测」结论都必须给出误报归因（子串碰撞 / 框架 API / 崩溃收集器 / 性能统计 …）
- **标签制度**：`observed`（跑出证据）/ `inferred`（推理）/ `unverified`（他处声称）/ `unknown`（未覆盖）

## 已知局限

1. 「未发现检测特征」≠「不存在检测」——无字面量的检测会漏过分诊
2. 单 ABI 覆盖（另一 ABI 未分诊）
3. 硬件证明（attestation）判定细节未逐行复原
4. 加密材料的单项折算算法未解

## License

- 文档（`docs/`、`README.md`）：**CC BY-NC 4.0** — 全文见 [LICENSE-DOCS](LICENSE-DOCS)
- 脚本（`scripts/`）：**MIT** — 全文见 [LICENSE-SCRIPTS](LICENSE-SCRIPTS)
