"""IDA 分诊脚本：对单个 .so 数据库做检测候选定位。

用法（headless）:
  idat.exe -A -S"triage_one.py" <lib.so.i64>

产出:
  <cwd>/triage/<lib>.triage.json   分类命中 + 引用函数 + 敏感导入调用者
  <cwd>/triage/<lib>.triage.md     人读摘要

说明：本脚本只做索引与统计，不判定「有无检测」；判定必须回到反编译逐函数核对。
""" """对单个 arm64 IDA 库做检测候选 triage：字符串指标 → 函数 xref；敏感导入清单。
用法: idat -A -S"triage_one.py" <db.i64>
输出: <db 目录>/../triage/<lib>.triage.json + .md
"""
import idaapi, ida_funcs, ida_name, idautils, idc, ida_bytes
from pathlib import Path
import json, os, re

OUTDIR = Path(os.environ.get("TRIAGE_OUT", Path.cwd() / "triage"))
OUTDIR.mkdir(parents=True, exist_ok=True)

CATS = {
 "root":       ["/system/bin/su", "/system/xbin/su", "/sbin/su", "which su", "supersu", "magisk", "busybox", "/su", "root"],
 "debug":      ["ptrace", "TracerPid", "gdb", "lldb", "android_server", "gdbserver"],
 "frida":      ["frida", "27042", "gum-js-loop", "linjector", "re.frida", "gadget"],
 "xposed":     ["xposed", "XposedBridge", "de.robv", "lsposed", "edxposed"],
 "emulator":   ["goldfish", "qemu", "ranchu", "vbox", "genymotion", "bluestacks", "nox", "android_x86", "ttVM", "VirtualBox"],
 "proc":       ["/proc/self/maps", "/proc/self/status", "/proc/net/tcp", "/proc/cpuinfo", "/proc/meminfo", "/proc/self/cgroup", "/proc/%d", "/proc/"],
 "props":      ["ro.debuggable", "ro.secure", "ro.build.tags", "ro.boot.verifiedbootstate", "ro.boot", "getprop", "service.adb", "ro.product"],
 "paths":      ["/data/local/tmp", "/data/adb", "/system/xbin", "/system/lib", "/sbin", "/dev/socket"],
 "net":        ["127.0.0.1", "localhost", "23946", "5555"],
 "detectword": ["detect", "risk", "hook", "trace", "anti", "checkdebug", "isanomal"],
}
IMPORTS = ["ptrace", "prctl", "fork", "vfork", "kill", "waitpid", "inotify_init", "syscall",
           "dl_iterate_phdr", "getauxval", "__system_property_get", "access", "stat", "readlink",
           "opendir", "readdir", "fopen", "popen", "getpid", "gettid", "uname", "socket", "connect"]

def libname():
    p = idaapi.get_input_file_path()
    return Path(p).name

def main():
    lib = libname()
    result = {"lib": lib, "imagebase": hex(idaapi.get_imagebase()),
              "func_count": sum(1 for _ in idautils.Functions()),
              "categories": {}, "imports": {}}

    # 1) 字符串指标（按类别）
    allstr = {}
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        allstr[s.ea] = v
    for cat, kws in CATS.items():
        hits = []
        for ea, v in allstr.items():
            lv = v.lower()
            for kw in kws:
                if kw.lower() in lv:
                    # 找引用该字符串的函数
                    funcs = set()
                    for x in idautils.XrefsTo(ea, 0):
                        f = ida_funcs.get_func(x.frm)
                        if f: funcs.add((f.start_ea, ida_name.get_name(f.start_ea) or f"sub_{f.start_ea:x}"))
                    hits.append(dict(ea=hex(ea), value=v[:160], kw=kw,
                                     funcs=[dict(ea=hex(a), name=n) for a, n in sorted(funcs)][:6]))
                    break
        if hits:
            result["categories"][cat] = hits

    # 2) 敏感导入
    for imp in IMPORTS:
        ea = ida_name.get_name_ea(idaapi.BADADDR, imp)
        if ea != idaapi.BADADDR:
            callers = set()
            for x in idautils.XrefsTo(ea, 0):
                f = ida_funcs.get_func(x.frm)
                if f: callers.add(f.start_ea)
            result["imports"][imp] = [hex(c) for c in sorted(callers)][:10]

    (OUTDIR / f"{lib}.triage.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")

    # 3) 摘要 md
    lines = [f"# {lib} 检测候选 triage\n",
             f"- 函数数: {result['func_count']}  imagebase: {result['imagebase']}\n"]
    for cat, hits in result["categories"].items():
        lines.append(f"\n## {cat} ({len(hits)} 命中)\n")
        for h in hits[:25]:
            lines.append(f"- `{h['value']}` @{h['ea']} kw={h['kw']} funcs={[f['name'] for f in h['funcs']][:3]}\n")
    lines.append("\n## 敏感导入\n")
    for imp, cs in result["imports"].items():
        lines.append(f"- {imp}: {len(cs)} callers {cs[:4]}\n")
    (OUTDIR / f"{lib}.triage.md").write_text("".join(lines), encoding="utf-8")
    print(f"[+] triage {lib}: cats={list(result['categories'])}, imports={list(result['imports'])}")

main()
