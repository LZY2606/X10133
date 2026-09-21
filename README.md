# 产物核验站（artifactproof）

把同一份源码快照在不同机器上生成的归档（zip / tar / tar.gz / tar.bz2 / tar.xz）
放进本站，安全地生成规范化清单，并把差异分离为**真实内容差异**与**可忽略差异**，
最终给出一条可复现性结论，可导出**字节稳定的 JSON 证明**。

全部使用 Python 标准库实现，处理完全离线。

## 安装

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

## 测试与演示

```bash
.venv/bin/pytest -q
.venv/bin/python -m artifactproof --host 127.0.0.1 --port 5218
```

打开 <http://127.0.0.1:5218>，页面标题为“产物核验站”。

## 使用

1. 把两份归档分别拖入 A / B 两个区域（或从“已上传归档”中选择）。
2. 勾选/保存版本化策略：可忽略时间戳、uid/gid、权限掩码位、压缩参数、成员顺序。
3. 点击“开始比较”，查看归档级差异、逐成员差异、成员集合差异与最终结论。
4. “导出字节稳定 JSON 证明”下载带 `proof_hash` 的规范化 JSON（重复导出字节一致）。

数据默认持久化在 `./.artifactproof-data`，可用 `--data-dir` 或环境变量
`ARTIFACTPROOF_DATA` 修改；重启后上传、策略、比较记录都保留。

## 规范化清单成员字段

`order`（归档内原始顺序）、`path`、`type`（file/dir/symlink/hardlink/other）、
`mode`（八进制）、`size`（含稀疏文件的逻辑大小）、`content_hash`（`sha256:` 前缀）、
`link_target`、`mtime`、`uid`、`gid`。

## 安全模型

- 绝不向工作目录或临时目录解包；成员数据只流经内存并在读取时计入解压预算。
- 不跟随符号链接：链接纯词法解析，逃逸归档根或成环即整份隔离。
- 重复路径、绝对路径、上跳路径、链接逃逸/成环、悬空硬链接、稀疏元数据异常、
  解压体积超预算（默认 100 MiB）、归档损坏或无法识别：**整份归档进入隔离状态**。
- 隔离后仍可查看已安全确认的成员前缀与明确原因；不会留下部分解压文件。
- 相同上传字节复用同一个内容寻址 blob；比较会话彼此独立。
- 策略只改变比较视图与结论，原始清单永不改写；清理 blob 前会校验无上传/会话引用。

## 结论

- `reproducible`：在所选策略下完全一致。
- `equivalent_under_policy`：仅剩策略声明为可忽略的差异。
- `content_differs`：存在真实内容差异（成员字节、类型、链接目标、集合等）。
- `quarantined`：至少一份归档隔离，无法判定。

## 目录结构

- `artifactproof/scanner.py`：安全流式扫描（zip/tar）。
- `artifactproof/compare.py`：比较引擎与证明构造。
- `artifactproof/policy.py`：版本化策略。
- `artifactproof/storage.py`：blob 存储、SQLite 持久化、引用保护 GC。
- `artifactproof/web.py` / `web_assets/`：离线 HTTP API 与页面。
- `tests/`：手工构造归档的场景测试（不依赖系统 tar 文本输出）。
