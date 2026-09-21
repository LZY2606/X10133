# 产物核验站（artifactproof）

离线、可复现的归档产物核验站。把“同一份源码快照在不同机器上打出来的归档”
拖进来，系统安全地列出成员、生成规范化清单，并区分：

- **真实内容差异**：成员缺失/新增、类型不同、内容哈希不同、链接目标不同；
- **元数据差异**：时间戳、uid/gid、权限（可设掩码）、压缩参数、sparse 排布、打包顺序；
- **可忽略差异**：由所选版本化策略声明可忽略的因素，只改变比较视图。

策略永远不会改写原始清单。相同上传字节复用同一个内容寻址 blob；每次比较生成
独立会话，并可导出**字节稳定的 canonical JSON 证明**。

## 安装

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

仅依赖 Python 标准库运行；测试依赖 `pytest`。若 venv 自带 pip 较旧（<21.3），
先 `.venv/bin/pip install -U pip setuptools wheel`。

## 演示

```bash
.venv/bin/pytest -q
.venv/bin/python -m artifactproof --host 127.0.0.1 --port 5218
```

打开 <http://127.0.0.1:5218>，页面顶部显示“产物核验站”。

可选参数：`--data 目录`（默认 `.artifactproof`）、`--budget 字节`
（单个归档解压逻辑体积预算，默认 100 MiB）。

## 安全模型

- **从不解压到工作目录**：成员数据只在内存流中增量读取并计算 SHA-256，
  异常时不产生任何部分解压文件。
- **不跟随符号链接**：只记录链接字面目标，绝不打开其目标。
- **整份隔离**：出现重复路径、绝对路径、上跳路径（`..`）、链接逃逸、
  sparse extent 异常、或解压体积超限时，归档标记为隔离，仍保留
  “安全扫描到的前缀”和明确原因；隔离归档只能得到“无法判定”的比较结论。
- 支持 zip 与 tar / tar.gz / tar.bz2 / tar.xz。

## 规范化清单字段

每个成员记录：`path`、`type`、`mode`、`uid`、`gid`、`mtime`、`size`、
`sha256`、`link_target`、`storage`（压缩/存储方式）、`sparse`、`order`
（归档中的原始顺序），硬链接额外带 `hardlink_resolved`。
清单自身有 `manifest_sha256`；归档记录还保存上传字节的 `blob_sha256`。

## 策略因素

`ignore_mtime`、`ignore_uid_gid`、`ignore_compression`、`ignore_order`、
`mode_mask`（八进制权限掩码，只比较保留的权限位；0 表示全部忽略）。
策略按名字保存、修改即生成新版本，历史版本不可变。

## 持久化与引用保护

数据按 `blobs/ archives/ policies/ sessions/ index.json` 组织，所有写入
均为“临时文件 + 原子替换”。重启后上传、策略、会话都在。

- 删除 blob 前检查归档引用，有引用则拒绝；
- 删除归档前检查比较会话引用，有会话则拒绝；
- 删除会话后，归档才可删除，其后 blob 才可清理。

## HTTP API

- `POST /api/archives`（multipart `file` 或原始字节）上传并扫描
- `GET /api/archives`、`GET /api/archives/{id}`
- `GET/POST /api/policies`，`POST /api/policies/{name}/versions`
- `POST /api/compare`（`archive_a`、`archive_b`、`policy_name`、`policy_version`）
- `GET /api/sessions`、`GET /api/sessions/{id}`、
  `GET /api/sessions/{id}/proof`（下载 canonical JSON）
- `GET /api/blobs`
- `DELETE /api/archives/{id}`、`DELETE /api/blobs/{sha256}`、
  `DELETE /api/sessions/{id}`

## 测试

测试自行用 `zipfile`/`tarfile` 与手写 GNU sparse 头构造小归档，覆盖：成员顺序、
时间戳、权限掩码、硬链接与符号链接、重复路径、路径逃逸、链接逃逸、
压缩炸弹预算、合法/异常 sparse、blob 去重、引用保护、重启持久化、
隔离结论、证明字节稳定性，以及 HTTP 端到端流程。测试不把系统 tar 的
文本输出作为判据。
