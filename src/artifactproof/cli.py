"""命令行入口：``python -m artifactproof``。"""

from __future__ import annotations

import argparse

from .scanner import DEFAULT_BUDGET
from .storage import Storage
from .webapp import run_server


def main(argv=None):
    parser = argparse.ArgumentParser(prog="artifactproof", description="离线产物核验站")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5218)
    parser.add_argument("--data", default=".artifactproof", help="持久化数据目录")
    parser.add_argument(
        "--budget",
        type=int,
        default=DEFAULT_BUDGET,
        help="单个归档解压逻辑体积预算（字节），默认 100 MiB",
    )
    args = parser.parse_args(argv)

    storage = Storage(args.data, budget=args.budget)
    httpd = run_server(storage, host=args.host, port=args.port)
    print("产物核验站已启动: http://%s:%d （数据目录 %s）" % (args.host, args.port, args.data))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

