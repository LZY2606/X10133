"""命令行入口：python -m artifactproof --host ... --port ..."""

from __future__ import annotations

import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(description="可复现产物核验站")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5218)
    parser.add_argument("--data-dir", default=None, help="持久化数据目录")
    args = parser.parse_args(argv)

    from .web import run

    server, store = run(args.host, args.port, data_dir=args.data_dir)
    print(f"产物核验站已启动：http://{args.host}:{args.port}")
    print(f"持久化目录：{store.data_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
