"""在包含 mihomo 的运行环境中检查各协议最小节点是否可被解析。

这是一个显式验收脚本，不属于 pytest 收集范围：本机没有 mihomo 时应
返回非零并明确提示，而不是把解析检查静默 skip 掉。脚本只生成本地
fixture，不发起网络连接，也不包含真实凭据。

用法：
    PYTHONPATH=src python tests/mihomo_parser_check.py --mihomo /usr/local/bin/mihomo
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from node_builder import build_manual_node


UUID = "123e4567-e89b-12d3-a456-426614174000"
PASSWORD = "parser-fixture-password"
PUBLIC_KEY = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


def _common(name: str) -> dict:
    return {"node_name": name, "node_server": "127.0.0.1", "node_port": 443}


def _build_fixture_nodes() -> list[dict]:
    nodes: list[dict] = []

    nodes.append(
        build_manual_node(
            "ss",
            {**_common("SS"), "ss_encryption": "aes-128-gcm", "node_password": PASSWORD},
        )
    )
    nodes.append(build_manual_node("ssr", {**_common("SSR"), "node_password": PASSWORD}))

    for network, extra in (
        ("ws", {"ws_path": "/ws", "ws_host": "example.test"}),
        ("grpc", {"grpc_service_name": "fixture"}),
        ("h2", {"h2_path": "/", "h2_host": "example.test"}),
    ):
        nodes.append(
            build_manual_node(
                "vmess",
                {**_common(f"VMess-{network}"), "node_uuid": UUID, "network_type": network, **extra},
            )
        )

    for network, extra in (
        ("ws", {"ws_path": "/ws", "ws_host": "example.test"}),
        ("grpc", {"grpc_service_name": "fixture"}),
    ):
        nodes.append(
            build_manual_node(
                "trojan",
                {**_common(f"Trojan-{network}"), "node_password": PASSWORD, "trojan_network": network, **extra},
            )
        )

    for network, extra in (
        ("ws", {"vless_ws_path": "/ws", "vless_ws_host": "example.test"}),
        ("h2", {"vless_h2_path": "/", "vless_h2_host": "example.test"}),
        ("grpc", {"vless_grpc_service_name": "fixture"}),
    ):
        nodes.append(
            build_manual_node(
                "vless",
                {
                    **_common(f"VLESS-{network}"),
                    "node_uuid": UUID,
                    "vless_tls": True,
                    "vless_network": network,
                    **extra,
                },
            )
        )

    nodes.append(
        build_manual_node(
            "vless",
            {
                **_common("VLESS-Reality"),
                "node_uuid": UUID,
                "vless_tls": True,
                "vless_network": "tcp",
                "vless_flow": "xtls-rprx-vision",
                "vless_servername": "example.test",
                "vless_public_key": PUBLIC_KEY,
                "vless_short_id": "01234567",
            },
        )
    )

    nodes.append(
        build_manual_node(
            "hysteria2",
            {
                **_common("Hysteria2"),
                "node_password": PASSWORD,
                "hy2_sni": "example.test",
                "hy2_up_mbps": 50,
                "hy2_down_mbps": 100,
                "enable_port_hopping": False,
                "hy2_hop_interval": "30",
            },
        )
    )
    nodes.append(
        build_manual_node(
            "tuic",
            {
                **_common("TUIC"),
                "tuic_uuid": UUID,
                "tuic_password": PASSWORD,
            },
        )
    )
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mihomo",
        default=os.environ.get("MIHOMO_BIN", "mihomo"),
        help="mihomo 可执行文件路径，默认读取 MIHOMO_BIN 或 PATH 中的 mihomo",
    )
    args = parser.parse_args()
    binary = shutil.which(args.mihomo) or (args.mihomo if Path(args.mihomo).is_file() else None)
    if not binary:
        print(f"mihomo parser check failed: binary not found: {args.mihomo}", file=sys.stderr)
        return 2

    try:
        nodes = _build_fixture_nodes()
    except Exception as exc:
        print(f"mihomo parser check failed while building fixtures: {exc}", file=sys.stderr)
        return 1

    config = {
        "mixed-port": 7890,
        "proxies": nodes,
        "proxy-groups": [{"name": "Fixture", "type": "select", "proxies": [node["name"] for node in nodes]}],
        "rules": ["MATCH,Fixture"],
    }
    with tempfile.TemporaryDirectory(prefix="mihomo-parser-") as temp_dir:
        config_path = Path(temp_dir, "config.yaml")
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        result = subprocess.run(
            [binary, "-t", "-f", str(config_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            return result.returncode
    print(f"mihomo parser check passed: {len(nodes)} nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
