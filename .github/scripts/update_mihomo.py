"""检查 mihomo 稳定版更新，并把新版本号与 sha256 写回 Dockerfile。

只用标准库，供 .github/workflows/mihomo-update.yml 调用：
- 只接受 vX.Y.Z 形式的正式版（跳过 Prerelease-Alpha 等），且主版本号不变；
- 发布不足 --min-age-hours 小时的版本先不升级，避开刚发布就被撤回的版本；
- 同时下载 amd64 与 arm64 资产自行计算 sha256，并与 GitHub API 返回的 digest 核对，不一致即失败。

用法：python update_mihomo.py [--dockerfile Dockerfile] [--write] [--min-age-hours 24]
有更新时向 $GITHUB_OUTPUT 写入 changed=true、version=vX.Y.Z。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

API_LATEST = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
DOWNLOAD = "https://github.com/MetaCubeX/mihomo/releases/download/{tag}/{name}"
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
ARCHES = {"amd64": "MIHOMO_SHA256_AMD64", "arm64": "MIHOMO_SHA256_ARM64"}


def parse_version(tag: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.match(tag or "")
    return tuple(int(part) for part in match.groups()) if match else None  # type: ignore[return-value]


def read_args(text: str) -> dict[str, str]:
    return dict(re.findall(r"^ARG (MIHOMO_[A-Z0-9_]+)=(\S+)$", text, flags=re.M))


def rewrite_dockerfile(text: str, version: str, digests: dict[str, str]) -> str:
    """只替换三行 ARG，其余内容原样保留；缺任何一行都视为 Dockerfile 结构变化，直接报错。"""
    updates = {"MIHOMO_VERSION": version, **{ARCHES[arch]: digest for arch, digest in digests.items()}}
    for key, value in updates.items():
        text, count = re.subn(rf"^ARG {key}=\S+$", f"ARG {key}={value}", text, flags=re.M)
        if count != 1:
            raise SystemExit(f"Dockerfile 中找不到唯一的 ARG {key}")
    return text


def should_upgrade(current: str, latest: str) -> tuple[bool, str]:
    cur, new = parse_version(current), parse_version(latest)
    if not cur:
        return False, f"当前版本 {current} 无法解析"
    if not new:
        return False, f"最新发布 {latest} 不是正式版号，跳过"
    if new[0] != cur[0]:
        return False, f"主版本号变化（{current} -> {latest}），需要人工评估"
    if new <= cur:
        return False, f"已是最新（{current}）"
    return True, f"{current} -> {latest}"


def _request(url: str):
    headers = {"User-Agent": "clash-config-gen-mihomo-updater", "Accept": "application/vnd.github+json"}
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120)


def fetch_digests(release: dict) -> dict[str, str]:
    tag = release["tag_name"]
    assets = {asset["name"]: asset for asset in release.get("assets") or []}
    digests: dict[str, str] = {}
    for arch in ARCHES:
        # 与 Dockerfile 下载的文件名保持一致。
        name = f"mihomo-linux-{arch}-{tag}.gz"
        if name not in assets:
            raise SystemExit(f"发布 {tag} 缺少资产 {name}")
        with _request(DOWNLOAD.format(tag=tag, name=name)) as response:
            actual = hashlib.sha256(response.read()).hexdigest()
        published = str(assets[name].get("digest") or "")
        if published and published != f"sha256:{actual}":
            raise SystemExit(f"{name} 的 sha256 与 GitHub 公布的 digest 不一致")
        digests[arch] = actual
        print(f"{name}: sha256={actual} digest核对={'一致' if published else 'API 未提供'}")
    return digests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--min-age-hours", type=float, default=24)
    args = parser.parse_args()

    path = Path(args.dockerfile)
    text = path.read_text(encoding="utf-8")
    current = read_args(text).get("MIHOMO_VERSION", "")
    with _request(API_LATEST) as response:
        release = json.load(response)
    latest = str(release.get("tag_name") or "")
    upgrade, reason = should_upgrade(current, latest)
    print(f"mihomo 版本检查：{reason}")
    if not upgrade:
        return 0
    published = dt.datetime.fromisoformat(str(release["published_at"]).replace("Z", "+00:00"))
    age_hours = (dt.datetime.now(dt.timezone.utc) - published).total_seconds() / 3600
    if age_hours < args.min_age_hours:
        print(f"{latest} 发布仅 {age_hours:.1f} 小时，未满 {args.min_age_hours:g} 小时，下次再检查")
        return 0

    digests = fetch_digests(release)
    if args.write:
        path.write_text(rewrite_dockerfile(text, latest, digests), encoding="utf-8")
        print(f"已更新 {path}")
        output = os.getenv("GITHUB_OUTPUT")
        if output:
            with open(output, "a", encoding="utf-8") as handle:
                handle.write(f"changed=true\nversion={latest}\nprevious={current}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
