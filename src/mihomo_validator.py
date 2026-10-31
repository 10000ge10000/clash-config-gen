import logging
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass

if os.name != "nt":
    import fcntl
else:  # Windows 本地开发无 fcntl，首次校验不加锁
    fcntl = None


LOGGER = logging.getLogger(__name__)
DEFAULT_MIHOMO_FIRST_RUN_TIMEOUT = 60
# MIHOMO_HOME 内的锁文件：首次下载 geodata 期间串行化校验，避免并发写同一文件。
GEODATA_LOCK_FILENAME = ".geodata.lock"
# mihomo 在 -d 目录中查找的 geodata 默认文件名（大小写不敏感）：
# - geodata-mode: false 时 GEOIP 用 MMDB（默认 geoip.metadb，兼容 Country.mmdb）；
# - geodata-mode: true 时 GEOIP 用 GeoIP.dat；GEOSITE / geosite: 用 GeoSite.dat；
# - IP-ASN 规则用 GeoLite2-ASN.mmdb。
_MMDB_FILENAMES = ("geoip.metadb", "country.mmdb")
_GEOIP_DAT_FILENAME = "geoip.dat"
_GEOSITE_FILENAME = "geosite.dat"
_ASN_FILENAME = "geolite2-asn.mmdb"
_GEODATA_MODE_TRUE_PATTERN = re.compile(r"^geodata-mode:\s*(true|yes|on)\s*(#.*)?$", re.IGNORECASE | re.MULTILINE)


@dataclass
class ValidationResult:
    enabled: bool
    ok: bool
    status: str
    message: str


def _mihomo_home_dir() -> tuple[str, bool]:
    """返回 mihomo -d 使用的目录及其是否为临时目录。

    生成的规则含 GEOIP,CN，mihomo -t 未指定 -d 时会尝试下载 geodata 导致超时；
    使用持久缓存目录让 geodata 只下载一次。目录不可写时回退临时目录。
    """
    home = os.getenv("MIHOMO_HOME", "/app/data/mihomo-home")
    try:
        os.makedirs(home, exist_ok=True)
        if os.access(home, os.W_OK):
            return home, False
    except OSError as exc:
        LOGGER.warning("无法使用 MIHOMO_HOME=%s，回退临时目录: %s", home, exc)
    return tempfile.mkdtemp(prefix="mihomo-home-"), True


def _first_run_timeout(default_timeout: int) -> int:
    """首次校验（需下载 geodata）的超时，至少不小于常规超时。"""
    try:
        value = int(os.getenv("MIHOMO_FIRST_RUN_TIMEOUT", str(DEFAULT_MIHOMO_FIRST_RUN_TIMEOUT)))
    except ValueError:
        value = DEFAULT_MIHOMO_FIRST_RUN_TIMEOUT
    return max(int(default_timeout), value if value > 0 else DEFAULT_MIHOMO_FIRST_RUN_TIMEOUT)


def _required_geodata_missing(home_dir: str, config_yaml: str) -> bool:
    """按配置内容粗判本次校验会用到哪些 geodata，并检查 MIHOMO_HOME 是否缺失。"""
    try:
        present = {name.lower() for name in os.listdir(home_dir)}
    except OSError:
        return True
    lowered = config_yaml.lower()
    if "geoip" in lowered:
        if _GEODATA_MODE_TRUE_PATTERN.search(config_yaml):
            if _GEOIP_DAT_FILENAME not in present:
                return True
        elif not any(name in present for name in _MMDB_FILENAMES):
            return True
    if "geosite" in lowered and _GEOSITE_FILENAME not in present:
        return True
    if "ip-asn" in lowered and _ASN_FILENAME not in present:
        return True
    return False


@contextmanager
def _geodata_download_lock(home_dir: str):
    """在 MIHOMO_HOME 上加独占文件锁（跨进程）；Windows 无 fcntl 时直接放行。"""
    if fcntl is None:
        yield
        return
    try:
        handle = open(os.path.join(home_dir, GEODATA_LOCK_FILENAME), "a+b")
    except OSError as exc:
        # 锁文件不可用时退化为不加锁，校验本身不因此失败。
        LOGGER.warning("无法创建 mihomo geodata 锁文件，本次不加锁: %s", exc)
        yield
        return
    with handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _run_mihomo(binary_path: str, home_dir: str, temp_path: str, timeout: int):
    return subprocess.run(
        [binary_path, "-t", "-d", home_dir, "-f", temp_path],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def validate_with_mihomo(config_yaml: str, timeout: int = 10) -> ValidationResult:
    """调用真实 mihomo 内核检查配置能否被加载。

    `mihomo -t -f config.yaml` 只做配置测试，不启动代理端口。生产环境默认
    启用；本地开发如未安装 mihomo，可通过 MIHOMO_VALIDATE_ENABLED=false
    显式跳过。
    """
    enabled = os.getenv("MIHOMO_VALIDATE_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    if not enabled:
        return ValidationResult(enabled=False, ok=True, status="skipped", message="mihomo 校验已通过环境变量关闭")

    binary = os.getenv("MIHOMO_BINARY", "mihomo")
    binary_path = shutil.which(binary)
    if not binary_path:
        return ValidationResult(enabled=True, ok=False, status="missing", message=f"找不到 mihomo 二进制: {binary}")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as temp_file:
        temp_file.write(config_yaml)
        temp_path = temp_file.name

    home_dir, home_is_temp = _mihomo_home_dir()
    effective_timeout = timeout
    try:
        if not home_is_temp and _required_geodata_missing(home_dir, config_yaml):
            # 共享 MIHOMO_HOME 首次缺 geodata：mihomo 会在校验时下载并写入同一文件。
            # 串行化本次校验，并放宽超时，避免下载耗时被算进常规 10 秒。
            with _geodata_download_lock(home_dir):
                # 拿到锁后复查：等锁期间其他校验可能已下载完成，此时按常规超时执行。
                if _required_geodata_missing(home_dir, config_yaml):
                    effective_timeout = _first_run_timeout(timeout)
                result = _run_mihomo(binary_path, home_dir, temp_path, effective_timeout)
        else:
            result = _run_mihomo(binary_path, home_dir, temp_path, effective_timeout)
    except subprocess.TimeoutExpired:
        return ValidationResult(enabled=True, ok=False, status="timeout", message=f"mihomo 校验超过 {effective_timeout} 秒")
    finally:
        if home_is_temp:
            shutil.rmtree(home_dir, ignore_errors=True)
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode == 0:
        return ValidationResult(enabled=True, ok=True, status="passed", message=output[:2000] or "mihomo 配置校验通过")
    return ValidationResult(enabled=True, ok=False, status="failed", message=output[:2000] or f"mihomo 退出码: {result.returncode}")
