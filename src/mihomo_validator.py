import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class ValidationResult:
    enabled: bool
    ok: bool
    status: str
    message: str


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

    try:
        result = subprocess.run(
            [binary_path, "-t", "-f", temp_path],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(enabled=True, ok=False, status="timeout", message=f"mihomo 校验超过 {timeout} 秒")
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode == 0:
        return ValidationResult(enabled=True, ok=True, status="passed", message=output[:2000] or "mihomo 配置校验通过")
    return ValidationResult(enabled=True, ok=False, status="failed", message=output[:2000] or f"mihomo 退出码: {result.returncode}")
