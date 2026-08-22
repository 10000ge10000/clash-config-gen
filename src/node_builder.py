"""手动添加节点的构建逻辑与表单 schema。

从 web_app.py 抽取而来，供 Streamlit UI 与 V2 JSON API 共用同一套构建逻辑，
避免两处维护协议字段。build_manual_node 只做 fields -> node 的纯转换，
不做 YAML 解析与校验；最终写入前仍走 parse_proxy_yaml + validate_proxy_fields。
"""

import base64
import binascii
import re
import uuid

from normalizer import parse_strict_port


NODE_TYPES = ("ss", "ssr", "vmess", "trojan", "vless", "hysteria2", "tuic", "anytls")

IP_VERSION_OPTIONS = ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"]
FINGERPRINT_OPTIONS = ["chrome", "firefox", "safari", "edge", "ios", "android", "random", "none"]
HY2_FINGERPRINT_OPTIONS = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "none"]
ALPN_OPTIONS = ["h3", "h3-29", "h3-27"]

# These values are deliberately duplicated into the server-owned schema.  The
# browser receives the same lists for its select controls, but API callers are
# not trusted to use that UI.  Keep the lists conservative: a value accepted
# here must be understood by the mihomo node parser.
VMESS_NETWORK_OPTIONS = ["tcp", "ws", "h2", "grpc"]
TROJAN_NETWORK_OPTIONS = ["tcp", "ws", "grpc"]
VLESS_NETWORK_OPTIONS = ["tcp", "ws", "h2", "grpc", "http", "xhttp"]
VMESS_CIPHER_OPTIONS = ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"]
SS_CIPHER_OPTIONS = [
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
]
SS2022_KEY_LENGTHS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
SSR_CIPHER_OPTIONS = [
    "none", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "chacha20",
    "chacha20-ietf", "salsa20", "xsalsa20", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
]
SSR_PROTOCOL_OPTIONS = [
    "origin", "verify_simple", "verify_sha1", "auth_sha1_v4", "auth_aes128_md5",
    "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c",
    "auth_chain_d", "auth_chain_e", "auth_chain_f",
]
SSR_OBFS_OPTIONS = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"]
VLESS_FLOW_OPTIONS = ["none", "xtls-rprx-vision", "xtls-rprx-vision-udp443"]
TUIC_CONGESTION_OPTIONS = ["bbr", "cubic", "new_reno"]
TUIC_RELAY_OPTIONS = ["native", "quic"]
HY2_OBFS_OPTIONS = ["none", "salamander"]
# The empty value means "do not emit packet-encoding".  Keeping it in the
# server-owned list makes the select schema and the API validator identical.
PACKET_ENCODING_OPTIONS = ["", "xudp", "packetaddr"]
SMUX_PROTOCOL_OPTIONS = ["h2mux", "yamux", "smux"]
ANYTLS_ALPN_OPTIONS = ["h2,http/1.1", "h2", "http/1.1", "none"]

_MISSING = object()


def normalize_hy2_hop_interval(raw_value: str) -> int:
    """OpenClash/mihomo 当前把 Hysteria2 hop-interval 按整数秒解析。"""
    value = str(raw_value or "").strip()
    if not value:
        return 30
    if value.isdigit():
        seconds = int(value)
        if seconds <= 0:
            raise ValueError("hop-interval 必须大于 0 秒")
        return seconds
    if "-" in value:
        left, right = [part.strip() for part in value.split("-", 1)]
        if not left.isdigit() or not right.isdigit():
            raise ValueError("随机跳跃间隔必须写成 5-25 这种纯数字范围")
        start = int(left)
        end = int(right)
        if start <= 0 or end <= 0 or start > end:
            raise ValueError("随机跳跃间隔范围必须大于 0，且左侧不能大于右侧")
        return start
    raise ValueError("hop-interval 只支持整数秒，兼容输入 5-25 时会自动取 5 秒")


def _bool(value) -> bool:
    return bool(value)


def _str(value, default: str = "") -> str:
    return default if value is None else str(value)


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _required_text(fields: dict, key: str, label: str) -> str:
    value = _str(fields.get(key)).strip()
    if not value:
        raise ValueError(f"{label}不能为空")
    return value


def _raw_field(fields: dict, key: str, *aliases: str):
    """Read a canonical form key while retaining older API aliases."""
    if key in fields:
        return fields[key]
    for alias in aliases:
        if alias in fields:
            return fields[alias]
    return _MISSING


def _enum_field(
    fields: dict,
    key: str,
    label: str,
    options: list[str],
    *,
    default=_MISSING,
    aliases: tuple[str, ...] = (),
) -> str:
    raw = _raw_field(fields, key, *aliases)
    if raw is _MISSING:
        if default is _MISSING:
            raise ValueError(f"{label}不能为空")
        return str(default)
    value = _str(raw).strip()
    if not value:
        raise ValueError(f"{label}不能为空")
    if value not in options:
        raise ValueError(f"{label}不支持：{value}")
    return value


def _alpn_items(raw_value: object, label: str, *, default: str) -> list[str]:
    """ALPN 支持逗号分隔多值（如 'h3,h3-29'），逐项校验后返回数组。"""
    text = _str(raw_value).strip() or default
    items = [item.strip() for item in text.split(",") if item.strip()]
    if not items:
        raise ValueError(f"{label}不能为空")
    for item in items:
        if item not in ALPN_OPTIONS:
            raise ValueError(f"{label}不支持：{item}")
    return items


def _int_field(
    fields: dict,
    key: str,
    label: str,
    *,
    default=_MISSING,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = _raw_field(fields, key)
    if raw is _MISSING:
        if default is _MISSING:
            raise ValueError(f"{label}不能为空")
        raw = default
    raw_text = str(raw).strip()
    if isinstance(raw, bool) or not raw_text:
        raise ValueError(f"{label}必须是数字")
    if isinstance(raw, float) and not raw.is_integer():
        raise ValueError(f"{label}必须是整数")
    if isinstance(raw, str) and not raw_text.lstrip("+-").isdigit():
        raise ValueError(f"{label}必须是整数")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}必须是整数") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{label}必须不小于 {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label}必须不大于 {maximum}")
    return value


def _ip_version_field_value(fields: dict, key: str) -> str:
    return _enum_field(fields, key, "IP Version", IP_VERSION_OPTIONS, default="默认")


def _validate_port_range(value: str) -> str:
    match = value.strip().split("-", 1)
    if len(match) != 2 or not all(part.strip().isdigit() for part in match):
        raise ValueError("端口范围必须写成 29950-30000")
    start, end = (int(part.strip()) for part in match)
    if not 1 <= start <= end <= 65535:
        raise ValueError("端口范围必须在 1-65535 内，且起始端口不能大于结束端口")
    return f"{start}-{end}"


def _required_uuid(fields: dict, key: str, label: str) -> str:
    value = _required_text(fields, key, label)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label}必须是有效 UUID") from exc
    if parsed.int == 0:
        raise ValueError(f"{label}不能使用全零占位 UUID")
    return str(parsed)


def _required_service(fields: dict, key: str, label: str = "gRPC service-name") -> str:
    return _required_text(fields, key, label)


def _validate_ss2022_password(cipher: str, password: str) -> None:
    """Validate the raw key format required by mihomo's SS 2022 ciphers."""
    expected_length = SS2022_KEY_LENGTHS.get(cipher)
    if expected_length is None:
        return
    try:
        decoded = base64.b64decode(password, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError("Shadowsocks 2022 密码必须是严格 Base64 密钥") from None
    # Reject non-canonical encodings (including omitted/incorrect padding)
    # without ever including the credential in an error or log message.
    if base64.b64encode(decoded).decode("ascii") != password or len(decoded) != expected_length:
        raise ValueError(f"Shadowsocks 2022 密钥必须是 {expected_length} 字节 Base64")


def _validate_reality_public_key(value: str) -> None:
    """Validate mihomo Reality's 32-byte unpadded Base64URL public key."""
    if not value:
        return
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) % 4 == 1:
        raise ValueError("VLESS Reality public-key 必须是无 padding 的 Base64URL 公钥")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError("VLESS Reality public-key 必须是有效 Base64URL 公钥") from None
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != 32 or canonical != value:
        raise ValueError("VLESS Reality public-key 必须解码为 32 bytes")


def build_manual_node(node_type: str, fields: dict) -> dict:
    """按协议把表单字段构建为 mihomo 节点 dict（含 name/type/server/port）。"""
    f = fields or {}

    node_type = str(node_type or "").strip().lower()
    if node_type not in NODE_TYPES:
        raise ValueError(f"不支持的节点协议：{node_type or '未指定'}")

    node_name = _str(f.get("node_name")).strip()
    node_server = _str(f.get("node_server")).strip()
    if not node_name:
        raise ValueError("节点名称不能为空")
    if not node_server:
        raise ValueError("服务器地址不能为空")
    node_port = parse_strict_port(f.get("node_port", 443))
    # tuic / hysteria2 没有通用 UDP 开关，其余协议才有。
    node_udp = _bool(f.get("node_udp", True))

    # 通用高级字段仅 ss / vless / vmess 支持（smux / ip-version 兜底）。
    common_ip_version = _ip_version_field_value(f, "common_ip_version")
    enable_smux = _bool(f.get("enable_smux"))
    smux_enabled = _bool(f.get("smux_enabled", True))
    smux_protocol = _enum_field(f, "smux_protocol", "smux.protocol", SMUX_PROTOCOL_OPTIONS, default="h2mux")
    smux_max_connections = _int_field(f, "smux_max_connections", "smux.max-connections", default=4, minimum=1)
    smux_brutal_enabled = _bool(f.get("smux_brutal_enabled"))
    smux_brutal_up = _int_field(f, "smux_brutal_up", "smux.brutal-opts.up", default=100, minimum=1)
    smux_brutal_down = _int_field(f, "smux_brutal_down", "smux.brutal-opts.down", default=100, minimum=1)

    manual_node = {
        "name": node_name,
        "type": node_type,
        "server": node_server,
        "port": node_port,
    }

    if node_type == "vmess":
        node_uuid = _required_uuid(f, "node_uuid", "UUID")
        node_alterid = _int_field(f, "node_alterid", "Alter ID", default=0, minimum=0)
        vmess_encryption = _enum_field(
            f,
            "vmess_encryption",
            "VMess 加密方式",
            VMESS_CIPHER_OPTIONS,
            default="auto",
            aliases=("node_cipher", "cipher"),
        )
        node_tls = _bool(f.get("node_tls"))
        node_skip_cert = _bool(f.get("node_skip_cert"))
        node_tfo = _bool(f.get("node_tfo"))
        network_type = _enum_field(f, "network_type", "VMess 传输协议", VMESS_NETWORK_OPTIONS, default="tcp")
        ip_version = _ip_version_field_value(f, "ip_version")

        manual_node["uuid"] = node_uuid
        manual_node["alterId"] = node_alterid
        manual_node["cipher"] = vmess_encryption
        manual_node["tls"] = node_tls
        manual_node["skip-cert-verify"] = node_skip_cert
        manual_node["tfo"] = node_tfo
        manual_node["network"] = network_type
        manual_node["udp"] = node_udp
        if ip_version != "默认":
            manual_node["ip-version"] = ip_version

        if network_type == "ws":
            ws_opts = {"path": _str(f.get("ws_path"), "/")}
            ws_host = _str(f.get("ws_host")).strip()
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            manual_node["ws-opts"] = ws_opts
        elif network_type == "h2":
            h2_opts = {"path": _str(f.get("h2_path"), "/")}
            h2_host = _str(f.get("h2_host")).strip()
            if h2_host:
                h2_opts["host"] = [h2_host]
            manual_node["h2-opts"] = h2_opts
        elif network_type == "grpc":
            manual_node["grpc-opts"] = {"grpc-service-name": _required_service(f, "grpc_service_name")}

    elif node_type == "ss":
        ss_encryption = _enum_field(
            f,
            "ss_encryption",
            "Shadowsocks 加密方式",
            SS_CIPHER_OPTIONS,
            default="aes-128-gcm",
            aliases=("node_cipher", "cipher"),
        )
        node_password = _required_text(f, "node_password", "密码")
        _validate_ss2022_password(ss_encryption, node_password)
        ss_udp_over_tcp = _bool(f.get("ss_udp_over_tcp"))
        ss_tfo = _bool(f.get("ss_tfo"))
        ss_ip_version = _ip_version_field_value(f, "ss_ip_version")
        ss_mux = _bool(f.get("ss_mux"))

        manual_node["password"] = node_password
        manual_node["cipher"] = ss_encryption
        manual_node["udp"] = node_udp
        manual_node["udp-over-tcp"] = ss_udp_over_tcp
        manual_node["tfo"] = ss_tfo
        if ss_ip_version != "默认":
            manual_node["ip-version"] = ss_ip_version
        manual_node["mux"] = ss_mux

    elif node_type == "ssr":
        node_password = _required_text(f, "node_password", "密码")
        ssr_cipher = _enum_field(
            f,
            "ssr_encryption",
            "SSR 加密方式",
            SSR_CIPHER_OPTIONS,
            default="aes-128-ctr",
            aliases=("ssr_cipher", "cipher"),
        )
        ssr_protocol = _enum_field(
            f,
            "ssr_protocol",
            "SSR 协议",
            SSR_PROTOCOL_OPTIONS,
            default="origin",
        )
        ssr_protocol_param = _str(f.get("ssr_protocol_param")).strip()
        ssr_obfs = _enum_field(f, "ssr_obfs", "SSR 混淆", SSR_OBFS_OPTIONS, default="plain")
        ssr_obfs_param = _str(f.get("ssr_obfs_param")).strip()
        manual_node.update(
            {
                "password": node_password,
                "cipher": ssr_cipher,
                "protocol": ssr_protocol,
                "obfs": ssr_obfs,
                "udp": node_udp,
            }
        )
        if ssr_protocol_param:
            manual_node["protocol-param"] = ssr_protocol_param
        if ssr_obfs_param:
            manual_node["obfs-param"] = ssr_obfs_param

    elif node_type == "trojan":
        node_password = _required_text(f, "node_password", "密码")
        trojan_udp_over_tcp = _bool(f.get("trojan_udp_over_tcp"))
        trojan_tfo = _bool(f.get("trojan_tfo"))
        trojan_network = _enum_field(f, "trojan_network", "Trojan 传输协议", TROJAN_NETWORK_OPTIONS, default="tcp")
        trojan_ip_version = _ip_version_field_value(f, "trojan_ip_version")

        manual_node["password"] = node_password
        manual_node["udp"] = node_udp
        manual_node["udp-over-tcp"] = trojan_udp_over_tcp
        manual_node["tfo"] = trojan_tfo
        manual_node["network"] = trojan_network
        if trojan_ip_version != "默认":
            manual_node["ip-version"] = trojan_ip_version

        if trojan_network == "ws":
            ws_opts = {"path": _str(f.get("ws_path"), "/")}
            ws_host = _str(f.get("ws_host")).strip()
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            manual_node["ws-opts"] = ws_opts
        elif trojan_network == "grpc":
            manual_node["grpc-opts"] = {"grpc-service-name": _required_service(f, "grpc_service_name")}

    elif node_type == "hysteria2":
        node_password = _required_text(f, "node_password", "密码")
        hy2_sni = _str(f.get("hy2_sni")).strip()
        hy2_obfs_type = _enum_field(f, "hy2_obfs_type", "Hysteria2 混淆插件", HY2_OBFS_OPTIONS, default="none")
        hy2_up_mbps = _int_field(f, "hy2_up_mbps", "Hysteria2 上行容量", default=50, minimum=1)
        hy2_down_mbps = _int_field(f, "hy2_down_mbps", "Hysteria2 下行容量", default=100, minimum=1)
        hy2_obfs_password = _str(f.get("hy2_obfs_password"))
        hy2_skip_cert = _bool(f.get("hy2_skip_cert", True))
        hy2_alpn_items = _alpn_items(f.get("hy2_alpn"), "Hysteria2 ALPN", default="h3")
        enable_port_hopping = _bool(f.get("enable_port_hopping", True))
        port_hopping_range = _str(f.get("port_hopping_range"), "29950-30000")
        enable_quic_params = _bool(f.get("enable_quic_params"))
        hy2_hop_interval = _str(f.get("hy2_hop_interval"), "30")
        hy2_fingerprint = _enum_field(f, "hy2_fingerprint", "Hysteria2 客户端指纹", HY2_FINGERPRINT_OPTIONS, default="chrome")
        hy2_ip_version = _ip_version_field_value(f, "hy2_ip_version")

        if enable_port_hopping:
            port_hopping_range = _validate_port_range(port_hopping_range)
        if not str(hy2_hop_interval).strip():
            raise ValueError("Hysteria2 hop-interval 不能为空")
        try:
            normalized_hop_interval = normalize_hy2_hop_interval(hy2_hop_interval)
        except ValueError as exc:
            raise ValueError(f"Hysteria2 hop-interval 无效：{exc}") from exc

        manual_node["password"] = node_password
        if hy2_sni:
            manual_node["sni"] = hy2_sni
        manual_node["skip-cert-verify"] = hy2_skip_cert
        manual_node["alpn"] = hy2_alpn_items
        if hy2_obfs_type and hy2_obfs_type != "none":
            if not hy2_obfs_password.strip():
                raise ValueError("Hysteria2 混淆启用时混淆密码不能为空")
            manual_node["obfs"] = hy2_obfs_type
            manual_node["obfs-password"] = hy2_obfs_password
        manual_node["up"] = f"{hy2_up_mbps} Mbps"
        manual_node["down"] = f"{hy2_down_mbps} Mbps"
        manual_node["hop-interval"] = normalized_hop_interval
        if hy2_fingerprint != "none":
            manual_node["client-fingerprint"] = hy2_fingerprint
        if hy2_ip_version != "默认":
            manual_node["ip-version"] = hy2_ip_version

        if enable_port_hopping:
            manual_node["ports"] = port_hopping_range
        if enable_quic_params:
            manual_node["quic-params"] = {
                "initial-stream-receive-window": _int_field(
                    f, "initial_stream_receive_window", "QUIC 初始流接收窗口", default=8388608, minimum=1
                ),
                "max-stream-receive-window": _int_field(
                    f, "max_stream_receive_window", "QUIC 最大流接收窗口", default=8388608, minimum=1
                ),
                "initial-connection-receive-window": _int_field(
                    f, "initial_connection_receive_window", "QUIC 初始连接接收窗口", default=20971520, minimum=1
                ),
                "max-connection-receive-window": _int_field(
                    f, "max_connection_receive_window", "QUIC 最大连接接收窗口", default=20971520, minimum=1
                ),
            }

    elif node_type == "tuic":
        tuic_uuid = _required_uuid(f, "tuic_uuid", "UUID")
        tuic_password = _required_text(f, "tuic_password", "Password")
        tuic_server_ip = _str(f.get("tuic_server_ip")).strip()
        tuic_congestion = _enum_field(f, "tuic_congestion", "TUIC 拥塞控制", TUIC_CONGESTION_OPTIONS, default="bbr")
        tuic_alpn_items = _alpn_items(f.get("tuic_alpn"), "TUIC ALPN", default="h3")
        tuic_sni = _str(f.get("tuic_sni")).strip()
        tuic_udp_relay_mode = _enum_field(f, "tuic_udp_relay_mode", "TUIC UDP Relay Mode", TUIC_RELAY_OPTIONS, default="native")
        tuic_heartbeat_interval = _int_field(f, "tuic_heartbeat_interval", "TUIC 心跳间隔", default=10000, minimum=1)
        tuic_close_sni = _bool(f.get("tuic_close_sni"))
        tuic_reduce_rtt = _bool(f.get("tuic_reduce_rtt", True))
        tuic_skip_cert_verify = _bool(f.get("tuic_skip_cert_verify", True))
        tuic_fast_open = _bool(f.get("tuic_fast_open", True))
        tuic_ip_version = _ip_version_field_value(f, "tuic_ip_version")

        manual_node["uuid"] = tuic_uuid
        manual_node["password"] = tuic_password
        if tuic_server_ip:
            manual_node["ip"] = tuic_server_ip
        manual_node["congestion-controller"] = tuic_congestion
        manual_node["alpn"] = tuic_alpn_items
        manual_node["udp-relay-mode"] = tuic_udp_relay_mode
        manual_node["disable-sni"] = tuic_close_sni
        if not tuic_close_sni:
            manual_node["sni"] = tuic_sni or node_server
        manual_node["reduce-rtt"] = tuic_reduce_rtt
        manual_node["skip-cert-verify"] = tuic_skip_cert_verify
        manual_node["fast-open"] = tuic_fast_open
        if tuic_ip_version != "默认":
            manual_node["ip-version"] = tuic_ip_version
        manual_node["heartbeat-interval"] = tuic_heartbeat_interval

    elif node_type == "vless":
        node_uuid = _required_uuid(f, "node_uuid", "UUID")
        vless_tls = _bool(f.get("vless_tls"))
        vless_flow = _enum_field(f, "vless_flow", "VLESS flow", VLESS_FLOW_OPTIONS, default="none")
        vless_servername = _str(f.get("vless_servername")).strip()
        vless_network = _enum_field(f, "vless_network", "VLESS 传输协议", VLESS_NETWORK_OPTIONS, default="tcp")
        vless_packet_encoding = _str(f.get("vless_packet_encoding")).strip()
        if vless_packet_encoding and vless_packet_encoding not in PACKET_ENCODING_OPTIONS:
            raise ValueError(f"VLESS Packet-Encoding 不支持：{vless_packet_encoding}")
        vless_tfo = _bool(f.get("vless_tfo"))
        vless_fp = _enum_field(f, "vless_fp", "VLESS 客户端指纹", FINGERPRINT_OPTIONS, default="chrome")
        vless_ip_version = _ip_version_field_value(f, "vless_ip_version")
        vless_public_key = _str(f.get("vless_public_key")).strip()
        vless_short_id = _str(f.get("vless_short_id")).strip()
        _validate_reality_public_key(vless_public_key)
        vless_skip_cert_verify = _bool(f.get("vless_skip_cert_verify"))
        if bool(vless_public_key.strip()) != bool(vless_short_id.strip()):
            raise ValueError("VLESS Reality 的 public-key 和 short-id 必须同时填写或同时留空")

        manual_node["uuid"] = node_uuid
        manual_node["tls"] = vless_tls
        if vless_servername:
            manual_node["servername"] = vless_servername
        manual_node["network"] = vless_network
        if vless_flow != "none":
            manual_node["flow"] = vless_flow
        if vless_packet_encoding:
            manual_node["packet-encoding"] = vless_packet_encoding
        manual_node["udp"] = node_udp
        manual_node["tfo"] = vless_tfo
        manual_node["client-fingerprint"] = vless_fp
        if vless_ip_version != "默认":
            manual_node["ip-version"] = vless_ip_version
        manual_node["skip-cert-verify"] = vless_skip_cert_verify

        if vless_public_key:
            manual_node["reality-opts"] = {"public-key": vless_public_key}
            if vless_short_id:
                manual_node["reality-opts"]["short-id"] = vless_short_id

        if vless_network == "ws":
            ws_opts = {"path": _str(f.get("vless_ws_path"), "/vless")}
            vless_ws_host = _str(f.get("vless_ws_host")).strip()
            if vless_ws_host:
                ws_opts["headers"] = {"Host": vless_ws_host}
            manual_node["ws-opts"] = ws_opts
        elif vless_network == "h2":
            h2_opts = {"path": _str(f.get("vless_h2_path"), "/")}
            vless_h2_host = _str(f.get("vless_h2_host")).strip()
            if vless_h2_host:
                h2_opts["host"] = [vless_h2_host]
            manual_node["h2-opts"] = h2_opts
        elif vless_network == "grpc":
            manual_node["grpc-opts"] = {"grpc-service-name": _required_service(f, "vless_grpc_service_name")}

    elif node_type == "anytls":
        anytls_password = _required_text(f, "anytls_password", "密码")
        anytls_sni = _str(f.get("anytls_sni")).strip()
        anytls_fp = _enum_field(f, "anytls_fp", "AnyTLS 客户端指纹", FINGERPRINT_OPTIONS, default="chrome")
        anytls_skip_cert_verify = _bool(f.get("anytls_skip_cert_verify", True))
        anytls_alpn = _enum_field(f, "anytls_alpn", "AnyTLS ALPN", ANYTLS_ALPN_OPTIONS, default="h2,http/1.1")
        anytls_ip_version = _ip_version_field_value(f, "anytls_ip_version")
        anytls_idle_session_check_interval = _int_field(
            f, "anytls_idle_session_check_interval", "AnyTLS idle-session-check-interval", default=30, minimum=1
        )
        anytls_idle_session_timeout = _int_field(
            f, "anytls_idle_session_timeout", "AnyTLS idle-session-timeout", default=180, minimum=1
        )
        anytls_min_idle_session = _int_field(
            f, "anytls_min_idle_session", "AnyTLS min-idle-session", default=2, minimum=0
        )
        anytls_ech_enabled = _bool(f.get("anytls_ech_enabled"))
        anytls_ech_config = _str(f.get("anytls_ech_config"))
        anytls_ech_query_server_name = _str(f.get("anytls_ech_query_server_name"))

        manual_node["password"] = anytls_password
        manual_node["skip-cert-verify"] = anytls_skip_cert_verify
        if anytls_sni:
            manual_node["sni"] = anytls_sni
        if anytls_alpn != "none":
            manual_node["alpn"] = anytls_alpn.split(",") if "," in anytls_alpn else [anytls_alpn]
        manual_node["idle-session-check-interval"] = anytls_idle_session_check_interval
        manual_node["idle-session-timeout"] = anytls_idle_session_timeout
        manual_node["min-idle-session"] = anytls_min_idle_session
        manual_node["client-fingerprint"] = anytls_fp
        manual_node["udp"] = node_udp
        if anytls_ip_version != "默认":
            manual_node["ip-version"] = anytls_ip_version
        if anytls_ech_enabled:
            manual_node["ech-opts"] = {"enable": True}
            if anytls_ech_config.strip():
                manual_node["ech-opts"]["config"] = anytls_ech_config.strip()
            if anytls_ech_query_server_name.strip():
                manual_node["ech-opts"]["query-server-name"] = anytls_ech_query_server_name.strip()

    if common_ip_version != "默认" and "ip-version" not in manual_node:
        manual_node["ip-version"] = common_ip_version
    if enable_smux:
        manual_node["smux"] = {
            "enabled": smux_enabled,
            "protocol": smux_protocol,
            "max-connections": smux_max_connections,
        }
        if smux_brutal_enabled:
            manual_node["smux"]["brutal-opts"] = {
                "enabled": True,
                "up": f"{smux_brutal_up} Mbps",
                "down": f"{smux_brutal_down} Mbps",
            }

    use_dialer_proxy = _bool(f.get("use_dialer_proxy"))
    dialer_proxy_name = _str(f.get("dialer_proxy_name")).strip()
    if use_dialer_proxy and dialer_proxy_name:
        manual_node["dialer-proxy"] = dialer_proxy_name

    return manual_node


def _f(
    key,
    label,
    ftype="text",
    default=None,
    options=None,
    minimum=None,
    maximum=None,
    visible=None,
    help_=None,
    required=False,
):
    control_type = "input" if ftype in {"text", "password", "number"} else ftype
    field = {"key": key, "label": label, "type": control_type, "default": default}
    if ftype in {"text", "password", "number"}:
        field["control"] = "input"
        field["input_type"] = ftype
    if options is not None:
        field["options"] = options
    if minimum is not None:
        field["min"] = minimum
    if maximum is not None:
        field["max"] = maximum
    if visible is not None:
        field["visible"] = visible
        field["visible_condition"] = visible
    if help_ is not None:
        field["help"] = help_
    if required:
        field["required"] = True
    return field


def _common_fields(node_type: str):
    """名称/服务器/端口 + 通用 UDP 开关（tuic/hysteria2 无）。"""
    fields = [
        _f("node_name", "节点名称", required=True),
        _f("node_server", "服务器地址", required=True),
        _f("node_port", "端口", "number", default=443, minimum=1, maximum=65535, required=True),
    ]
    if node_type not in ("tuic", "hysteria2"):
        fields.append(_f("node_udp", "UDP 支持", "checkbox", default=True))
    return fields


def _ip_version_field(key):
    return _f(key, "IP Version", "select", default="默认", options=IP_VERSION_OPTIONS)


def _smux_fields(node_type: str):
    """通用多路复用 (smux) 字段组，仅 ss / vless / vmess 支持（对齐 Streamlit 通用高级区）。"""
    show = {"key": "enable_smux", "equals": True}
    show_brutal = {"key": "smux_brutal_enabled", "equals": True}
    return [
        _f("enable_smux", "多路复用 (smux)", "checkbox",
           help_="TCP 多路复用可降低握手开销，部分服务端不支持"),
        _f("smux_enabled", "启用 smux", "checkbox", default=True, visible=show),
        _f("smux_protocol", "smux 协议", "select", default="h2mux",
           options=SMUX_PROTOCOL_OPTIONS, visible=show),
        _f("smux_max_connections", "最大连接数", "number", default=4, minimum=1, visible=show),
        _f("smux_brutal_enabled", "Brutal 拥塞控制", "checkbox",
           default=node_type == "vless", visible=show,
           help_="需服务端配合，vless 默认开启"),
        _f("smux_brutal_up", "Brutal 上行 (Mbps)", "number", default=100, minimum=1, visible=show_brutal),
        _f("smux_brutal_down", "Brutal 下行 (Mbps)", "number", default=100, minimum=1, visible=show_brutal),
    ]


def _dialer_fields():
    """链式代理 (dialer-proxy) 字段组，全部协议支持；上游名称由前端 datalist 提供现有节点。"""
    return [
        _f("use_dialer_proxy", "链式代理 (dialer-proxy)", "checkbox",
           help_="开启后经由指定上游节点转发流量"),
        _f("dialer_proxy_name", "上游节点",
           visible={"key": "use_dialer_proxy", "equals": True},
           help_="填写当前节点列表中的已有节点名称"),
    ]


# 每协议的表单 schema，供 V2 前端通用渲染器读取；后端只做权威来源。
NODE_FORM_SCHEMA = {
    "ss": _common_fields("ss") + [
        _f("ss_encryption", "加密方式", "select", default="aes-128-gcm", options=SS_CIPHER_OPTIONS),
        _f("node_password", "密码", "password", required=True),
        _f("ss_udp_over_tcp", "udp-over-tcp", "checkbox"),
        _f("ss_tfo", "TFO", "checkbox"),
        _ip_version_field("ss_ip_version"),
        _f("ss_mux", "多路复用 (旧式 mux)", "checkbox",
           help_="旧式 mux 字段；如需 TCP 多路复用建议使用下方 smux 组"),
    ] + _smux_fields("ss") + _dialer_fields(),
    "ssr": _common_fields("ssr") + [
        _f("node_password", "密码", "password", required=True),
        _f("ssr_encryption", "加密方式", "select", default="aes-128-ctr", options=SSR_CIPHER_OPTIONS, required=True),
        _f("ssr_protocol", "SSR 协议", "select", default="origin", options=SSR_PROTOCOL_OPTIONS, required=True),
        _f("ssr_protocol_param", "协议参数"),
        _f("ssr_obfs", "SSR 混淆", "select", default="plain", options=SSR_OBFS_OPTIONS, required=True),
        _f("ssr_obfs_param", "混淆参数"),
    ] + _dialer_fields(),
    "vless": _common_fields("vless") + [
        _f("node_uuid", "UUID", required=True),
        _f("vless_tls", "TLS", "checkbox", default=True,
           help_="reality / vision 流控必须开启 TLS"),
        _f("vless_flow", "flow (reality)", "select", default="xtls-rprx-vision", options=VLESS_FLOW_OPTIONS),
        _f("vless_servername", "servername", default="v1-dy.ixigua.com"),
        _f("vless_network", "传输协议", "select", default="tcp", options=VLESS_NETWORK_OPTIONS),
        _f("vless_packet_encoding", "Packet-Encoding", "select", default="", options=PACKET_ENCODING_OPTIONS),
        _f("vless_ws_path", "WebSocket path", default="/vless", visible={"key": "vless_network", "equals": "ws"}),
        _f("vless_ws_host", "WebSocket Host", visible={"key": "vless_network", "equals": "ws"}),
        _f("vless_h2_path", "HTTP/2 path", default="/", visible={"key": "vless_network", "equals": "h2"}),
        _f("vless_h2_host", "HTTP/2 Host", visible={"key": "vless_network", "equals": "h2"}),
        _f("vless_grpc_service_name", "gRPC service-name", visible={"key": "vless_network", "equals": "grpc"}, required=True),
        _f("vless_tfo", "TFO", "checkbox"),
        _f("vless_fp", "客户端指纹", "select", default="chrome", options=FINGERPRINT_OPTIONS),
        _ip_version_field("vless_ip_version"),
        _f("vless_public_key", "public-key (reality)", visible={"key": "vless_flow", "not_equals": "none"},
           help_="flow 不为 none 时必填，Base64URL 格式"),
        _f("vless_short_id", "short-id (reality)", visible={"key": "vless_flow", "not_equals": "none"},
           help_="flow 不为 none 时必填，可为空字符串以外的十六进制串"),
        _f("vless_skip_cert_verify", "跳过证书验证", "checkbox"),
    ] + _smux_fields("vless") + _dialer_fields(),
    "vmess": _common_fields("vmess") + [
        _f("node_uuid", "UUID", required=True),
        _f("node_alterid", "Alter ID", "number", default=0, minimum=0),
        _f("vmess_encryption", "加密方式", "select", default="auto",
           options=VMESS_CIPHER_OPTIONS),
        _f("node_tls", "启用 TLS", "checkbox", default=True),
        _f("node_skip_cert", "跳过证书验证", "checkbox"),
        _f("node_tfo", "TFO", "checkbox"),
        _f("network_type", "传输协议", "select", default="tcp", options=VMESS_NETWORK_OPTIONS),
        _ip_version_field("ip_version"),
        _f("ws_path", "WebSocket 路径", default="/", visible={"key": "network_type", "equals": "ws"}),
        _f("ws_host", "WebSocket 主机", visible={"key": "network_type", "equals": "ws"}),
        _f("h2_path", "HTTP/2 路径", default="/", visible={"key": "network_type", "equals": "h2"}),
        _f("h2_host", "HTTP/2 主机", visible={"key": "network_type", "equals": "h2"}),
        _f("grpc_service_name", "gRPC 服务名称", visible={"key": "network_type", "equals": "grpc"}, required=True),
    ] + _smux_fields("vmess") + _dialer_fields(),
    "trojan": _common_fields("trojan") + [
        _f("node_password", "密码", "password", required=True),
        _f("trojan_udp_over_tcp", "udp-over-tcp", "checkbox"),
        _f("trojan_tfo", "TFO", "checkbox"),
        _f("trojan_network", "传输协议", "select", default="tcp", options=TROJAN_NETWORK_OPTIONS),
        _ip_version_field("trojan_ip_version"),
        _f("ws_path", "WebSocket 路径", default="/", visible={"key": "trojan_network", "equals": "ws"}),
        _f("ws_host", "WebSocket 主机", visible={"key": "trojan_network", "equals": "ws"}),
        _f("grpc_service_name", "gRPC 服务名称", visible={"key": "trojan_network", "equals": "grpc"}, required=True),
    ] + _dialer_fields(),
    "anytls": _common_fields("anytls") + [
        _f("anytls_password", "密码", "password", required=True),
        _f("anytls_sni", "SNI", default="www.bing.com"),
        _f("anytls_fp", "客户端指纹", "select", default="chrome", options=FINGERPRINT_OPTIONS),
        _f("anytls_skip_cert_verify", "跳过证书验证", "checkbox", default=True),
        _f("anytls_alpn", "ALPN", "select", default="h2,http/1.1",
           options=["h2,http/1.1", "h2", "http/1.1", "none"]),
        _ip_version_field("anytls_ip_version"),
        _f("anytls_idle_session_check_interval", "idle-session-check-interval", "number", default=30, minimum=1),
        _f("anytls_idle_session_timeout", "idle-session-timeout", "number", default=180, minimum=1),
        _f("anytls_min_idle_session", "min-idle-session", "number", default=2, minimum=0),
        _f("anytls_ech_enabled", "启用 ECH", "checkbox"),
        _f("anytls_ech_config", "ECH config", "textarea", visible={"key": "anytls_ech_enabled", "equals": True}),
        _f("anytls_ech_query_server_name", "ECH query-server-name", visible={"key": "anytls_ech_enabled", "equals": True}),
    ] + _dialer_fields(),
    "tuic": _common_fields("tuic") + [
        _f("tuic_uuid", "UUID", required=True),
        _f("tuic_password", "Password", "password", required=True),
        _f("tuic_server_ip", "Server IP"),
        _f("tuic_congestion", "Congestion Controller", "select", default="bbr", options=TUIC_CONGESTION_OPTIONS),
        _f("tuic_alpn", "ALPN", "select", default="h3", options=ALPN_OPTIONS,
           help_="可手动输入逗号分隔多值，如 h3,h3-29"),
        _f("tuic_sni", "SNI",
           help_="留空则使用服务器地址作为 SNI"),
        _f("tuic_udp_relay_mode", "UDP Relay Mode", "select", default="native", options=TUIC_RELAY_OPTIONS),
        _f("tuic_heartbeat_interval", "心跳间隔 (毫秒)", "number", default=10000, minimum=1),
        _f("tuic_close_sni", "关闭 SNI 服务器名称指示", "checkbox"),
        _f("tuic_reduce_rtt", "Reduce RTT", "checkbox", default=True),
        _f("tuic_skip_cert_verify", "跳过证书验证", "checkbox", default=True),
        _f("tuic_fast_open", "快速打开", "checkbox", default=True),
        _ip_version_field("tuic_ip_version"),
    ] + _dialer_fields(),
    "hysteria2": _common_fields("hysteria2") + [
        _f("node_password", "密码", "password", required=True),
        _f("hy2_sni", "SNI", default="www.bing.com"),
        _f("hy2_obfs_type", "混淆插件", "select", default="none", options=HY2_OBFS_OPTIONS),
        _f("hy2_up_mbps", "上行链路容量 (Mbps)", "number", default=50, minimum=1),
        _f("hy2_down_mbps", "下行链路容量 (Mbps)", "number", default=100, minimum=1),
        _f("hy2_obfs_password", "混淆密码", "password", visible={"key": "hy2_obfs_type", "not_equals": "none"}, required=True),
        _f("hy2_skip_cert", "跳过证书验证", "checkbox", default=True),
        _f("hy2_alpn", "ALPN", "select", default="h3", options=ALPN_OPTIONS,
           help_="可手动输入逗号分隔多值，如 h3,h3-29"),
        _f("enable_port_hopping", "启用端口跳跃", "checkbox", default=True),
        _f("port_hopping_range", "端口范围", default="29950-30000", visible={"key": "enable_port_hopping", "equals": True}),
        _f("enable_quic_params", "QUIC 参数", "checkbox"),
        _f("initial_stream_receive_window", "initial-stream-receive-window", "number", default=8388608, minimum=1, visible={"key": "enable_quic_params", "equals": True}),
        _f("max_stream_receive_window", "max-stream-receive-window", "number", default=8388608, minimum=1, visible={"key": "enable_quic_params", "equals": True}),
        _f("initial_connection_receive_window", "initial-connection-receive-window", "number", default=20971520, minimum=1, visible={"key": "enable_quic_params", "equals": True}),
        _f("max_connection_receive_window", "max-connection-receive-window", "number", default=20971520, minimum=1, visible={"key": "enable_quic_params", "equals": True}),
        _f("hy2_hop_interval", "跳跃间隔（单位：秒）", default="30",
           help_="端口跳跃间隔，5-25 秒会自动归一为 5 秒"),
        _f("hy2_fingerprint", "Client Fingerprint", "select", default="chrome", options=HY2_FINGERPRINT_OPTIONS),
        _ip_version_field("hy2_ip_version"),
    ] + _dialer_fields(),
}
