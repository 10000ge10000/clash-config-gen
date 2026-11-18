import json
import unittest
from unittest import mock

import node_health


def fake_resolve(mapping):
    def resolve(host, _port):
        if host not in mapping:
            raise OSError("no such host")
        return [(None, None, None, "", (address, 0)) for address in mapping[host]]
    return resolve


def json_dump(value):
    return json.dumps(value, ensure_ascii=False)


class PlanHealthCheckTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(node_health, "ipv6_available", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_skips_private_direct_and_duplicate_nodes(self):
        proxies = [
            {"name": "A", "type": "hysteria2", "server": "8.8.8.8", "port": 443},
            {"name": "B", "type": "ss", "server": "10.0.0.5", "port": 8388},
            {"name": "C", "type": "direct"},
            {"name": "D", "type": "vless", "server": "inner.example", "port": 443},
            {"name": "E", "type": "vless", "server": "pub.example", "port": 443},
            {"name": "A", "type": "ss", "server": "1.1.1.1", "port": 1},
            {"name": "F", "type": "ss", "server": "localhost", "port": 1},
            {"name": "G", "type": "ss", "server": "[::1]", "port": 1},
        ]
        resolve = fake_resolve({"inner.example": ["192.168.1.2"], "pub.example": ["1.1.1.1", "2606:4700::1111"]})
        config, names, skipped = node_health.plan_health_check(proxies, [], resolve)
        self.assertEqual(names, ["A", "E"])
        self.assertEqual(skipped, {"B": "private", "C": "unsupported", "D": "private", "F": "private", "G": "private"})
        # 域名在服务器上解析一次并固定给 mihomo，防止 DNS rebinding。
        self.assertEqual(config["hosts"], {"pub.example": ["1.1.1.1", "2606:4700::1111"]})
        self.assertTrue(config["use-hosts"])
        self.assertFalse(config["use-system-hosts"])
        self.assertEqual([proxy["name"] for proxy in config["proxies"]], ["A", "E"])
        self.assertEqual(config["proxy-groups"], [{"name": node_health.HEALTH_GROUP_NAME, "type": "select", "proxies": ["A", "E"]}])
        self.assertEqual(config["rules"], ["MATCH,DIRECT"])
        self.assertNotIn("external-controller", config)

    def test_unresolvable_domain_is_down_and_not_given_to_mihomo(self):
        config, names, skipped = node_health.plan_health_check(
            [{"name": "X", "type": "ss", "server": "gone.example", "port": 1}], [], fake_resolve({}))
        self.assertEqual(names, [])
        self.assertEqual(skipped, {"X": "unresolved"})
        self.assertEqual(config["proxies"], [])

    def test_wireguard_peers_are_checked_and_interface_ip_is_ignored(self):
        proxies = [
            {"name": "WG", "type": "wireguard", "server": "1.1.1.1", "ip": "172.16.0.2", "port": 51820},
            {"name": "WG2", "type": "wireguard", "ip": "172.16.0.2", "peers": [{"server": "10.0.0.9", "port": 1}]},
        ]
        _, names, skipped = node_health.plan_health_check(proxies, [], fake_resolve({}))
        self.assertEqual(names, ["WG"])
        self.assertEqual(skipped, {"WG2": "private"})

    def test_resolution_has_overall_timeout(self):
        import threading
        release = threading.Event()

        def slow(host, _port):
            release.wait(5)
            raise OSError("late")

        with mock.patch.object(node_health, "RESOLVE_TIMEOUT", 0.2):
            started = node_health.time.monotonic()
            _, names, skipped = node_health.plan_health_check(
                [{"name": "S", "type": "ss", "server": "slow.example", "port": 1}], [], slow)
            elapsed = node_health.time.monotonic() - started
        release.set()
        self.assertLess(elapsed, 2)
        self.assertEqual(skipped, {"S": "unresolved"})

    def test_groups_become_select_without_user_url_and_dialer_is_kept_when_reachable(self):
        proxies = [
            {"name": "Up", "type": "ss", "server": "1.1.1.1", "port": 1},
            {"name": "Down", "type": "ss", "server": "8.8.4.4", "port": 1, "dialer-proxy": "Chain"},
            {"name": "Lost", "type": "ss", "server": "9.9.9.9", "port": 1, "dialer-proxy": "Missing"},
            {"name": "Inner", "type": "ss", "server": "10.1.1.1", "port": 1},
        ]
        groups = [
            {"name": "Chain", "type": "url-test", "url": "http://127.0.0.1:8000/", "interval": 60, "proxies": ["Up"]},
            {"name": "OnlyInner", "type": "fallback", "proxies": ["Inner"]},
            {"name": "Outer", "type": "select", "proxies": ["OnlyInner"]},
            {"name": "Mixed", "type": "select", "proxies": ["Inner", "Up", "DIRECT"]},
            {"name": "Remote", "type": "select", "use": ["provider"]},
        ]
        config, names, _ = node_health.plan_health_check(proxies, groups, fake_resolve({}))
        self.assertEqual(names, ["Up", "Down", "Lost"])
        by_name = {group["name"]: group for group in config["proxy-groups"]}
        self.assertEqual(by_name["Chain"], {"name": "Chain", "type": "select", "proxies": ["Up"]})
        self.assertEqual(by_name["Mixed"]["proxies"], ["Up", "DIRECT"])
        self.assertNotIn("OnlyInner", by_name)
        self.assertNotIn("Outer", by_name)
        self.assertNotIn("Remote", by_name)
        nodes = {proxy["name"]: proxy for proxy in config["proxies"]}
        self.assertEqual(nodes["Down"]["dialer-proxy"], "Chain")
        self.assertNotIn("dialer-proxy", nodes["Lost"])
        self.assertFalse(any("url" in group for group in config["proxy-groups"]))


class Ipv6HandlingTest(unittest.TestCase):
    PROXIES = [
        {"name": "V6", "type": "hysteria2", "server": "2606:4700::1111", "port": 443},
        {"name": "Dual", "type": "vless", "server": "dual.example", "port": 443},
        {"name": "OnlyV6", "type": "vless", "server": "v6.example", "port": 443},
        {"name": "Inner6", "type": "ss", "server": "fd00::1", "port": 1},
    ]
    RESOLVE = staticmethod(fake_resolve({"dual.example": ["1.1.1.1", "2606:4700::1001"], "v6.example": ["2606:4700::1002"]}))

    def test_ipv6_nodes_are_tested_when_server_has_ipv6(self):
        config, names, skipped = node_health.plan_health_check(self.PROXIES, [], self.RESOLVE, ipv6=True)
        self.assertEqual(names, ["V6", "Dual", "OnlyV6"])
        self.assertEqual(skipped, {"Inner6": "private"})
        self.assertEqual(config["hosts"]["dual.example"], ["1.1.1.1", "2606:4700::1001"])
        self.assertTrue(config["ipv6"])

    def test_without_ipv6_pure_v6_nodes_are_skipped_not_down(self):
        config, names, skipped = node_health.plan_health_check(self.PROXIES, [], self.RESOLVE, ipv6=False)
        self.assertEqual(names, ["Dual"])
        self.assertEqual(skipped, {"V6": "ipv6", "OnlyV6": "ipv6", "Inner6": "private"})
        # 同时有 v4 / v6 的域名只用 IPv4 测。
        self.assertEqual(config["hosts"], {"dual.example": "1.1.1.1"})

    def test_reasons_are_returned_with_results(self):
        node_health._CACHE.clear()
        with mock.patch.object(node_health, "health_enabled", return_value=True), \
                mock.patch.object(node_health, "ipv6_available", return_value=False):
            result = node_health.check_user_nodes(
                21, self.PROXIES, [], runner=lambda config, names: {"Dual": True}, resolve=self.RESOLVE)
        self.assertEqual(result["results"], {"Dual": "ok", "V6": "skipped", "OnlyV6": "skipped", "Inner6": "skipped"})
        self.assertEqual(result["reasons"], {"V6": "ipv6", "OnlyV6": "ipv6", "Inner6": "private"})


class Ipv6AvailabilityTest(unittest.TestCase):
    def check(self, local=None, error=None):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        if error:
            sock.connect.side_effect = error
        sock.getsockname.return_value = (local, 0, 0, 0)
        node_health._IPV6_STATE.update(checked=0.0, available=False)
        with mock.patch.object(node_health.socket, "socket", return_value=sock):
            return node_health.ipv6_available()

    def test_nat66_ula_source_counts_as_available(self):
        self.assertTrue(self.check("fd7a:c1a5:6e17:1::2"))
        self.assertTrue(self.check("2001:db8::5"))

    def test_no_route_or_link_local_is_unavailable(self):
        self.assertFalse(self.check(error=OSError(101, "Network is unreachable")))
        self.assertFalse(self.check("fe80::1"))
        self.assertFalse(self.check("::1"))


class CheckUserNodesTest(unittest.TestCase):
    def setUp(self):
        node_health._CACHE.clear()
        patcher = mock.patch.object(node_health, "health_enabled", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        resolve_patch = mock.patch.object(node_health.socket, "getaddrinfo", side_effect=OSError("offline"))
        resolve_patch.start()
        self.addCleanup(resolve_patch.stop)
        ipv6_patch = mock.patch.object(node_health, "ipv6_available", return_value=True)
        ipv6_patch.start()
        self.addCleanup(ipv6_patch.stop)

    def proxies(self):
        return [
            {"name": "A", "type": "ss", "server": "1.1.1.1", "port": 1, "_source_name": "x"},
            {"name": "B", "type": "ss", "server": "8.8.8.8", "port": 1},
            {"name": "C", "type": "ss", "server": "127.0.0.1", "port": 1},
            {"name": "D", "type": "ss", "server": "gone.example", "port": 1},
        ]

    def test_maps_results_and_caches(self):
        calls = []

        def runner(config, names):
            calls.append(list(names))
            return {"A": True, "B": False}

        configs = []
        original = runner

        def runner(config, names):
            configs.append(config)
            return original(config, names)

        result = node_health.check_user_nodes(7, self.proxies(), [], runner=runner)
        self.assertEqual(result["results"], {"A": "ok", "B": "down", "C": "skipped", "D": "down"})
        self.assertNotIn("_source_name", configs[0]["proxies"][0])
        self.assertTrue(result["enabled"])
        again = node_health.check_user_nodes(7, self.proxies(), [], runner=runner)
        self.assertEqual(again, result)
        self.assertEqual(len(calls), 1)
        changed = self.proxies()[:1]
        node_health.check_user_nodes(7, changed, [], runner=runner)
        self.assertEqual(len(calls), 2)

    def test_force_bypasses_cache_after_short_interval(self):
        calls = []

        def runner(config, names):
            calls.append(1)
            return {}

        clock = [100.0]
        with mock.patch.object(node_health.time, "time", side_effect=lambda: clock[0]):
            node_health.check_user_nodes(8, self.proxies(), [], runner=runner)
            clock[0] = 101.0  # 5 秒内的强制检测复用结果，防止连点
            node_health.check_user_nodes(8, self.proxies(), [], force=True, runner=runner)
            clock[0] = 110.0
            node_health.check_user_nodes(8, self.proxies(), [], force=True, runner=runner)
        self.assertEqual(len(calls), 2)

    def test_runner_error_is_cached_to_avoid_restart_loops(self):
        calls = []

        def runner(config, names):
            calls.append(1)
            raise RuntimeError("secret detail")

        result = node_health.check_user_nodes(9, self.proxies(), [], runner=runner)
        self.assertEqual(result["results"], {})
        self.assertEqual(result["error"], "检测暂时不可用")
        self.assertNotIn("secret", json_dump(result))
        node_health.check_user_nodes(9, self.proxies(), [], runner=runner)
        self.assertEqual(len(calls), 1)

    def test_concurrent_request_for_same_user_returns_busy_without_waiting(self):
        lock = node_health._user_lock(11)
        lock.acquire()
        try:
            result = node_health.check_user_nodes(11, self.proxies(), [], runner=lambda c, n: {})
        finally:
            lock.release()
        self.assertTrue(result["busy"])
        self.assertEqual(result["results"], {})

    def test_global_slots_full_returns_busy(self):
        with mock.patch.object(node_health, "SEMAPHORE_WAIT", 0.05), \
                mock.patch.object(node_health, "_GLOBAL_SEMAPHORE", node_health.threading.BoundedSemaphore(1)) as sem:
            sem.acquire()
            try:
                result = node_health.check_user_nodes(12, self.proxies(), [], runner=lambda c, n: {})
            finally:
                sem.release()
        self.assertTrue(result["busy"])

    def test_disabled_returns_flag(self):
        with mock.patch.object(node_health, "health_enabled", return_value=False):
            result = node_health.check_user_nodes(10, self.proxies(), [])
        self.assertEqual(result, {"enabled": False, "checked_at": 0, "results": {}})


if __name__ == "__main__":
    unittest.main()
