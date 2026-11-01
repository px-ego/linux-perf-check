#!/usr/bin/env python3
"""Run one linux-perf-check inspection and push a Feishu summary."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from feishu_notify import send_text


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def _safe_host(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", host).replace(".", "_")


def _load_simple_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_section: dict[str, Any] | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")) and raw_line.rstrip().endswith(":"):
            section = raw_line.strip()[:-1]
            current_section = {}
            data[section] = current_section
            continue
        if current_section is None or ":" not in raw_line:
            continue
        key, value = raw_line.strip().split(":", 1)
        value = value.strip().strip("'\"")
        current_section[key.strip()] = value

    return data


def _load_default_config(skill_root: Path) -> dict[str, Any]:
    config_path = skill_root / "config" / "default.yaml"
    if not config_path.exists():
        return {}

    try:
        try:
            import yaml  # type: ignore
        except ImportError:
            return _load_simple_yaml(config_path)

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise RuntimeError("config/default.yaml must contain a mapping")
        return data
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to read config/default.yaml: {exc}") from exc


def _server_config(skill_root: Path) -> dict[str, Any]:
    config = _load_default_config(skill_root)
    server = config.get("server", {})
    if server is None:
        return {}
    if not isinstance(server, dict):
        raise RuntimeError("config/default.yaml field server must be a mapping")
    return server


def _config_value(config: dict[str, Any], key: str) -> str | None:
    value = config.get(key)
    if value is None:
        return None
    value_str = str(value).strip()
    return value_str if value_str else None


def _first_value(cli_value: Any, env_name: str, config: dict[str, Any], config_key: str) -> Any:
    if cli_value is not None and str(cli_value).strip():
        return cli_value
    env_value = _env(env_name)
    if env_value:
        return env_value
    return _config_value(config, config_key)


def _parse_size_to_mib(value: str) -> float:
    value = value.strip()
    if not value:
        return 0.0
    match = re.match(r"^([\d.]+)\s*([KMGTPE]?i?B?|B)?$", value, re.IGNORECASE)
    if not match:
        return 0.0
    number = float(match.group(1))
    unit = (match.group(2) or "").upper().replace("IB", "").replace("B", "")
    factor = {
        "": 1.0 / 1024.0,
        "K": 1.0 / 1024.0,
        "M": 1.0,
        "G": 1024.0,
        "T": 1024.0 * 1024.0,
        "P": 1024.0 * 1024.0 * 1024.0,
        "E": 1024.0 * 1024.0 * 1024.0 * 1024.0,
    }.get(unit, 0.0)
    return number * factor


def _format_pct(value: float | None) -> str:
    return f"{value:.1f}%" if value is not None else "N/A"


def _stdout(results: dict[str, Any], module: str) -> str:
    item = results.get(module, {})
    if isinstance(item, dict):
        return str(item.get("stdout") or "")
    return ""


def _extract_cpu(results: dict[str, Any]) -> str:
    text = _stdout(results, "cpu")
    cpu_pct: float | None = None
    match = re.search(r"Cpu\(s\):.*?([\d.]+)\s*id", text, re.IGNORECASE)
    if match:
        cpu_pct = max(0.0, min(100.0, 100.0 - float(match.group(1))))

    load = "N/A"
    for line in text.splitlines():
        if re.match(r"^\s*[\d.]+\s+[\d.]+\s+[\d.]+\s+\d+/\d+\s+\d+", line):
            load = " ".join(line.split()[:3])
            break

    return f"{_format_pct(cpu_pct)} used, load {load}"


def _extract_memory(results: dict[str, Any]) -> str:
    text = _stdout(results, "memory")
    for line in text.splitlines():
        if line.strip().startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 3:
                total_raw, used_raw = parts[1], parts[2]
                total = _parse_size_to_mib(total_raw)
                used = _parse_size_to_mib(used_raw)
                pct = (used / total * 100.0) if total > 0 else None
                return f"{used_raw}/{total_raw} ({_format_pct(pct)})"
    return "N/A"


def _extract_disk(results: dict[str, Any]) -> str:
    text = _stdout(results, "disk")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == "/" and parts[-2].endswith("%"):
            return parts[-2]
    return "N/A"


def _is_zero_value_line(line: str) -> bool:
    numbers = re.findall(r"(?<![\d.])(\d+(?:\.\d+)?)(?![\d.])", line)
    return bool(numbers) and all(float(n) == 0.0 for n in numbers)


def _has_high_percentage(line: str, threshold: float = 85.0) -> bool:
    for value in re.findall(r"(\d+(?:\.\d+)?)%", line):
        if float(value) >= threshold:
            return True
    return False


def _extract_alerts(results: dict[str, Any], max_items: int = 8) -> list[str]:
    text = _stdout(results, "alert")
    alert_tokens = (
        "告警",
        "警告",
        "失败",
        "僵尸",
        "鍛婅",
        "澶辫",
        "鍍靛案",
        "warning",
        "error",
        "fail",
        "failed",
        "zombie",
    )
    alerts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if not line or line.startswith("===") or "===" in line:
            continue
        has_keyword = any(token in lower or token in line for token in alert_tokens)
        if not has_keyword and not _has_high_percentage(line):
            continue
        if _is_zero_value_line(line):
            continue
        alerts.append(line)
        if len(alerts) >= max_items:
            break
    return alerts


def _latest_file(reports_dir: Path, suffix: str) -> Path | None:
    candidates = [
        p
        for p in reports_dir.glob(f"*{suffix}")
        if p.is_file() and not p.name.startswith(("batch_summary_", "batch_report_"))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _load_json(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _inspection_failed(data: dict[str, Any], returncode: int) -> bool:
    if returncode != 0:
        return True
    results = data.get("results")
    if not isinstance(results, dict) or not results:
        return False
    statuses = []
    for value in results.values():
        if not isinstance(value, dict):
            continue
        has_stdout = bool(str(value.get("stdout") or "").strip())
        has_error = bool(str(value.get("error") or "").strip())
        statuses.append((has_stdout, has_error))
    return bool(statuses) and all(has_error and not has_stdout for has_stdout, has_error in statuses)


def _compose_message(
    data: dict[str, Any],
    txt_path: Path | None,
    json_path: Path | None,
    host: str,
    port: int,
    user: str,
    check: str,
    failed: bool,
    process: subprocess.CompletedProcess[str],
) -> str:
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    results = data.get("results") if isinstance(data.get("results"), dict) else {}
    report_time = meta.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_host = meta.get("host") or host
    report_port = meta.get("port") or port
    status = "失败" if failed else "成功"

    alerts = _extract_alerts(results)
    alert_text = "无告警" if not alerts else "\n".join(f"- {item}" for item in alerts)
    if failed and not alerts:
        error_tail = (process.stderr or process.stdout or "").strip().splitlines()[-3:]
        if error_tail:
            alert_text = "\n".join(f"- {line}" for line in error_tail)

    lines = [
        f"Linux 巡检{status}",
        f"时间: {report_time}",
        f"主机: {report_host}:{report_port}",
        f"用户: {user}",
        f"检查项: {check}",
        f"CPU: {_extract_cpu(results)}",
        f"内存: {_extract_memory(results)}",
        f"磁盘(/): {_extract_disk(results)}",
        "告警摘要:",
        alert_text,
    ]
    if txt_path:
        lines.append(f"文本报告: {txt_path}")
    if json_path:
        lines.append(f"JSON报告: {json_path}")
    return "\n".join(lines)


def _resolve_args(args: argparse.Namespace, skill_root: Path) -> argparse.Namespace:
    defaults = _server_config(skill_root)
    args.host = _first_value(args.host, "LINUX_PERF_HOST", defaults, "host")
    try:
        raw_port = _first_value(args.port, "LINUX_PERF_PORT", defaults, "port") or 22
        args.port = int(raw_port)
    except ValueError as exc:
        raise RuntimeError("LINUX_PERF_PORT must be an integer") from exc
    args.user = _first_value(args.user, "LINUX_PERF_USER", defaults, "user")
    args.key = _first_value(args.key, "LINUX_PERF_KEY", defaults, "key")
    args.password = args.password or _env("LINUX_PERF_PASSWORD")
    args.check = _first_value(args.check, "LINUX_PERF_CHECK", defaults, "check")

    if args.key:
        args.key = os.path.expanduser(str(args.key))

    if not args.host:
        raise RuntimeError("Missing host: set --host, LINUX_PERF_HOST, or config/default.yaml server.host")
    if not args.user:
        raise RuntimeError("Missing user: set --user, LINUX_PERF_USER, or config/default.yaml server.user")
    if not args.key and not args.password:
        raise RuntimeError("Missing SSH credential: set --key, LINUX_PERF_KEY, config/default.yaml server.key, or password fallback")
    if not args.check:
        raise RuntimeError("Missing check: set --check, LINUX_PERF_CHECK, or config/default.yaml server.check")
    return args


def _run_inspection(args: argparse.Namespace, txt_path: Path, json_path: Path) -> subprocess.CompletedProcess[str]:
    script_dir = Path(__file__).resolve().parent
    skill_root = script_dir.parent
    inspection_script = script_dir / "linux_inspection.py"
    cmd = [
        sys.executable,
        str(inspection_script),
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--user",
        args.user,
        "--check",
        args.check,
        "-o",
        str(txt_path),
        "--json-output",
        str(json_path),
    ]
    if args.key:
        cmd.extend(["--key", args.key])
    else:
        cmd.extend(["--password", args.password])

    return subprocess.run(
        cmd,
        cwd=str(skill_root),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one Linux inspection and push a Feishu text summary")
    parser.add_argument("--host", help="SSH host; overrides LINUX_PERF_HOST and config/default.yaml")
    parser.add_argument("--port", type=int, help="SSH port; overrides LINUX_PERF_PORT and config/default.yaml")
    parser.add_argument("--user", help="SSH user; overrides LINUX_PERF_USER and config/default.yaml")
    parser.add_argument("--key", help="SSH private key path; preferred over password")
    parser.add_argument("--password", help="SSH password fallback")
    parser.add_argument("--check", help="inspection modules; overrides LINUX_PERF_CHECK and config/default.yaml")
    args = parser.parse_args()

    try:
        skill_root = Path(__file__).resolve().parent.parent
        args = _resolve_args(args, skill_root)
        reports_dir = skill_root / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{_safe_host(args.host)}_{timestamp}"
        txt_path = reports_dir / f"{base}.txt"
        json_path = reports_dir / f"{base}.json"

        process = _run_inspection(args, txt_path, json_path)
        actual_txt = txt_path if txt_path.exists() else _latest_file(reports_dir, ".txt")
        actual_json = json_path if json_path.exists() else _latest_file(reports_dir, ".json")
        data = _load_json(actual_json)
        failed = _inspection_failed(data, process.returncode)
        message = _compose_message(
            data=data,
            txt_path=actual_txt,
            json_path=actual_json,
            host=args.host,
            port=args.port,
            user=args.user,
            check=args.check,
            failed=failed,
            process=process,
        )
        send_text(message)
    except RuntimeError as exc:
        print(f"[inspection notify failed] {exc}", file=sys.stderr)
        return 1

    print(f"[Feishu notified] host={args.host} check={args.check} report={actual_txt or 'N/A'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
