#!/usr/bin/env python3
"""Send Feishu/Lark custom bot text messages."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from typing import Any
from urllib import error, request


def generate_sign(timestamp: str, secret: str) -> str:
    string_to_sign = f"{timestamp}\n{secret}"
    digest = hmac.new(
        string_to_sign.encode("utf-8"),
        b"",
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def build_text_payload(text: str, secret: str | None = None) -> dict[str, Any]:
    if not text:
        raise RuntimeError("Feishu text message is empty")

    payload: dict[str, Any] = {
        "msg_type": "text",
        "content": {"text": text},
    }
    if secret:
        timestamp = str(int(time.time()))
        payload["timestamp"] = timestamp
        payload["sign"] = generate_sign(timestamp, secret)
    return payload


def _read_response(resp: Any) -> tuple[int, str]:
    body = resp.read().decode("utf-8", errors="replace")
    return int(resp.status), body


def _extract_code(data: dict[str, Any]) -> int:
    raw_code = data.get("code", data.get("StatusCode", data.get("status_code", 0)))
    try:
        return int(raw_code)
    except (TypeError, ValueError):
        raise RuntimeError(f"Feishu webhook returned non-numeric code: {raw_code!r}")


def send_text(
    text: str,
    webhook_url: str | None = None,
    secret: str | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    webhook = webhook_url or os.environ.get("FEISHU_WEBHOOK_URL")
    if not webhook:
        raise RuntimeError("Missing FEISHU_WEBHOOK_URL environment variable")

    bot_secret = secret if secret is not None else os.environ.get("FEISHU_SECRET")
    payload = build_text_payload(text, bot_secret)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        webhook,
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "linux-perf-check/feishu-notify",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            status, body = _read_response(resp)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Feishu webhook HTTP {exc.code}: {body[:500]}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Feishu webhook request failed: {exc.reason}") from exc

    if status < 200 or status >= 300:
        raise RuntimeError(f"Feishu webhook HTTP {status}: {body[:500]}")

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Feishu webhook returned invalid JSON: {body[:500]}") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError(f"Feishu webhook returned unexpected JSON: {parsed!r}")

    code = _extract_code(parsed)
    if code != 0:
        msg = parsed.get("msg") or parsed.get("StatusMessage") or parsed.get("message") or ""
        raise RuntimeError(f"Feishu webhook returned error code {code}: {msg}")

    return parsed


def _read_text_arg(args: argparse.Namespace) -> str:
    if args.text:
        return args.text
    if args.message:
        return " ".join(args.message)
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    raise RuntimeError("Provide message text with --text, positional args, or stdin")


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a Feishu custom bot text message")
    parser.add_argument("message", nargs="*", help="message text")
    parser.add_argument("--text", help="message text")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    args = parser.parse_args()

    try:
        send_text(_read_text_arg(args), timeout=args.timeout)
    except RuntimeError as exc:
        print(f"[Feishu push failed] {exc}", file=sys.stderr)
        return 1

    print("[Feishu push success]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
