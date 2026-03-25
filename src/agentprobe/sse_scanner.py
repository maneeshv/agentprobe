"""
SSE Scanner — handles Server-Sent Events (SSE) streaming endpoints.

Parses SSE streams, extracts the final response, and runs the same
analysis as the standard scanner.
"""

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .payloads import Payload, get_payloads
from .scanner import ScanResult, analyze_response


def parse_sse_events(raw: str) -> list[dict[str, str]]:
    """Parse raw SSE text into a list of {event, data} dicts."""
    events = []
    current: dict[str, str] = {}
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            if current:
                events.append(current)
                current = {}
            continue
        if line.startswith("event:"):
            current["event"] = line[6:].strip()
        elif line.startswith("data:"):
            data_part = line[5:].strip()
            if "data" in current:
                current["data"] += "\n" + data_part
            else:
                current["data"] = data_part
    if current:
        events.append(current)
    return events


def extract_response_from_sse(raw: str, response_path: str | None = None) -> str:
    """
    Extract the final agent response from an SSE stream.

    Tries to find the 'complete' event first, then falls back to
    concatenating all data events.
    """
    events = parse_sse_events(raw)

    # Look for 'complete' status event
    for ev in reversed(events):
        data_str = ev.get("data", "")
        try:
            data = json.loads(data_str)
        except (json.JSONDecodeError, TypeError):
            continue

        status = data.get("status")
        if status == "complete":
            if response_path:
                return _extract_path(data, response_path)
            # Try common paths
            answer = _try_common_paths(data)
            if answer:
                return answer
            return data_str

    # Fallback: concatenate all 'streaming' data or delta events
    chunks = []
    for ev in events:
        data_str = ev.get("data", "")
        try:
            data = json.loads(data_str)
        except (json.JSONDecodeError, TypeError):
            chunks.append(data_str)
            continue

        # delta events
        if ev.get("event") == "delta":
            answer = data.get("answer", "")
            if answer:
                chunks.append(answer)
                continue

        # streaming events
        if data.get("status") == "streaming":
            answer = _try_common_paths(data)
            if answer:
                chunks.append(answer)

    return " ".join(chunks) if chunks else raw


def _extract_path(data: Any, path: str) -> str:
    """Extract value from nested dict using dot-notation path."""
    current = data
    for key in path.split("."):
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return str(data)
        else:
            return str(data)
        if current is None:
            return str(data)
    return str(current)


def _try_common_paths(data: dict) -> str | None:
    """Try common response paths to extract the answer."""
    paths = [
        ["message", "response", "data", "answer", "answer"],
        ["message", "response", "data", "answer"],
        ["message", "response", "answer"],
        ["response", "data", "answer"],
        ["response", "answer"],
        ["answer"],
        ["message", "content"],
        ["content"],
    ]
    for path in paths:
        current: Any = data
        for key in path:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                current = None
                break
        if current and isinstance(current, str):
            return current
    return None


class SSEScanner:
    """Runs payloads against an SSE streaming endpoint."""

    def __init__(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        cookie_string: str | None = None,
        body_template: dict[str, Any] | None = None,
        payload_path: str = "params.question",
        response_path: str | None = None,
        timeout: float = 60.0,
        concurrency: int = 2,
        delay: float = 2.0,
    ):
        """
        Args:
            endpoint: SSE endpoint URL
            headers: HTTP headers
            cookies: Cookie dict
            cookie_string: Raw cookie string (alternative to cookies dict)
            body_template: Base request body (deep-copied per payload).
                          The payload text replaces the value at payload_path.
            payload_path: Dot-notation path in body_template where the payload
                         text gets inserted. Default: "params.question"
            response_path: Dot-notation path to extract response from the
                          'complete' SSE event JSON. Auto-detected if not set.
            timeout: Request timeout in seconds
            concurrency: Max concurrent requests
            delay: Delay between requests (seconds)
        """
        self.endpoint = endpoint
        self.headers = headers or {}
        self.cookies = cookies
        self.cookie_string = cookie_string
        self.body_template = body_template or {
            "event": "textbox",
            "params": {"question": "{{PAYLOAD}}", "thinking_mode": "quick"},
            "product_recommender": True,
            "meta_context": {"local_time": "2026-03-24T11:34:13.889+05:30"},
        }
        self.payload_path = payload_path
        self.response_path = response_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.delay = delay

    def _build_body(self, payload: Payload) -> dict[str, Any]:
        """Build the request body with the payload injected."""
        import copy
        body = copy.deepcopy(self.body_template)
        # Navigate to the right place and set the value
        keys = self.payload_path.split(".")
        current = body
        for key in keys[:-1]:
            current = current[key]
        current[keys[-1]] = payload.prompt
        return body

    async def _send_payload(
        self,
        client: httpx.AsyncClient,
        payload: Payload,
        semaphore: asyncio.Semaphore,
    ) -> ScanResult:
        """Send a single payload and analyze the SSE response."""
        async with semaphore:
            body = self._build_body(payload)
            start = time.monotonic()
            raw_response = ""

            try:
                async with client.stream(
                    "POST",
                    self.endpoint,
                    json=body,
                    timeout=self.timeout,
                ) as resp:
                    chunks = []
                    async for chunk in resp.aiter_text():
                        chunks.append(chunk)
                        # Stop reading once we get a complete event
                        joined = "".join(chunks)
                        if '"status": "complete"' in joined or '"status":"complete"' in joined:
                            break
                    raw_response = "".join(chunks)

                elapsed_ms = (time.monotonic() - start) * 1000

                # Extract the final response text
                response_text = extract_response_from_sse(
                    raw_response, self.response_path
                )

                findings, refused = analyze_response(response_text)

                result = ScanResult(
                    payload=payload,
                    response_text=response_text,
                    response_status=resp.status_code,
                    response_time_ms=elapsed_ms,
                    findings=findings,
                    refused=refused,
                )

            except httpx.TimeoutException:
                result = ScanResult(
                    payload=payload,
                    response_text=raw_response,
                    response_status=0,
                    response_time_ms=(time.monotonic() - start) * 1000,
                    error="Request timed out",
                )
            except Exception as e:
                result = ScanResult(
                    payload=payload,
                    response_text=raw_response,
                    response_status=0,
                    response_time_ms=(time.monotonic() - start) * 1000,
                    error=str(e),
                )

            if self.delay > 0:
                await asyncio.sleep(self.delay)

            return result

    async def scan(
        self,
        category: str | None = None,
        severity: str | None = None,
        tag: str | None = None,
        names: list[str] | None = None,
        on_result: Any = None,
        include_domain: str | None = None,
        domain_only: bool = False,
        extra_payloads: list | None = None,
        extra_only: bool = False,
    ) -> list[ScanResult]:
        """Run payloads against the SSE endpoint."""
        payloads = get_payloads(
            category=category, severity=severity, tag=tag,
            include_domain=include_domain, domain_only=domain_only,
            extra_payloads=extra_payloads, extra_only=extra_only,
        )
        if names:
            payloads = [p for p in payloads if p.name in names]

        if not payloads:
            return []

        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[ScanResult] = []

        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            **self.headers,
        }

        # Build cookie header
        cookie_header = self.cookie_string
        if self.cookies and not cookie_header:
            cookie_header = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        if cookie_header:
            headers["Cookie"] = cookie_header

        async with httpx.AsyncClient(headers=headers) as client:
            tasks = [
                self._send_payload(client, payload, semaphore)
                for payload in payloads
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                if on_result:
                    await on_result(result)

        results.sort(key=lambda r: r.payload.name)
        return results

    def scan_sync(self, **kwargs: Any) -> list[ScanResult]:
        """Synchronous wrapper around scan()."""
        return asyncio.run(self.scan(**kwargs))
