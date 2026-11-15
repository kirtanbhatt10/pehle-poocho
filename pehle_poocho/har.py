"""Read HAR (HTTP Archive) files into simple request records."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

from .detect import PAN_RE


class HarError(Exception):
    """The file is not a HAR recording we can read."""


@dataclass
class Request:
    index: int
    started: datetime | None
    method: str
    url: str
    scheme: str
    host: str
    path: str
    raw_query: str
    query: list[tuple[str, str]]
    headers: dict[str, str]
    body: str
    body_params: list[tuple[str, str]]
    set_cookies: list[str]
    resource_type: str

    @property
    def display_url(self) -> str:
        return display_url(self.url)


def display_url(url: str) -> str:
    """scheme://host/path with the query dropped and identifier-looking path segments hidden."""
    parts = urlsplit(url)
    segments = []
    for segment in parts.path.split("/"):
        text = unquote(segment)
        if "@" in text or re.search(r"\d{6,}", text) or PAN_RE.search(text):
            segment = "***"
        segments.append(segment)
    shown = f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}{'/'.join(segments)}"
    return shown if len(shown) <= 100 else shown[:97] + "..."


def parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    m = re.match(r"(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", text)
    if m:
        fraction = (m.group(2) or "")[:7]
        text = m.group(1) + (fraction.ljust(7, "0") if fraction else "") + m.group(3)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _pairs(items) -> list[tuple[str, str]]:
    out = []
    for item in items or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            out.append((unquote_plus(item["name"]), unquote_plus(str(item.get("value", "")))))
    return out


def _parse_entry(index: int, entry: dict) -> Request | None:
    req = entry.get("request")
    if not isinstance(req, dict) or not isinstance(req.get("url"), str):
        return None
    url = req["url"]
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None

    headers: dict[str, str] = {}
    for header in req.get("headers") or []:
        if isinstance(header, dict) and isinstance(header.get("name"), str):
            name, value = header["name"].lower(), str(header.get("value", ""))
            if name == "cookie" and name in headers:
                headers[name] += "; " + value
            else:
                headers[name] = value
    if "cookie" not in headers:
        cookies = [f"{name}={value}" for name, value in _pairs(req.get("cookies"))]
        if cookies:
            headers["cookie"] = "; ".join(cookies)

    post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
    body = post.get("text") if isinstance(post.get("text"), str) else ""
    params = _pairs(post.get("params"))
    if not params and body and "application/x-www-form-urlencoded" in str(post.get("mimeType", "")).lower():
        params = parse_qsl(body, keep_blank_values=True)

    resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    set_cookies = [name for name, _value in _pairs(resp.get("cookies")) if name]
    if not set_cookies:
        for header in resp.get("headers") or []:
            if isinstance(header, dict) and str(header.get("name", "")).lower() == "set-cookie":
                for line in str(header.get("value", "")).split("\n"):
                    name = line.split("=", 1)[0].strip()
                    if name:
                        set_cookies.append(name)

    resource_type = str(entry.get("_resourceType") or "").lower()
    if not resource_type:
        content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        if "text/html" in str(content.get("mimeType", "")).lower():
            resource_type = "document"

    return Request(
        index=index,
        started=parse_time(entry.get("startedDateTime")),
        method=str(req.get("method", "GET")).upper(),
        url=url,
        scheme=parts.scheme,
        host=parts.hostname,
        path=parts.path or "/",
        raw_query=parts.query,
        query=parse_qsl(parts.query, keep_blank_values=True),
        headers=headers,
        body=body,
        body_params=params,
        set_cookies=sorted(set(set_cookies)),
        resource_type=resource_type,
    )


def load(path: str) -> tuple[list[Request], str | None]:
    """Return the recording's requests in time order and the URL of the recorded page."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise HarError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise HarError(f"{path} is not valid JSON: {exc}") from exc
    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise HarError(f"{path} has no log.entries; save it from the browser's Network panel as HAR")

    requests = [r for i, e in enumerate(log["entries"]) if isinstance(e, dict) for r in [_parse_entry(i, e)] if r]
    requests.sort(key=lambda r: (r.started.timestamp() if r.started else float("inf"), r.index))

    page = None
    for p in log.get("pages") or []:
        title = p.get("title") if isinstance(p, dict) else None
        if isinstance(title, str) and title.startswith(("http://", "https://")):
            page = title
            break
    if page is None and requests:
        documents = [r for r in requests if r.resource_type == "document"]
        page = (documents or requests)[0].url
    return requests, page
