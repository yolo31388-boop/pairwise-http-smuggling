"""HTTP 请求走私（request smuggling）防御工具集。

核心原则：所有代理/后端必须对同一请求得出**唯一**的消息边界解释。
本模块提供：

* 严格的头部解析（拒绝 obs-fold、冒号前空白、裸 LF/CR、控制字符等）；
* ``Content-Length`` / ``Transfer-Encoding`` 的严格校验；
* 对歧义请求的拒绝（同时出现 CL/TE、重复 CL/TE、非法编码等）；
* 禁用 ``Transfer-Encoding``（按策略拒绝分块请求）；
* 头部/请求体大小限制；
* 走私特征检测、前后端一致性比对、审计与错误映射。

设计为 fail-closed：无法可靠解析的输入一律视为不可信并拒绝。
所有入口都接受原始报文（``bytes`` / ``str``）、头部集合
（``dict`` / ``list[(name, value)]`` / 原始头部块）或已解析结果字典，
并对非法输入返回结构化的拒绝结果而不是抛出异常。
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

__all__ = [
    "reject_ambiguous",
    "unified_parser",
    "header_length",
    "te_disable",
    "cl_check",
    "smuggling_detect",
    "proxy_consistency",
    "validation",
    "audit",
    "error_map",
    "rate_limit",
    "logging",
    "fallback",
    "body_limit",
    "test_vectors",
]

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_MAX_HEADER_BYTES = 8 * 1024
DEFAULT_MAX_HEADER_COUNT = 100
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW = 60.0

_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REQUEST_LINE_RE = re.compile(r"^(\S+) (\S+) (HTTP/\d\.\d)$")
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")
_CHUNK_SIZE_RE = re.compile(rb"^[0-9A-Fa-f]+$")

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def _issue(code: str, severity: str, detail: str = "") -> dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def _dedupe_issues(issues: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for item in issues:
        code = str(item.get("code", "unknown"))
        detail = str(item.get("detail", ""))
        key = (code, detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "code": code,
                "severity": str(item.get("severity", "medium")),
                "detail": detail,
            }
        )
    return out


def _max_severity(issues: Iterable[Mapping[str, Any]]) -> str | None:
    level = 0
    name: str | None = None
    for item in issues:
        sev = str(item.get("severity", "medium"))
        rank = _SEVERITY_ORDER.get(sev, 0)
        if rank > level:
            level, name = rank, sev
    return name


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1", "replace")
    raise ValueError("value is not text")


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("latin-1", "replace")
    raise ValueError("value is not text")


def _valid_status(status: Any, default: int = 400) -> int:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return default
    return code if 400 <= code <= 599 else default


# ---------------------------------------------------------------------------
# 头部规范化
# ---------------------------------------------------------------------------


def _check_header_name(name: str, issues: list[dict[str, str]]) -> str:
    """校验头部字段名，返回用于比较的规范名（小写）。"""
    normalized = name.strip()
    if name != normalized:
        issues.append(
            _issue(
                "whitespace_before_colon",
                "high",
                "header name has leading/trailing whitespace before ':'",
            )
        )
    if any(ch.isspace() for ch in normalized):
        issues.append(
            _issue("whitespace_in_header_name", "high", "header name contains whitespace")
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        issues.append(_issue("control_char", "high", "control character in header name"))
    if normalized and not _TOKEN_RE.match(normalized):
        issues.append(
            _issue("invalid_header_name", "high", "header name is not a valid token")
        )
    return normalized.lower()


def _check_header_value(value: str, issues: list[dict[str, str]]) -> str:
    if any(ord(ch) < 0x20 and ch != "\t" for ch in value) or any(
        ord(ch) == 0x7F for ch in value
    ):
        issues.append(
            _issue("control_char", "high", "control character in header value")
        )
    return value.strip(" \t")


def _parse_raw_header_lines(
    text: str, max_count: int = DEFAULT_MAX_HEADER_COUNT
) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    """解析原始头部块（不含起始行）。保留重复字段的顺序。"""
    pairs: list[tuple[str, str]] = []
    issues: list[dict[str, str]] = []
    if not text:
        return pairs, issues

    if re.search(r"(?<!\r)\n", text):
        issues.append(_issue("bare_lf", "high", "header block uses bare LF line endings"))
    if re.search(r"\r(?!\n)", text):
        issues.append(_issue("bare_cr", "high", "header block uses bare CR line endings"))

    lines = re.split(r"\r?\n", text)
    for line in lines:
        if line == "":
            continue
        if line[0] in " \t":
            issues.append(
                _issue(
                    "obs_fold",
                    "high",
                    "obsolete line folding (continuation line) is not accepted",
                )
            )
            continue
        colon = line.find(":")
        if colon <= 0:
            issues.append(_issue("malformed_header", "high", "header line has no ':'"))
            continue
        raw_name = line[:colon]
        raw_value = line[colon + 1 :]
        name = _check_header_name(raw_name, issues)
        value = _check_header_value(raw_value, issues)
        if len(pairs) >= max_count:
            issues.append(
                _issue(
                    "too_many_headers",
                    "high",
                    f"more than {max_count} header fields",
                )
            )
            break
        pairs.append((name, value))
    return pairs, issues


def _coerce_header_pairs(
    headers: Any,
) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    """把多种头部表示统一成 ``[(name, value), ...]``。

    支持 dict、二维序列、原始头部块。无法识别时抛 ``ValueError``。
    """
    issues: list[dict[str, str]] = []

    if headers is None:
        return [], issues

    if isinstance(headers, Mapping):
        pairs: list[tuple[str, str]] = []
        for key, value in headers.items():
            name = _check_header_name(_to_text(key), issues)
            val = _check_header_value(_to_text(value), issues)
            pairs.append((name, val))
        return pairs, issues

    if isinstance(headers, (bytes, bytearray, memoryview, str)):
        return _parse_raw_header_lines(_to_text(headers))

    if isinstance(headers, (list, tuple)):
        pairs = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                name = _check_header_name(_to_text(item[0]), issues)
                val = _check_header_value(_to_text(item[1]), issues)
                pairs.append((name, val))
            elif isinstance(item, (bytes, bytearray, memoryview, str)):
                parsed, line_issues = _parse_raw_header_lines(_to_text(item))
                pairs.extend(parsed)
                issues.extend(line_issues)
            else:
                raise ValueError("unsupported header item")
        return pairs, issues

    raise ValueError("unsupported headers type")


# ---------------------------------------------------------------------------
# Content-Length / Transfer-Encoding 语义
# ---------------------------------------------------------------------------


def _parse_content_length(value: str) -> tuple[int | None, str | None]:
    """严格解析单个 Content-Length 值。返回 (长度, 错误码)。"""
    if not isinstance(value, str):
        return None, "invalid_content_length"
    # 逗号列表（"5, 5"）是常见的解析器分歧点，直接拒绝。
    if "," in value:
        return None, "content_length_list"
    stripped = value.strip(" \t")
    if not stripped:
        return None, "invalid_content_length"
    # 限制位数，避免超大整数带来的解析开销/差异。
    if len(stripped) > 20 or not _CONTENT_LENGTH_RE.match(stripped):
        return None, "invalid_content_length"
    return int(stripped), None


def _parse_transfer_encoding(
    values: list[str],
) -> tuple[list[str] | None, str | None]:
    """解析 Transfer-Encoding 字段列表，只接受精确的 ``chunked``。"""
    codings: list[str] = []
    for value in values:
        parts = value.split(",")
        if any(part.strip() == "" for part in parts):
            return None, "invalid_transfer_encoding"
        codings.extend(part.strip().lower() for part in parts)
    if codings == ["chunked"]:
        return ["chunked"], None
    if "chunked" not in codings:
        return codings, "unsupported_transfer_encoding"
    if codings[-1] != "chunked":
        return codings, "chunked_not_last"
    if codings.count("chunked") > 1:
        return codings, "duplicate_chunked_coding"
    return codings, "unsupported_transfer_encoding"


def _analyze_message(
    pairs: list[tuple[str, str]], issues: list[dict[str, str]]
) -> dict[str, Any]:
    """基于规范化头部推导消息边界（framing）。"""
    issues = list(issues)

    cl_values = [value for name, value in pairs if name == "content-length"]
    te_values = [value for name, value in pairs if name == "transfer-encoding"]

    framing = "none"
    content_length: int | None = None
    transfer_encoding: list[str] | None = None

    if cl_values and te_values:
        issues.append(
            _issue(
                "both_cl_and_te",
                "high",
                "request carries both Content-Length and Transfer-Encoding",
            )
        )
        framing = "ambiguous"

    if len(cl_values) > 1:
        issues.append(
            _issue(
                "duplicate_content_length",
                "high",
                f"multiple Content-Length fields ({len(cl_values)})",
            )
        )
        framing = "ambiguous"
    elif len(cl_values) == 1:
        parsed, error = _parse_content_length(cl_values[0])
        if error:
            issues.append(_issue(error, "high", "invalid Content-Length value"))
            if framing != "ambiguous":
                framing = "invalid-content-length"
        else:
            content_length = parsed
            if cl_values[0].strip(" \t") != str(parsed):
                issues.append(
                    _issue(
                        "content_length_leading_zero",
                        "low",
                        "Content-Length has leading zeros",
                    )
                )
            if framing == "none":
                framing = "content-length"

    if te_values:
        if len(te_values) > 1:
            issues.append(
                _issue(
                    "duplicate_transfer_encoding",
                    "high",
                    f"multiple Transfer-Encoding fields ({len(te_values)})",
                )
            )
            framing = "ambiguous"
        parsed_te, te_error = _parse_transfer_encoding(te_values)
        if te_error:
            issues.append(
                _issue(
                    te_error,
                    "high",
                    f"non-canonical Transfer-Encoding: {te_values!r}",
                )
            )
            if framing == "none":
                framing = "invalid-transfer-encoding"
        else:
            transfer_encoding = parsed_te
            if framing == "none":
                framing = "chunked"

    header_map: dict[str, list[str]] = {}
    for name, value in pairs:
        header_map.setdefault(name, []).append(value)

    return {
        "ok": not any(i["severity"] == "high" for i in issues),
        "status": 200,
        "error": None,
        "method": None,
        "target": None,
        "version": None,
        "headers": pairs,
        "header_map": header_map,
        "framing": framing,
        "content_length": content_length,
        "transfer_encoding": transfer_encoding,
        "cl_values": cl_values,
        "te_values": te_values,
        "body": b"",
        "body_bytes": 0,
        "extra_bytes": b"",
        "issues": _dedupe_issues(issues),
    }


def _view_from_headers(headers: Any) -> dict[str, Any] | None:
    try:
        pairs, issues = _coerce_header_pairs(headers)
    except (ValueError, TypeError):
        return None
    view = _analyze_message(pairs, issues)
    _finalize_view(view)
    return view


def _finalize_view(view: dict[str, Any]) -> None:
    high = [i for i in view["issues"] if i["severity"] == "high"]
    view["ok"] = not high
    if "status" not in view or view["status"] == 200:
        view["status"] = 200 if view["ok"] else 400
    view["error"] = high[0]["code"] if high else None


def _to_view(request: Any) -> dict[str, Any] | None:
    """把任意受支持的请求表示转换为统一的 view，无法识别时返回 None。"""
    if isinstance(request, Mapping):
        if "framing" in request and "issues" in request and "headers" in request:
            return request  # 已经是 unified_parser / _analyze_message 的结果
        if "headers" in request:
            view = _view_from_headers(request.get("headers"))
            if view is None:
                return None
            if "body" in request:
                try:
                    view["body"] = _to_bytes(request["body"])
                except (ValueError, TypeError):
                    view["body"] = b""
                view["body_bytes"] = len(view["body"])
            return view
        return _view_from_headers(request)
    if isinstance(request, (bytes, bytearray, memoryview, str)):
        return unified_parser(request)
    if isinstance(request, (list, tuple)):
        return _view_from_headers(request)
    return None


# ---------------------------------------------------------------------------
# 1. 拒绝歧义请求
# ---------------------------------------------------------------------------


def reject_ambiguous(headers: Any, method: str = "POST") -> dict[str, Any]:
    """拒绝消息边界存在歧义的请求（CL+TE、重复 CL/TE、混淆头部等）。

    返回结构化裁决；无法解析的输入按拒绝处理（fail-closed）。
    """
    view = _to_view(headers)
    if view is None:
        return {
            "allowed": False,
            "ok": False,
            "status": 400,
            "reason": "invalid_input",
            "reasons": ["invalid_input"],
            "framing": None,
            "method": method if isinstance(method, str) else None,
            "headers": [],
        }

    reasons = sorted(
        {i["code"] for i in view["issues"] if i["severity"] in ("high", "medium")}
    )
    # 分块请求本身不歧义，但会被独立的 te_disable 策略拒绝。
    allowed = not reasons and view["framing"] not in {
        "ambiguous",
        "invalid-content-length",
        "invalid-transfer-encoding",
    }
    return {
        "allowed": allowed,
        "ok": allowed,
        "status": 200 if allowed else 400,
        "reason": reasons[0] if reasons else None,
        "reasons": reasons,
        "framing": view["framing"],
        "method": method if isinstance(method, str) else None,
        "headers": view["headers"],
    }


# ---------------------------------------------------------------------------
# 2. 统一解析器
# ---------------------------------------------------------------------------


def _parser_error(code: str, status: int, detail: str) -> dict[str, Any]:
    issue = _issue(code, "high", detail)
    return {
        "ok": False,
        "status": status,
        "error": code,
        "method": None,
        "target": None,
        "version": None,
        "headers": [],
        "header_map": {},
        "framing": None,
        "content_length": None,
        "transfer_encoding": None,
        "cl_values": [],
        "te_values": [],
        "body": b"",
        "body_bytes": 0,
        "extra_bytes": b"",
        "issues": [issue],
    }


def _decode_chunked(
    body: bytes,
) -> tuple[bytes, int, list[dict[str, str]]]:
    """严格解码 chunked 请求体。返回 (解码内容, 消耗字节, 问题列表)。"""
    out = bytearray()
    issues: list[dict[str, str]] = []
    pos = 0
    total = len(body)

    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            issues.append(
                _issue("chunked_truncated", "high", "missing chunk-size line terminator")
            )
            return bytes(out), pos, issues
        line = body[pos:line_end]
        if b";" in line:
            issues.append(
                _issue("chunked_extension", "high", "chunk extensions are not accepted")
            )
            return bytes(out), pos, issues
        if not line or len(line) > 16 or not _CHUNK_SIZE_RE.match(line):
            issues.append(_issue("chunked_invalid_size", "high", "invalid chunk size"))
            return bytes(out), pos, issues
        size = int(line, 16)
        pos = line_end + 2

        if size == 0:
            # 尾部字段（trailers）一直读到空行。
            while True:
                trailer_end = body.find(b"\r\n", pos)
                if trailer_end == -1:
                    issues.append(
                        _issue(
                            "chunked_truncated",
                            "high",
                            "missing trailer terminator",
                        )
                    )
                    return bytes(out), pos, issues
                trailer = body[pos:trailer_end]
                pos = trailer_end + 2
                if trailer == b"":
                    return bytes(out), pos, issues
                if b":" not in trailer:
                    issues.append(
                        _issue("chunked_invalid_trailer", "high", "invalid trailer field")
                    )
                    return bytes(out), pos, issues

        end = pos + size
        if end + 2 > total:
            issues.append(
                _issue("chunked_truncated", "high", "chunk data is truncated")
            )
            return bytes(out), pos, issues
        out.extend(body[pos:end])
        pos = end
        if body[pos : pos + 2] != b"\r\n":
            issues.append(
                _issue("chunked_missing_crlf", "high", "chunk not terminated by CRLF")
            )
            return bytes(out), pos, issues
        pos += 2


def unified_parser(
    raw: Any,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
    max_header_count: int = DEFAULT_MAX_HEADER_COUNT,
) -> dict[str, Any]:
    """用**同一套规则**解析原始 HTTP/1.x 请求，返回唯一的消息边界解释。

    严格拒绝可导致不同解析器产生分歧的构造：obs-fold、冒号前空白、
    裸 LF/CR、控制字符、重复/非法 CL、非规范 TE、CL 之外的多余字节等。
    """
    try:
        data = _to_bytes(raw)
    except (ValueError, TypeError):
        return _parser_error("invalid_input", 400, "raw request must be bytes or str")

    try:
        limit = int(max_header_bytes)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_HEADER_BYTES
    if limit <= 0:
        limit = DEFAULT_MAX_HEADER_BYTES

    text = data.decode("latin-1")
    sep = text.find("\r\n\r\n")
    sep_len = 4
    if sep == -1:
        sep = text.find("\n\n")
        sep_len = 2

    header_text = text if sep == -1 else text[:sep]
    body = b"" if sep == -1 else data[sep + sep_len :]

    if len(header_text.encode("latin-1", "replace")) > limit:
        return _parser_error(
            "header_too_large", 431, f"header block exceeds {limit} bytes"
        )

    # 统一按行切分，避免混用行尾造成前面解析偏差。
    lines = re.split(r"\r?\n", header_text)

    if not lines or lines[0] == "":
        return _parser_error("invalid_request_line", 400, "missing request line")

    start_line = lines[0]
    match = _REQUEST_LINE_RE.match(start_line)
    if not match:
        return _parser_error(
            "invalid_request_line",
            400,
            "request line must be 'METHOD SP target SP HTTP/x.y'",
        )
    method, target, version = match.groups()
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        return _parser_error(
            "unsupported_version", 505, f"unsupported HTTP version {version!r}"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return _parser_error("invalid_request_target", 400, "control character in target")

    # 保留原始行尾（CRLF/LF），交给头部解析器统一检测裸 LF/CR。
    first_newline = header_text.find("\n")
    rest = "" if first_newline == -1 else header_text[first_newline + 1 :]
    pairs, issues = _parse_raw_header_lines(rest, max_header_count)
    view = _analyze_message(pairs, issues)
    view["method"] = method
    view["target"] = target
    view["version"] = version
    view["body"] = b""
    view["body_bytes"] = 0
    view["extra_bytes"] = b""

    framing = view["framing"]
    if framing == "content-length" and view["content_length"] is not None:
        declared = view["content_length"]
        if len(body) < declared:
            view["issues"].append(
                _issue("incomplete_body", "high", "body shorter than Content-Length")
            )
        elif len(body) > declared:
            view["extra_bytes"] = body[declared:]
            view["body"] = body[:declared]
            view["issues"].append(
                _issue(
                    "extra_bytes_after_body",
                    "high",
                    "bytes remain after the declared Content-Length body",
                )
            )
        else:
            view["body"] = body
        view["body_bytes"] = len(view["body"])
    elif framing == "chunked" and view["transfer_encoding"] == ["chunked"]:
        decoded, consumed, chunk_issues = _decode_chunked(body)
        view["issues"].extend(chunk_issues)
        view["body"] = decoded
        view["body_bytes"] = len(decoded)
        remainder = body[consumed:]
        if remainder and not chunk_issues:
            view["extra_bytes"] = remainder
            view["issues"].append(
                _issue(
                    "extra_bytes_after_body",
                    "high",
                    "bytes remain after the final chunk",
                )
            )
    elif framing == "none":
        if body:
            view["extra_bytes"] = body
            view["issues"].append(
                _issue(
                    "body_without_framing",
                    "medium",
                    "body present without Content-Length or Transfer-Encoding",
                )
            )

    view["issues"] = _dedupe_issues(view["issues"])
    _finalize_view(view)
    return view


# ---------------------------------------------------------------------------
# 3. 头部长度限制
# ---------------------------------------------------------------------------


def header_length(
    headers: Any, max_bytes: int = DEFAULT_MAX_HEADER_BYTES
) -> dict[str, Any]:
    """限制请求头总字节数与字段数量（默认 8 KiB / 100 个字段）。"""
    try:
        limit = int(max_bytes)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_limit",
            "total_bytes": None,
            "limit": None,
            "count": None,
            "max_count": DEFAULT_MAX_HEADER_COUNT,
        }

    # 允许直接传入已知字节数。
    if isinstance(headers, int) and not isinstance(headers, bool):
        total = headers
        count = None
        parse_issues = []
    else:
        raw_size: int | None = None
        if isinstance(headers, (bytes, bytearray, memoryview, str)):
            try:
                raw_size = len(_to_bytes(headers))
            except (ValueError, TypeError):
                raw_size = None
            # 原始头部块先按字节数裁决，避免为超大头部分配解析结构。
            if raw_size is not None and raw_size > limit:
                return {
                    "ok": False,
                    "status": 431,
                    "reason": "header_too_large",
                    "total_bytes": raw_size,
                    "limit": limit,
                    "count": None,
                    "max_count": DEFAULT_MAX_HEADER_COUNT,
                }
        try:
            pairs, parse_issues = _coerce_header_pairs(headers)
        except (ValueError, TypeError):
            return {
                "ok": False,
                "status": 400,
                "reason": "invalid_input",
                "total_bytes": raw_size,
                "limit": limit,
                "count": None,
                "max_count": DEFAULT_MAX_HEADER_COUNT,
            }
        total = sum(
            len(name.encode("latin-1", "replace"))
            + 2  # ": "
            + len(value.encode("latin-1", "replace"))
            + 2  # CRLF
            for name, value in pairs
        )
        count = len(pairs)
        if raw_size is not None:
            total = raw_size

    # 无法严格解析的头部块本身就不安全，即使字节数未超限也要拒绝。
    malformed = [i["code"] for i in parse_issues if i["severity"] == "high"]
    too_large = total > limit
    too_many = count is not None and count > DEFAULT_MAX_HEADER_COUNT
    ok = not too_large and not too_many and not malformed
    reason = None
    if too_large:
        reason = "header_too_large"
    elif too_many:
        reason = "too_many_headers"
    elif malformed:
        reason = malformed[0]
    # 超过字节/数量限制属于 431；语法不可解析属于 400（请求本身非法）。
    if too_large or too_many:
        status = 431
    elif malformed:
        status = 400
    else:
        status = 200
    return {
        "ok": ok,
        "status": status,
        "reason": reason,
        "total_bytes": total,
        "limit": limit,
        "count": count,
        "max_count": DEFAULT_MAX_HEADER_COUNT,
    }


# ---------------------------------------------------------------------------
# 4. 禁用 Transfer-Encoding
# ---------------------------------------------------------------------------


def te_disable(headers: Any, reject: bool = True) -> dict[str, Any]:
    """按策略移除并拒绝 Transfer-Encoding。

    ``reject=True``（默认）表示任何带 TE 的请求都被拒绝；返回的
    ``headers`` 是已剔除 TE 的安全头部副本，供需要继续处理时使用。
    """
    view = _to_view(headers)
    if view is None:
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_input",
            "removed": [],
            "headers": [],
            "transfer_encoding_disabled": True,
        }

    removed = [value for name, value in view["headers"] if name == "transfer-encoding"]
    sanitized = [
        {"name": name, "value": value}
        for name, value in view["headers"]
        if name != "transfer-encoding"
    ]
    present = bool(removed)
    allowed = not present or not reject
    reason = None
    if present and reject:
        reason = "transfer_encoding_not_allowed"
    return {
        "ok": allowed,
        "status": 200 if allowed else 400,
        "reason": reason,
        "removed": removed,
        "headers": sanitized,
        "transfer_encoding_disabled": True,
    }


# ---------------------------------------------------------------------------
# 5. Content-Length 校验
# ---------------------------------------------------------------------------


def cl_check(
    headers: Any, max_bytes: int = DEFAULT_MAX_BODY_BYTES
) -> dict[str, Any]:
    """校验 Content-Length：至多一个、纯十进制、无符号/列表、在大小限制内。"""
    view = _to_view(headers)
    if view is None:
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_input",
            "content_length": None,
            "values": [],
            "limit": max_bytes,
        }

    try:
        limit = int(max_bytes)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_BODY_BYTES

    values = view["cl_values"]
    if not values:
        return {
            "ok": True,
            "status": 200,
            "reason": None,
            "content_length": None,
            "values": [],
            "limit": limit,
        }
    if len(values) > 1:
        return {
            "ok": False,
            "status": 400,
            "reason": "duplicate_content_length",
            "content_length": None,
            "values": values,
            "limit": limit,
        }
    parsed, error = _parse_content_length(values[0])
    if error:
        return {
            "ok": False,
            "status": 400,
            "reason": error,
            "content_length": None,
            "values": values,
            "limit": limit,
        }
    if parsed is not None and limit >= 0 and parsed > limit:
        return {
            "ok": False,
            "status": 413,
            "reason": "body_too_large",
            "content_length": parsed,
            "values": values,
            "limit": limit,
        }
    return {
        "ok": True,
        "status": 200,
        "reason": None,
        "content_length": parsed,
        "values": values,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# 6. 走私特征检测
# ---------------------------------------------------------------------------


_SMUGGLING_CODES = {
    "both_cl_and_te",
    "duplicate_content_length",
    "duplicate_transfer_encoding",
    "content_length_list",
    "invalid_content_length",
    "invalid_transfer_encoding",
    "unsupported_transfer_encoding",
    "chunked_not_last",
    "duplicate_chunked_coding",
    "whitespace_before_colon",
    "whitespace_in_header_name",
    "invalid_header_name",
    "obs_fold",
    "bare_lf",
    "bare_cr",
    "control_char",
    "malformed_header",
    "too_many_headers",
    "chunked_extension",
    "chunked_invalid_size",
    "chunked_missing_crlf",
    "chunked_invalid_trailer",
    "chunked_truncated",
    "extra_bytes_after_body",
    "body_without_framing",
    "incomplete_body",
    "header_too_large",
}


def smuggling_detect(request: Any, options: Any = None) -> dict[str, Any]:
    """检测请求中的走私特征，返回指标、严重级别与处置建议。"""
    view = _to_view(request)
    if view is None:
        indicators = [
            _issue(
                "unparseable_request",
                "high",
                "request cannot be parsed by the unified parser",
            )
        ]
        return {
            "detected": True,
            "ok": False,
            "status": 400,
            "severity": "high",
            "indicators": indicators,
            "recommendation": "reject",
            "framing": None,
        }

    indicators: list[dict[str, str]] = []
    for issue in view["issues"]:
        if issue["code"] in _SMUGGLING_CODES:
            indicators.append(issue)

    framing = view.get("framing")
    if framing in ("ambiguous", "invalid-content-length", "invalid-transfer-encoding"):
        indicators.append(
            _issue(
                "ambiguous_framing",
                "high",
                f"message framing is {framing!r}",
            )
        )
    if view.get("extra_bytes"):
        indicators.append(
            _issue(
                "extra_bytes_after_body",
                "high",
                "data follows the end of the framed body",
            )
        )

    indicators = _dedupe_issues(indicators)
    severity = _max_severity(indicators)
    detected = bool(indicators) and severity in ("medium", "high")
    if detected:
        status = 400
        if any(i["code"] == "header_too_large" for i in indicators):
            status = 431
        elif any(i["code"] == "body_too_large" for i in indicators):
            status = 413
    else:
        status = 200
    return {
        "detected": detected,
        "ok": not detected,
        "status": status,
        "severity": severity,
        "indicators": indicators,
        "recommendation": "reject" if detected else "allow",
        "framing": framing,
    }


# ---------------------------------------------------------------------------
# 7. 前后端一致性
# ---------------------------------------------------------------------------


def proxy_consistency(front: Any, back: Any = None) -> dict[str, Any]:
    """比较前置代理与后端对同一请求的消息边界解释是否一致。

    任一视角无法解析、或 framing / 长度 / 编码集合不同，都判定为不一致。
    """
    front_view = _to_view(front)
    back_view = _to_view(back) if back is not None else None

    if front_view is None or back_view is None:
        return {
            "consistent": False,
            "ok": False,
            "status": 400,
            "reason": "unparseable_view",
            "differences": [
                {
                    "field": "view",
                    "front": front_view is not None,
                    "back": back_view is not None,
                }
            ],
            "front_framing": None if front_view is None else front_view.get("framing"),
            "back_framing": None if back_view is None else back_view.get("framing"),
        }

    differences: list[dict[str, Any]] = []
    fields = (
        ("framing", front_view.get("framing"), back_view.get("framing")),
        (
            "content_length",
            front_view.get("content_length"),
            back_view.get("content_length"),
        ),
        (
            "transfer_encoding",
            front_view.get("transfer_encoding"),
            back_view.get("transfer_encoding"),
        ),
        (
            "cl_count",
            len(front_view.get("cl_values", [])),
            len(back_view.get("cl_values", [])),
        ),
        (
            "te_count",
            len(front_view.get("te_values", [])),
            len(back_view.get("te_values", [])),
        ),
    )
    for field, left, right in fields:
        if left != right:
            differences.append({"field": field, "front": left, "back": right})

    for side, view in (("front", front_view), ("back", back_view)):
        for issue in view["issues"]:
            if issue["severity"] == "high":
                differences.append(
                    {
                        "field": f"{side}_error",
                        "front": issue["code"] if side == "front" else None,
                        "back": issue["code"] if side == "back" else None,
                    }
                )

    consistent = not differences
    return {
        "consistent": consistent,
        "ok": consistent,
        "status": 200 if consistent else 400,
        "reason": None if consistent else "proxy_parser_mismatch",
        "differences": differences,
        "front_framing": front_view.get("framing"),
        "back_framing": back_view.get("framing"),
    }


# ---------------------------------------------------------------------------
# 8. 综合校验
# ---------------------------------------------------------------------------


def validation(request: Any, options: Any = None) -> dict[str, Any]:
    """依次执行长度、歧义、CL、TE、走私检测，输出单一裁决。"""
    settings = options if isinstance(options, Mapping) else {}
    max_header_bytes = settings.get("max_header_bytes", DEFAULT_MAX_HEADER_BYTES)
    max_body_bytes = settings.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    allow_transfer_encoding = bool(settings.get("allow_transfer_encoding", False))

    view = _to_view(request)
    if view is None:
        return {
            "ok": False,
            "status": 400,
            "decision": "reject",
            "reason": "invalid_input",
            "checks": {},
            "errors": ["invalid_input"],
        }

    header_check = header_length(view["headers"], max_header_bytes)
    ambiguity_check = reject_ambiguous(view)
    cl_result = cl_check(view, max_body_bytes)
    te_result = te_disable(view, reject=not allow_transfer_encoding)
    body_result = body_limit(
        view["content_length"]
        if view["content_length"] is not None
        else len(view.get("body") or b""),
        max_body_bytes,
    )
    detection = smuggling_detect(view)

    checks = {
        "header_length": header_check,
        "reject_ambiguous": ambiguity_check,
        "cl_check": cl_result,
        "te_disable": te_result,
        "body_limit": body_result,
        "smuggling_detect": detection,
    }
    errors: list[str] = []
    for name, result in checks.items():
        if not result.get("ok", False):
            errors.append(f"{name}:{result.get('reason') or result.get('error') or 'failed'}")
    for issue in view["issues"]:
        if issue["severity"] == "high":
            errors.append(issue["code"])
    errors = sorted(set(errors))

    if header_check.get("status") == 431:
        status = 431
    elif "body_too_large" in errors or body_result.get("status") == 413:
        status = 413
    else:
        status = 400
    ok = not errors
    return {
        "ok": ok,
        "status": 200 if ok else status,
        "decision": "allow" if ok else "reject",
        "reason": None if ok else errors[0],
        "checks": checks,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# 9. 审计
# ---------------------------------------------------------------------------


_AUDIT_LOG: list[dict[str, Any]] = []
_AUDIT_LIMIT = 1000


def _fingerprint(view: Mapping[str, Any], raw: Any) -> str:
    parts: list[str] = []
    method = view.get("method") or ""
    target = view.get("target") or ""
    parts.append(f"{method} {target}")
    for name, value in view.get("headers", []):
        # 只对字段名与长度做指纹，避免把敏感头部值写入日志。
        parts.append(f"{name}:{len(str(value))}")
    if not parts or parts == [" "]:
        seed = repr(raw)[:512]
        parts = [seed]
    return hashlib.sha256("\n".join(parts).encode("latin-1", "replace")).hexdigest()


def audit(request: Any, verdict: Any = None) -> dict[str, Any]:
    """生成一条不含敏感值的结构化审计记录（进程内保留最近 1000 条）。"""
    view = _to_view(request)
    if isinstance(verdict, Mapping):
        decision = verdict.get("decision") or verdict.get("action")
        status = verdict.get("status")
    elif isinstance(verdict, str):
        decision = verdict
        status = None
    else:
        decision = None
        status = None

    if decision not in ("allow", "reject", "log"):
        if view is None:
            decision = "reject"
        else:
            decision = validation(view)["decision"]
    if status is None:
        status = 400 if decision == "reject" else 200
    status = _valid_status(status, 400 if decision == "reject" else 200)

    indicators: list[str] = []
    if view is None:
        fingerprint = hashlib.sha256(repr(request)[:512].encode("utf-8", "replace")).hexdigest()
    else:
        fingerprint = _fingerprint(view, request)
        indicators = sorted({i["code"] for i in view["issues"]})

    record = {
        "event": "http_smuggling_audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint,
        "method": None if view is None else view.get("method"),
        "target": None if view is None else view.get("target"),
        "framing": None if view is None else view.get("framing"),
        "header_names": [] if view is None else [name for name, _ in view["headers"]],
        "decision": decision,
        "status": status,
        "indicators": indicators,
    }
    _AUDIT_LOG.append(record)
    if len(_AUDIT_LOG) > _AUDIT_LIMIT:
        del _AUDIT_LOG[: len(_AUDIT_LOG) - _AUDIT_LIMIT]
    return record


# ---------------------------------------------------------------------------
# 10. 错误映射
# ---------------------------------------------------------------------------

_ERROR_STATUS: dict[str, dict[str, Any]] = {
    "invalid_input": {"status": 400, "message": "Malformed request"},
    "invalid_request_line": {"status": 400, "message": "Malformed request line"},
    "invalid_request_target": {"status": 400, "message": "Malformed request target"},
    "unsupported_version": {"status": 505, "message": "HTTP version not supported"},
    "both_cl_and_te": {
        "status": 400,
        "message": "Content-Length and Transfer-Encoding are mutually exclusive",
    },
    "duplicate_content_length": {"status": 400, "message": "Duplicate Content-Length"},
    "duplicate_transfer_encoding": {
        "status": 400,
        "message": "Duplicate Transfer-Encoding",
    },
    "content_length_list": {"status": 400, "message": "Content-Length must be a single value"},
    "invalid_content_length": {"status": 400, "message": "Invalid Content-Length"},
    "invalid_transfer_encoding": {"status": 400, "message": "Invalid Transfer-Encoding"},
    "unsupported_transfer_encoding": {
        "status": 501,
        "message": "Unsupported transfer coding",
    },
    "transfer_encoding_not_allowed": {
        "status": 400,
        "message": "Transfer-Encoding is not allowed",
    },
    "whitespace_before_colon": {"status": 400, "message": "Ambiguous header syntax"},
    "whitespace_in_header_name": {"status": 400, "message": "Ambiguous header name"},
    "invalid_header_name": {"status": 400, "message": "Invalid header name"},
    "obs_fold": {"status": 400, "message": "Obsolete line folding is not allowed"},
    "bare_lf": {"status": 400, "message": "Bare LF line endings are not allowed"},
    "bare_cr": {"status": 400, "message": "Bare CR line endings are not allowed"},
    "control_char": {"status": 400, "message": "Control character in header"},
    "malformed_header": {"status": 400, "message": "Malformed header field"},
    "header_too_large": {"status": 431, "message": "Request header fields too large"},
    "too_many_headers": {"status": 431, "message": "Too many header fields"},
    "body_too_large": {"status": 413, "message": "Request body too large"},
    "extra_bytes_after_body": {
        "status": 400,
        "message": "Data after the framed request body",
    },
    "body_without_framing": {"status": 400, "message": "Body without message framing"},
    "incomplete_body": {"status": 400, "message": "Incomplete request body"},
    "ambiguous_framing": {"status": 400, "message": "Ambiguous message framing"},
    "proxy_parser_mismatch": {
        "status": 400,
        "message": "Proxy and backend disagree on message framing",
    },
    "rate_limited": {"status": 429, "message": "Too many requests"},
    "unparseable_request": {"status": 400, "message": "Unparseable request"},
}


def error_map(code: Any = None, default_status: int = 500) -> dict[str, Any]:
    """把内部错误码映射为 HTTP 状态与安全文案。

    ``code=None`` 时返回完整的错误码表。
    """
    if code is None:
        return {
            "code": None,
            "status": None,
            "message": None,
            "errors": {key: dict(value) for key, value in _ERROR_STATUS.items()},
        }

    key = str(code).lower().strip()
    entry = _ERROR_STATUS.get(key)
    if entry is not None:
        return {
            "code": key,
            "status": entry["status"],
            "message": entry["message"],
        }
    fallback_status = _valid_status(default_status, 500)
    return {
        "code": key,
        "status": fallback_status,
        "message": "Unknown error",
    }


# ---------------------------------------------------------------------------
# 11. 限流
# ---------------------------------------------------------------------------

_RATE_BUCKETS: dict[str, list[float]] = {}
_RATE_LOCK = threading.Lock()
_RATE_MAX_BUCKETS = 10000


def rate_limit(
    key: Any,
    limit: int = DEFAULT_RATE_LIMIT,
    window: float = DEFAULT_RATE_WINDOW,
    now: float | None = None,
) -> dict[str, Any]:
    """进程内固定窗口限流，作为走私攻击的纵深防御。"""
    try:
        max_requests = int(limit)
        seconds = float(window)
    except (TypeError, ValueError):
        return {
            "allowed": False,
            "ok": False,
            "status": 400,
            "reason": "invalid_arguments",
            "limit": None,
            "remaining": 0,
            "retry_after": None,
        }
    if max_requests < 1 or seconds <= 0:
        return {
            "allowed": False,
            "ok": False,
            "status": 400,
            "reason": "invalid_arguments",
            "limit": max_requests,
            "remaining": 0,
            "retry_after": None,
        }

    stamp = time.monotonic() if now is None else float(now)
    bucket_key = str(key)
    with _RATE_LOCK:
        if bucket_key not in _RATE_BUCKETS and len(_RATE_BUCKETS) >= _RATE_MAX_BUCKETS:
            # 简单淘汰：清掉最旧的桶，防止内存无限增长。
            _RATE_BUCKETS.pop(next(iter(_RATE_BUCKETS)), None)
        timestamps = [
            ts for ts in _RATE_BUCKETS.get(bucket_key, []) if ts > stamp - seconds
        ]
        allowed = len(timestamps) < max_requests
        if allowed:
            timestamps.append(stamp)
        _RATE_BUCKETS[bucket_key] = timestamps
        remaining = max(0, max_requests - len(timestamps))
        retry_after = 0.0
        if not allowed and timestamps:
            retry_after = max(0.0, seconds - (stamp - min(timestamps)))

    return {
        "allowed": allowed,
        "ok": allowed,
        "status": 200 if allowed else 429,
        "reason": None if allowed else "rate_limited",
        "key": bucket_key,
        "limit": max_requests,
        "remaining": remaining,
        "window": seconds,
        "retry_after": round(retry_after, 3),
    }


# ---------------------------------------------------------------------------
# 12. 结构化日志
# ---------------------------------------------------------------------------

_LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "warn": 30,
    "error": 40,
    "critical": 50,
}
_LEVEL_BY_VALUE = {value: name for name, value in _LEVELS.items() if name != "warn"}


def logging(record: Any, level: Any = "info") -> dict[str, Any]:
    """构造结构化日志条目（默认不产生写盘/输出副作用）。"""
    if isinstance(level, str) and level.lower() in _LEVELS:
        level_name = "warning" if level.lower() == "warn" else level.lower()
    elif isinstance(level, int) and not isinstance(level, bool):
        level_name = _LEVEL_BY_VALUE.get(level, "info")
    else:
        level_name = "info"

    if isinstance(record, Mapping):
        message = str(
            record.get("message")
            or record.get("event")
            or "http_smuggling event"
        )
        fields: Any = dict(record)
    else:
        message = str(record) if record is not None else "http_smuggling event"
        fields = {"value": record}

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level_name,
        "logger": "security.http_smuggling",
        "message": message,
        "fields": fields,
    }


# ---------------------------------------------------------------------------
# 13. 失败关闭（fallback）
# ---------------------------------------------------------------------------


def fallback(decision: Any, status: Any = 400) -> dict[str, Any]:
    """在无法确定安全性时默认拒绝；仅显式“干净”的结果才放行。"""
    reject_status = _valid_status(status, 400)
    allow = False
    reason = "uncertain_decision_rejected"

    if isinstance(decision, bool):
        allow = decision
        reason = None if allow else "explicit_reject"
    elif isinstance(decision, str):
        allow = decision.lower() in {"allow", "ok", "clean", "accept"}
        reason = None if allow else "explicit_reject"
    elif isinstance(decision, Mapping):
        detected = bool(decision.get("detected"))
        ok = decision.get("ok") is True
        status_value = decision.get("status")
        clean_status = status_value in (None, 200)
        if ok and not detected and clean_status:
            allow = True
            reason = None
        else:
            reason = str(
                decision.get("reason")
                or decision.get("error")
                or "unclean_decision_rejected"
            )

    return {
        "action": "allow" if allow else "reject",
        "ok": allow,
        "status": 200 if allow else reject_status,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# 14. 请求体大小限制
# ---------------------------------------------------------------------------


def body_limit(length: Any, max_bytes: Any = DEFAULT_MAX_BODY_BYTES) -> dict[str, Any]:
    """限制请求体字节数，超过限制返回 413。"""
    try:
        limit = int(max_bytes)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_limit",
            "length": None,
            "limit": None,
        }
    if limit < 0:
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_limit",
            "length": length,
            "limit": limit,
        }

    if isinstance(length, bool) or length is None:
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_length",
            "length": length,
            "limit": limit,
        }
    if isinstance(length, str):
        text = length.strip()
        if not _CONTENT_LENGTH_RE.match(text):
            return {
                "ok": False,
                "status": 400,
                "reason": "invalid_length",
                "length": length,
                "limit": limit,
            }
        parsed = int(text)
    else:
        try:
            parsed = int(length)
        except (TypeError, ValueError):
            return {
                "ok": False,
                "status": 400,
                "reason": "invalid_length",
                "length": length,
                "limit": limit,
            }
        if parsed != length:
            return {
                "ok": False,
                "status": 400,
                "reason": "invalid_length",
                "length": length,
                "limit": limit,
            }

    if parsed < 0:
        return {
            "ok": False,
            "status": 400,
            "reason": "invalid_length",
            "length": parsed,
            "limit": limit,
        }
    if parsed > limit:
        return {
            "ok": False,
            "status": 413,
            "reason": "body_too_large",
            "length": parsed,
            "limit": limit,
        }
    return {
        "ok": True,
        "status": 200,
        "reason": None,
        "length": parsed,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# 15. 测试向量
# ---------------------------------------------------------------------------


def test_vectors(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """返回一组经典 HTTP 请求走私测试向量（原始报文 + 期望指标）。"""
    request_line = "POST / HTTP/1.1\r\nHost: example.test\r\n"
    return [
        {
            "name": "cl_te_conflict",
            "description": "CL.TE: front uses Content-Length, back uses chunked",
            "raw": request_line
            + "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "expected": ["both_cl_and_te"],
        },
        {
            "name": "te_cl_conflict",
            "description": "TE.CL: front uses chunked, back uses Content-Length",
            "raw": request_line
            + "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\n\r\n0\r\n\r\n",
            "expected": ["both_cl_and_te"],
        },
        {
            "name": "duplicate_content_length",
            "description": "Two Content-Length fields with different values",
            "raw": request_line
            + "Content-Length: 5\r\nContent-Length: 6\r\n\r\nAAAAA",
            "expected": ["duplicate_content_length"],
        },
        {
            "name": "duplicate_transfer_encoding",
            "description": "Transfer-Encoding obfuscation with two fields",
            "raw": request_line
            + "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n",
            "expected": ["duplicate_transfer_encoding"],
        },
        {
            "name": "space_before_colon",
            "description": "Whitespace between header name and colon",
            "raw": request_line + "Content-Length : 5\r\n\r\nAAAAA",
            "expected": ["whitespace_before_colon"],
        },
        {
            "name": "obs_fold",
            "description": "Obsolete line folding inside Transfer-Encoding",
            "raw": request_line
            + "Transfer-Encoding: chunked\r\n\t, chunked\r\n\r\n0\r\n\r\n",
            "expected": ["obs_fold"],
        },
        {
            "name": "bare_lf",
            "description": "Header block terminated with bare LF (parser split)",
            "raw": "POST / HTTP/1.1\nHost: example.test\nContent-Length: 5\n\nAAAAA",
            "expected": ["bare_lf"],
        },
        {
            "name": "unsupported_transfer_encoding",
            "description": "Non-standard transfer coding",
            "raw": request_line + "Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
            "expected": ["unsupported_transfer_encoding"],
        },
        {
            "name": "content_length_list",
            "description": "Comma-separated Content-Length values",
            "raw": request_line + "Content-Length: 5, 5\r\n\r\nAAAAA",
            "expected": ["content_length_list"],
        },
        {
            "name": "extra_bytes_after_body",
            "description": "Smuggled request appended after the declared body",
            "raw": request_line
            + "Content-Length: 5\r\n\r\nAAAAAGET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n",
            "expected": ["extra_bytes_after_body"],
        },
        {
            "name": "body_without_framing",
            "description": "Body present but no framing header",
            "raw": request_line + "\r\nGET /admin HTTP/1.1\r\n\r\n",
            "expected": ["body_without_framing"],
        },
        {
            "name": "chunked_extension",
            "description": "Chunk extensions may be ignored by one parser",
            "raw": request_line
            + "Transfer-Encoding: chunked\r\n\r\n5;ext=1\r\nAAAAA\r\n0\r\n\r\n",
            "expected": ["chunked_extension"],
        },
    ]
