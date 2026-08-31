# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
xspct_scan_client — command-line client for the xspct_scan HTTP API.

Usage::

    xspct_scan_client [options] FILE [FILE ...]

Options::

    -C, --capabilities        Fetch GET /v1/capabilities and show the active
                              analyzer/MIME overview
    -c, --config PATH         YAML config file providing defaults for the
                              options below (default: $XSPCT_SCAN_CLIENT_CONFIG,
                              ~/.config/xspct_scan/client.yml, or
                              /etc/xspct_scan/client.yml, first match wins)
    -u, --url URL             Base URL of the daemon (default:
                              http://localhost:8080)
    -a, --api-key KEY         X-Api-Key header value for authenticated daemons
    -t, --timeout SECS        Analysis timeout in seconds passed to the daemon
                              (default: 30)
    -p, --passwords LIST      Comma-separated passwords to try for encrypted files
    -f, --force-analyzers LIST  Comma-separated analyzer paths to bypass
                              exclusion gates for this request (e.g. image.ocr)
    -F, --force-ocr           Shortcut for --force-analyzers image.ocr
    -R, --invalidate-cache    Delete the daemon's cached report and force a
                              full rescan
    -L, --legacy-multipart    Use the legacy "doc" multipart field instead of
                              the structured "metadata" + "file" shape (default)
    -r, --rspamd-uid ID       rspamd_uid to place in the metadata part
    -Q, --queue-id ID         queue_id to place in the metadata part
    -m, --message-id ID       message_id to place in the metadata part
    -P, --poll                Poll /v1/query after a 202 response until the
                              result is ready
    -I, --poll-interval SECS  Seconds between poll attempts (default: 2)
    -q, --query HASH          Look up a report by SHA-256 hash via GET /v1/query
                              instead of submitting a file (no re-upload needed
                              for a scan still processing in the background)
    -j, --json                Output raw JSON instead of a human-readable summary
    -o, --output FILE         Write JSON result(s) to FILE (single result or
                              JSON array)
    -n, --no-color            Disable rich/colour output
    -i, --insecure            Skip TLS certificate verification

Each boolean above has a counterpart that overrides a config-file default for
a single invocation: --use-cache, --structured-multipart, --no-poll, --no-json,
--color, and --secure.

Config-file keys match the long flag names with dashes replaced by
underscores (url, api_key, timeout, ...). Unknown keys are ignored with a
warning. The mode selectors --capabilities, --query and FILE arguments are
command-line only.

By default the client uploads via the structured "metadata" + "file"
multipart shape (see docs/guide/api-http.md); --legacy-multipart switches
back to the plain "doc" field for talking to older daemons.

CLI flags always take precedence over the config file, which in turn
takes precedence over built-in defaults.
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any

import aiohttp
import yaml

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel

    _console = Console()
    _err_console = Console(stderr=True)
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    _console = None  # type: ignore[assignment]
    _err_console = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _normalize_result_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize daemon responses to the flat scan-report shape.

    ``POST /v1/scan`` returns the report directly, while ``GET /v1/query``
    wraps finished results as ``{"status": "finished", "report": {...}}``.
    The CLI formatters expect the flat report shape in both cases.
    """
    report = payload.get("report")
    if isinstance(report, dict):
        normalized = dict(report)
        if "status" in payload and "status" not in normalized:
            normalized["status"] = payload["status"]
        return normalized
    return payload


def _collect_iocs(result: dict[str, Any]) -> list[str]:
    """Collect all IOC values from a v2 report's iocs section."""
    seen: dict[str, None] = {}
    iocs = result.get("iocs") or {}
    for entries in iocs.values():
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    # v2: {value, source, confidence}
                    val = entry.get("value")
                    if val:
                        seen[str(val)] = None
                elif entry:
                    seen[str(entry)] = None
    return list(seen)


def _format_plain(result: dict[str, Any], filename: str) -> str:
    _file = result.get("file") or {}
    _scan = result.get("scan") or {}
    _flags_v2 = result.get("flags") or {}
    lines: list[str] = []
    lines.append(f"File:     {_file.get('name', result.get('filename', filename))}")
    lines.append(f"Hash:     {_file.get('sha256', result.get('file_hash', '-'))}")
    lines.append(
        f"Type:     {_file.get('type', result.get('detected_type', '-'))}"
        f"  ({_file.get('magic', result.get('file_description', '-'))})"
    )
    lines.append(
        f"Status:   {result.get('status', '-')}  ({_scan.get('duration_s', result.get('time_taken', '-'))} s)"
    )

    flags: list[str] = []
    if _flags_v2.get("macros", result.get("has_macro")):
        flags.append("macro")
    if _flags_v2.get("encrypted", result.get("is_encrypted")):
        flags.append("encrypted")
    if _flags_v2.get("javascript", result.get("has_javascript")):
        flags.append("javascript")
    if _flags_v2.get("decrypted", result.get("decrypted")):
        _pw = _flags_v2.get("decryption_password") or result.get(
            "decryption_password", "?"
        )
        flags.append(f"decrypted(pw={_pw})")
    if flags:
        lines.append(f"Flags:    {', '.join(flags)}")

    analyses = result.get("findings") or result.get("analyses") or []
    if analyses:
        lines.append(f"Analyses ({len(analyses)}):")
        for a in analyses[:10]:
            lines.append(
                f"  [{a.get('type', '')}] {a.get('keyword', '')} — {a.get('description', '')}"
            )
        if len(analyses) > 10:
            lines.append(f"  … {len(analyses) - 10} more")

    all_iocs = _collect_iocs(result)
    if all_iocs:
        lines.append(f"IOCs ({len(all_iocs)}):")
        for ioc in all_iocs[:20]:
            lines.append(f"  {ioc}")
        if len(all_iocs) > 20:
            lines.append(f"  … {len(all_iocs) - 20} more")

    yara = (
        (result.get("engines") or {}).get("yara", {}).get("matches")
        or result.get("yara_matches")
        or []
    )
    if yara:
        names = ", ".join(m.get("rule", "?") for m in yara[:6])
        suffix = f" … +{len(yara) - 6}" if len(yara) > 6 else ""
        lines.append(f"YARA ({len(yara)}): {names}{suffix}")

    archive = (
        (result.get("engines") or {}).get("archive", {}).get("files")
        or result.get("archive_files")
        or []
    )
    if archive:
        names = ", ".join(f.get("name", "?") for f in archive[:6])
        suffix = f" … +{len(archive) - 6}" if len(archive) > 6 else ""
        lines.append(f"Archive ({len(archive)}): {names}{suffix}")

    return "\n".join(lines)


def _format_rich(result: dict[str, Any], filename: str) -> None:
    from rich.table import Table  # noqa: PLC0415 — local import to avoid hard dep

    _file = result.get("file") or {}
    _scan = result.get("scan") or {}
    _flags_v2 = result.get("flags") or {}
    title = _file.get("name") or result.get("filename") or filename
    status = result.get("status", "-")
    border_color = "green" if status == "finished" else "yellow"

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tbl.add_column("Key", style="bold cyan", no_wrap=True)
    tbl.add_column("Value")

    tbl.add_row("Hash", _file.get("sha256") or result.get("file_hash", "-"))
    tbl.add_row(
        "Type",
        f"{_file.get('type', result.get('detected_type', '-'))}  ({_file.get('magic', result.get('file_description', '-'))})",
    )
    tbl.add_row(
        "Status",
        f"[{border_color}]{status}[/{border_color}]  ({_scan.get('duration_s', result.get('time_taken', '-'))} s)",
    )

    flags: list[str] = []
    if _flags_v2.get("macros", result.get("has_macro")):
        flags.append("[red]macro[/red]")
    if _flags_v2.get("encrypted", result.get("is_encrypted")):
        flags.append("[yellow]encrypted[/yellow]")
    if _flags_v2.get("javascript", result.get("has_javascript")):
        flags.append("[yellow]javascript[/yellow]")
    if _flags_v2.get("decrypted", result.get("decrypted")):
        _pw = _flags_v2.get("decryption_password") or result.get(
            "decryption_password", "?"
        )
        flags.append(f"[green]decrypted(pw={_pw})[/green]")
    if flags:
        tbl.add_row("Flags", "  ".join(flags))

    analyses = result.get("findings") or result.get("analyses") or []
    if analyses:
        tbl.add_row("Findings", f"[red]{len(analyses)}[/red]")
        for a in analyses[:8]:
            tbl.add_row(
                "",
                f"  [{a.get('type', '')}] {a.get('keyword', '')} — {a.get('description', '')}",
            )
        if len(analyses) > 8:
            tbl.add_row("", f"  … {len(analyses) - 8} more")

    all_iocs = _collect_iocs(result)
    if all_iocs:
        tbl.add_row("IOCs", f"[red]{len(all_iocs)}[/red]")
        for ioc in all_iocs[:15]:
            tbl.add_row("", f"  [red]{ioc}[/red]")
        if len(all_iocs) > 15:
            tbl.add_row("", f"  … {len(all_iocs) - 15} more")

    yara = (
        (result.get("engines") or {}).get("yara", {}).get("matches")
        or result.get("yara_matches")
        or []
    )
    if yara:
        names = ", ".join(m.get("rule", "?") for m in yara[:6])
        suffix = f" … +{len(yara) - 6}" if len(yara) > 6 else ""
        tbl.add_row("YARA", f"[red]{len(yara)}[/red]: {names}{suffix}")

    archive = (
        (result.get("engines") or {}).get("archive", {}).get("files")
        or result.get("archive_files")
        or []
    )
    if archive:
        names = ", ".join(f.get("name", "?") for f in archive[:6])
        suffix = f" … +{len(archive) - 6}" if len(archive) > 6 else ""
        tbl.add_row("Archive", f"{len(archive)}: {names}{suffix}")

    _console.print(Panel(tbl, title=f"[bold]{title}[/bold]", border_style=border_color))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _poll_result(
    session: aiohttp.ClientSession,
    base_url: str,
    file_hash: str,
    headers: dict[str, str],
    interval: float,
    max_attempts: int = 120,
) -> dict[str, Any] | None:
    for _ in range(max_attempts):
        await asyncio.sleep(interval)
        try:
            async with session.get(
                f"{base_url}/v1/query",
                params={"hash": file_hash},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    body = await resp.json(content_type=None)
                    if not isinstance(body, dict):
                        _print_error(
                            f"{base_url}/v1/query returned a "
                            f"{type(body).__name__}, expected a JSON object"
                        )
                        return None
                    # /v1/query answers 200 for an in-flight scan too, with
                    # status "processing" and a partial report. Only a
                    # terminal status ends the loop — returning on the bare
                    # 200 would hand back an unfinished report as the result.
                    if body.get("status") != "processing":
                        return _normalize_result_payload(body)
                # 404 → not found yet; keep polling
        except aiohttp.ClientError:
            pass
    # Deliberately no partial result here: an unfinished report must not be
    # mistaken for a verdict, so the caller reports failure instead.
    _print_error(
        f"Polling timed out for hash {file_hash} — the scan is still running. "
        "Query the hash again later, or raise --poll-interval."
    )
    return None


async def scan_file(
    session: aiohttp.ClientSession,
    path: Path,
    base_url: str,
    timeout: int,
    passwords: str | None,
    api_key: str | None,
    poll: bool,
    poll_interval: float,
    no_color: bool,
    force_analyzers: str | None = None,
    invalidate_cache: bool = False,
    legacy_multipart: bool = False,
    rspamd_uid: str | None = None,
    queue_id: str | None = None,
    message_id: str | None = None,
) -> dict[str, Any] | None:
    """POST *path* to /v1/scan. Returns the result dict or None on error.

    By default this uses the structured ``metadata`` + ``file`` multipart
    shape; pass ``legacy_multipart=True`` to fall back to the plain ``doc``
    field for talking to older daemons.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["X-Api-Key"] = api_key

    params: dict[str, str] = {"timeout": str(timeout)}
    if invalidate_cache:
        params["invalidate_cache"] = "true"

    try:
        with path.open("rb") as fh:
            form = aiohttp.FormData()
            if legacy_multipart:
                form.add_field(
                    "doc",
                    fh,
                    filename=path.name,
                    content_type="application/octet-stream",
                )
                if passwords:
                    form.add_field("passwords", passwords)
                if force_analyzers:
                    params["force_analyzers"] = force_analyzers
            else:
                metadata: dict[str, Any] = {"filename": path.name}
                if passwords:
                    metadata["passwords"] = [
                        p.strip() for p in passwords.split(",") if p.strip()
                    ]
                if force_analyzers:
                    metadata["force_analyzers"] = [
                        a.strip() for a in force_analyzers.split(",") if a.strip()
                    ]
                if invalidate_cache:
                    metadata["invalidate_cache"] = True
                if rspamd_uid:
                    metadata["rspamd_uid"] = rspamd_uid
                if queue_id:
                    metadata["queue_id"] = queue_id
                if message_id:
                    metadata["message_id"] = message_id
                form.add_field(
                    "metadata", json.dumps(metadata), content_type="application/json"
                )
                form.add_field(
                    "file",
                    fh,
                    filename=path.name,
                    content_type="application/octet-stream",
                )
            async with session.post(
                f"{base_url}/v1/scan",
                data=form,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=timeout + 60),
            ) as resp:
                body: dict[str, Any] = await resp.json(content_type=None)
                http_status = resp.status

    except aiohttp.ClientConnectorError as exc:
        _print_error(f"Cannot connect to {base_url}: {exc}")
        return None
    except aiohttp.ClientError as exc:
        _print_error(f"{path.name}: {exc}")
        return None

    if http_status == 202:
        if not poll:
            _print_error(
                f"{path.name}: daemon returned 202 (analysis still running). "
                "Use --poll to wait for the result."
            )
            return body  # return partial result so caller can still write it
        file_hash = body.get("file", {}).get("sha256") or body.get("file_hash")
        if not file_hash:
            _print_error(f"{path.name}: 202 response has no file_hash — cannot poll")
            return body
        body = await _poll_result(session, base_url, file_hash, headers, poll_interval)
        if body is None:
            return None

    if http_status not in (200, 202):
        msg = body.get("error") or body.get("message") or json.dumps(body)
        _print_error(f"{path.name}: HTTP {http_status} — {msg}")
        return None

    return _normalize_result_payload(body)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _emit_result(
    result: dict[str, Any],
    filename: str,
    output_json: bool,
    no_color: bool,
) -> None:
    if output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    if HAS_RICH and not no_color:
        _format_rich(result, filename)
    else:
        print(_format_plain(result, filename))
        print()


def _print_error(msg: str) -> None:
    if HAS_RICH and _err_console is not None:
        _err_console.print(f"[bold red]Error:[/bold red] {msg}")
    else:
        print(f"Error: {msg}", file=sys.stderr)


def _print_warning(msg: str) -> None:
    if HAS_RICH and _err_console is not None:
        _err_console.print(f"[bold yellow]Warning:[/bold yellow] {msg}")
    else:
        print(f"Warning: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _fetch_query(args: argparse.Namespace) -> int:
    """Fetch ``GET /v1/query?hash=...`` and display or write the result.

    Unlike ``--poll`` (which follows a 202 from a just-submitted scan), this
    looks up a report by hash alone — useful for checking on a scan that is
    still processing in the background without re-uploading the file.
    """
    ssl_ctx: bool | ssl.SSLContext = False if args.insecure else True
    headers: dict[str, str] = {}
    if args.api_key:
        headers["X-Api-Key"] = args.api_key

    base_url = args.url.rstrip("/")
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as session:
            async with session.get(
                f"{base_url}/v1/query",
                params={"hash": args.query},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 401:
                    _print_error("Unauthorized — provide --api-key")
                    return 1
                if resp.status == 404:
                    _print_error(f"No report found for hash {args.query}")
                    return 1
                if resp.status != 200:
                    _print_error(f"HTTP {resp.status} from {base_url}/v1/query")
                    return 1
                body: dict[str, Any] = await resp.json(content_type=None)
    except aiohttp.ClientConnectorError as exc:
        _print_error(f"Cannot connect to {base_url}: {exc}")
        return 1
    except aiohttp.ClientError as exc:
        _print_error(f"Request error: {exc}")
        return 1

    result = _normalize_result_payload(body)
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        if HAS_RICH and not args.no_color:
            _console.print(f"[green]Wrote result to {out_path}[/green]")
        else:
            print(f"Wrote result to {out_path}")
        return 0

    _emit_result(result, args.query, args.json, args.no_color)
    return 0


async def _fetch_capabilities(args: argparse.Namespace) -> int:
    """Fetch ``GET /v1/capabilities`` and display or write the result."""
    ssl_ctx: bool | ssl.SSLContext = False if args.insecure else True
    headers: dict[str, str] = {}
    if args.api_key:
        headers["X-Api-Key"] = args.api_key

    base_url = args.url.rstrip("/")
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as session:
            async with session.get(
                f"{base_url}/v1/capabilities",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 401:
                    _print_error("Unauthorized — provide --api-key")
                    return 1
                if resp.status != 200:
                    _print_error(f"HTTP {resp.status} from {base_url}/v1/capabilities")
                    return 1
                payload: dict[str, Any] = await resp.json(content_type=None)
    except aiohttp.ClientConnectorError as exc:
        _print_error(f"Cannot connect to {base_url}: {exc}")
        return 1
    except aiohttp.ClientError as exc:
        _print_error(f"Request error: {exc}")
        return 1

    raw_json = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(raw_json, encoding="utf-8")
        if HAS_RICH and not args.no_color:
            _console.print(f"[green]Wrote capabilities to {out_path}[/green]")
        else:
            print(f"Wrote capabilities to {out_path}")
        return 0

    if args.json or not HAS_RICH or args.no_color:
        print(raw_json)
        return 0

    # Rich-formatted view
    from rich.table import Table  # noqa: PLC0415

    eng = payload.get("engine", {})
    _console.print(
        f"[bold cyan]xspct_scan[/bold cyan] "
        f"[green]{eng.get('version', '?')}[/green]  "
        f"(schema {eng.get('schema_version', '?')})"
    )

    lim = payload.get("limits", {})
    _console.print(
        f"  max_file_size={lim.get('max_file_size', '?')}  "
        f"timeout={lim.get('default_timeout', '?')}s  "
        f"archive_depth={lim.get('archive_max_depth', '?')}"
    )
    fmts = payload.get("response_formats", [])
    _console.print(f"  response_formats: {', '.join(fmts)}")

    tbl = Table(title="Analyzers", box=box.SIMPLE, show_header=True)
    tbl.add_column("Analyzer", style="bold")
    tbl.add_column("Active")
    tbl.add_column("Scope")
    tbl.add_column("MIME summary")
    for name, info in sorted(payload.get("analyzers", {}).items()):
        active = info.get("active", False)
        active_str = "[green]yes[/green]" if active else "[red]no[/red]"
        scope = info.get("scope", "-")
        if scope == "type-routed":
            mimes = info.get("mime_types", [])
            pats = info.get("mime_patterns", [])
            prefixes = []
            if mimes:
                prefixes.append(", ".join(mimes[:3]) + ("…" if len(mimes) > 3 else ""))
            if pats:
                prefixes.append(", ".join(pats[:2]) + ("…" if len(pats) > 2 else ""))
            mime_summary = " | ".join(prefixes) if prefixes else "-"
        else:
            mime_summary = "all files"
        tbl.add_row(name, active_str, scope, mime_summary)
    _console.print(tbl)

    mt = payload.get("mime_types", {})
    if mt.get("exact"):
        _console.print(
            f"  exact MIMEs ({len(mt['exact'])}): "
            + ", ".join(mt["exact"][:6])
            + ("…" if len(mt["exact"]) > 6 else "")
        )
    if mt.get("prefixes"):
        _console.print(f"  prefixes: {', '.join(mt['prefixes'])}")
    if mt.get("patterns"):
        _console.print(
            f"  patterns: {', '.join(mt['patterns'][:6])}"
            + ("…" if len(mt.get("patterns", [])) > 6 else "")
        )
    if mt.get("global_scanners"):
        _console.print(f"  global scanners: {', '.join(mt['global_scanners'])}")
    return 0


async def _run(args: argparse.Namespace) -> int:
    if args.capabilities:
        return await _fetch_capabilities(args)

    if args.query:
        return await _fetch_query(args)

    if not args.files:
        _print_error("No files given. Provide FILE arguments or use --capabilities.")
        return 2

    files = [Path(f) for f in args.files]
    missing = [f for f in files if not f.exists()]
    if missing:
        for f in missing:
            _print_error(f"File not found: {f}")
        return 1

    ssl_ctx: bool | ssl.SSLContext = False if args.insecure else True

    results: list[dict[str, Any]] = []
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=ssl_ctx)
    ) as session:
        tasks = [
            scan_file(
                session=session,
                path=p,
                base_url=args.url.rstrip("/"),
                timeout=args.timeout,
                passwords=args.passwords,
                api_key=args.api_key,
                poll=args.poll,
                poll_interval=args.poll_interval,
                no_color=args.no_color,
                force_analyzers=args.force_analyzers,
                invalidate_cache=args.invalidate_cache,
                legacy_multipart=args.legacy_multipart,
                rspamd_uid=args.rspamd_uid,
                queue_id=args.queue_id,
                message_id=args.message_id,
            )
            for p in files
        ]
        raw = await asyncio.gather(*tasks)

    for result, path in zip(raw, files):
        if result is None:
            return 1
        results.append(result)
        if not args.output:
            _emit_result(result, path.name, args.json, args.no_color)

    if args.output:
        out_path = Path(args.output)
        payload = results[0] if len(results) == 1 else results
        out_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        if HAS_RICH and not args.no_color:
            _console.print(f"[green]Wrote result to {out_path}[/green]")
        else:
            print(f"Wrote result to {out_path}")

    return 0


_DEFAULT_URL = "http://localhost:8080"
_DEFAULT_TIMEOUT = 30
_DEFAULT_POLL_INTERVAL = 2.0

_CONFIG_ENV_VAR = "XSPCT_SCAN_CLIENT_CONFIG"
_CONFIG_SEARCH_PATHS = (
    Path.home() / ".config" / "xspct_scan" / "client.yml",
    Path("/etc/xspct_scan/client.yml"),
)

# Config keys applied as defaults when the matching CLI flag was not given,
# mapped to the type the rest of the client expects. CLI flags are coerced by
# argparse's ``type=``; the config file has no equivalent, so values are
# validated here rather than failing deep inside the request path.
_CONFIG_SPEC: "dict[str, str]" = {
    "url": "str",
    "api_key": "str",
    "timeout": "int",
    "passwords": "csv",
    "force_analyzers": "csv",
    "invalidate_cache": "bool",
    "legacy_multipart": "bool",
    "rspamd_uid": "str",
    "queue_id": "str",
    "message_id": "str",
    "poll": "bool",
    "poll_interval": "float",
    "json": "bool",
    "output": "str",
    "no_color": "bool",
    "insecure": "bool",
}


def _find_config_path(explicit: "str | None") -> "Path | None":
    """Resolve the config file to load, or None if none applies.

    A path named explicitly — via --config or $XSPCT_SCAN_CLIENT_CONFIG — must
    exist; naming one that does not is an error rather than a silent fallback
    to the built-in defaults, which would quietly redirect scans at the wrong
    daemon. The unnamed default locations are skipped when absent.
    """
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            _print_error(f"Config file not found: {path}")
            sys.exit(1)
        return path
    env_path = os.environ.get(_CONFIG_ENV_VAR)
    if env_path:
        path = Path(env_path)
        if not path.is_file():
            _print_error(f"Config file not found: {path} (${_CONFIG_ENV_VAR})")
            sys.exit(1)
        return path
    for candidate in _CONFIG_SEARCH_PATHS:
        if candidate.is_file():
            return candidate
    return None


def _coerce_config_value(path: Path, key: str, value: Any, kind: str) -> Any:
    """Return *value* as *kind*, or exit 1 explaining what the key expects."""

    def _reject(expected: str) -> None:
        _print_error(
            f"Config file {path}: '{key}' must be {expected}, got "
            f"{type(value).__name__} ({value!r})"
        )
        sys.exit(1)

    if kind == "bool":
        # Deliberately strict: a quoted "false" is a non-empty string and so
        # truthy, which would silently flip flags like insecure to on.
        if not isinstance(value, bool):
            _reject("a boolean")
        return value
    if kind in ("int", "float"):
        expected = "an integer" if kind == "int" else "a number"
        convert = int if kind == "int" else float
        # bool is an int subclass; not a meaningful timeout or interval.
        if isinstance(value, bool):
            _reject(expected)
        if isinstance(value, (int, float)):
            if kind == "int" and isinstance(value, float):
                _reject(expected)
            return convert(value)
        if isinstance(value, str):
            try:
                return convert(value.strip())
            except ValueError:
                _reject(expected)
        _reject(expected)
    if kind == "csv":
        # Accept the CLI's comma-separated form or the YAML-native list.
        if isinstance(value, str):
            return value
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return ",".join(value)
        _reject("a string or a list of strings")
    if not isinstance(value, str):
        _reject("a string")
    return value


def _warn_unknown_config_keys(path: Path, cfg: "dict[str, Any]") -> None:
    """Warn about keys that will be ignored, suggesting the nearest real one.

    Silence here is dangerous: a mistyped api_key drops authentication and the
    only symptom is an opaque 401 from the daemon.
    """
    for key in sorted(str(k) for k in cfg if k not in _CONFIG_SPEC):
        close = difflib.get_close_matches(key.replace("-", "_"), _CONFIG_SPEC, n=1)
        hint = f" (did you mean '{close[0]}'?)" if close else ""
        _print_warning(f"Config file {path}: ignoring unknown key '{key}'{hint}")


def _load_client_config(path: "Path | None") -> "dict[str, Any]":
    if path is None:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        _print_error(f"YAML error in {path}: {exc}")
        sys.exit(1)
    except UnicodeDecodeError as exc:
        _print_error(f"Config file {path} is not UTF-8 text: {exc}")
        sys.exit(1)
    except OSError as exc:
        _print_error(f"Cannot read {path}: {exc}")
        sys.exit(1)
    if data is None:
        return {}
    if not isinstance(data, dict):
        _print_error(f"Config file {path} must contain a YAML mapping")
        sys.exit(1)
    _warn_unknown_config_keys(path, data)
    return {
        key: _coerce_config_value(path, key, value, _CONFIG_SPEC[key])
        for key, value in data.items()
        if key in _CONFIG_SPEC
    }


def _apply_config_defaults(args: argparse.Namespace, cfg: "dict[str, Any]") -> None:
    """Fill in unset CLI options from *cfg*, then apply built-in defaults."""
    for key in _CONFIG_SPEC:
        if key in cfg and not hasattr(args, key):
            setattr(args, key, cfg[key])
    defaults = {
        "url": _DEFAULT_URL,
        "api_key": None,
        "timeout": _DEFAULT_TIMEOUT,
        "passwords": None,
        "force_analyzers": None,
        "invalidate_cache": False,
        "legacy_multipart": False,
        "rspamd_uid": None,
        "queue_id": None,
        "message_id": None,
        "poll": False,
        "poll_interval": _DEFAULT_POLL_INTERVAL,
        "json": False,
        "output": None,
        "no_color": False,
        "insecure": False,
    }
    for key, value in defaults.items():
        if not hasattr(args, key):
            setattr(args, key, value)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser.

    Split out of main() so the option set can be introspected — see the test
    that keeps the module docstring (published as docs/reference/client.md) in
    sync with the flags actually offered.
    """
    parser = argparse.ArgumentParser(
        prog="xspct_scan_client",
        description="Submit files to an xspct_scan daemon for analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="Files to scan")
    parser.add_argument(
        "-C",
        "--capabilities",
        action="store_true",
        help="Fetch GET /v1/capabilities and display the active analyzer/MIME overview",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        default=None,
        help=(
            "Path to a YAML config file providing defaults for the other "
            "options (default: $XSPCT_SCAN_CLIENT_CONFIG, "
            "~/.config/xspct_scan/client.yml, or /etc/xspct_scan/client.yml, "
            "first match wins)"
        ),
    )
    parser.add_argument(
        "-u",
        "--url",
        default=argparse.SUPPRESS,
        metavar="URL",
        help="Daemon base URL (default: http://localhost:8080, or the config file)",
    )
    parser.add_argument(
        "-a",
        "--api-key",
        metavar="KEY",
        default=argparse.SUPPRESS,
        help="X-Api-Key header value",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=argparse.SUPPRESS,
        metavar="SECS",
        help="Analysis timeout in seconds sent to the daemon (default: 30, or the config file)",
    )
    parser.add_argument(
        "-p",
        "--passwords",
        metavar="LIST",
        default=argparse.SUPPRESS,
        help="Comma-separated passwords to try for encrypted files",
    )
    parser.add_argument(
        "-f",
        "--force-analyzers",
        metavar="LIST",
        default=argparse.SUPPRESS,
        dest="force_analyzers",
        help=(
            "Comma-separated analyzer paths to bypass exclusion gates for this request.\n"
            "Example: image.ocr  (disables the camera/size OCR gate)\n"
            "Equivalent to --force-ocr when set to 'image.ocr'"
        ),
    )
    parser.add_argument(
        "-F",
        "--force-ocr",
        default=argparse.SUPPRESS,
        action="store_const",
        const="image.ocr",
        dest="force_analyzers",
        help="Force OCR even when the camera-photo/size exclusion gate would skip it",
    )
    parser.add_argument(
        "-R",
        "--invalidate-cache",
        default=argparse.SUPPRESS,
        action="store_true",
        dest="invalidate_cache",
        help=(
            "Delete the daemon's Redis and in-memory cached report and force "
            "a full rescan. Use when re-submitting a known "
            "file with a new/updated --passwords list that must be tried "
            "from scratch."
        ),
    )
    parser.add_argument(
        "--use-cache",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="invalidate_cache",
        help="Use cached reports when available",
    )
    parser.add_argument(
        "-L",
        "--legacy-multipart",
        default=argparse.SUPPRESS,
        action="store_true",
        help=(
            "Use the legacy 'doc' multipart field instead of the structured "
            "'metadata' + 'file' shape (default). For talking to older daemons."
        ),
    )
    parser.add_argument(
        "--structured-multipart",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="legacy_multipart",
        help="Use the structured metadata and file multipart shape",
    )
    parser.add_argument(
        "-r",
        "--rspamd-uid",
        metavar="ID",
        default=argparse.SUPPRESS,
        help="rspamd_uid to place in the metadata part (correlation)",
    )
    parser.add_argument(
        "-Q",
        "--queue-id",
        metavar="ID",
        default=argparse.SUPPRESS,
        help="queue_id to place in the metadata part",
    )
    parser.add_argument(
        "-m",
        "--message-id",
        metavar="ID",
        default=argparse.SUPPRESS,
        help="message_id to place in the metadata part",
    )
    parser.add_argument(
        "-P",
        "--poll",
        default=argparse.SUPPRESS,
        action="store_true",
        help="Poll /v1/query until the result is ready when a 202 is returned",
    )
    parser.add_argument(
        "--no-poll",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="poll",
        help="Return immediately when a scan is still processing",
    )
    parser.add_argument(
        "-q",
        "--query",
        metavar="HASH",
        default=None,
        help=(
            "Look up a report by SHA-256 hash via GET /v1/query instead of "
            "submitting a file. Useful for checking on a scan that is still "
            "processing in the background without re-uploading it."
        ),
    )
    parser.add_argument(
        "-I",
        "--poll-interval",
        type=float,
        default=argparse.SUPPRESS,
        metavar="SECS",
        help="Seconds between poll attempts (default: 2, or the config file)",
    )
    parser.add_argument(
        "-j",
        "--json",
        default=argparse.SUPPRESS,
        action="store_true",
        help="Output raw JSON instead of a formatted summary",
    )
    parser.add_argument(
        "--no-json",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="json",
        help="Output a formatted summary instead of raw JSON",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=argparse.SUPPRESS,
        help="Write JSON result(s) to FILE",
    )
    parser.add_argument(
        "-n",
        "--no-color",
        default=argparse.SUPPRESS,
        action="store_true",
        help="Disable coloured rich output",
    )
    parser.add_argument(
        "--color",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="no_color",
        help="Enable coloured rich output",
    )
    parser.add_argument(
        "-i",
        "--insecure",
        default=argparse.SUPPRESS,
        action="store_true",
        help="Skip TLS certificate verification",
    )
    parser.add_argument(
        "--secure",
        default=argparse.SUPPRESS,
        action="store_false",
        dest="insecure",
        help="Verify TLS certificates",
    )

    parser.epilog = (
        "Examples:\n"
        "  xspct_scan_client invoice.pdf\n"
        "  xspct_scan_client --url http://scan.internal:8080 --json report.zip\n"
        "  xspct_scan_client --poll --timeout 60 large_archive.zip\n"
        "  xspct_scan_client --api-key s3cr3t --output result.json sample.doc\n"
        "  xspct_scan_client --capabilities --url http://scan.internal:8080\n"
        "  xspct_scan_client --query <sha256>\n"
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    config_path = _find_config_path(args.config)
    _apply_config_defaults(args, _load_client_config(config_path))

    if sum(bool(x) for x in (args.capabilities, args.query, args.files)) > 1:
        parser.error(
            "--capabilities, --query, and FILE arguments are mutually exclusive"
        )
    if not args.capabilities and not args.query and not args.files:
        parser.error("provide FILE arguments to scan, or use --capabilities or --query")
    if args.legacy_multipart and (args.rspamd_uid or args.queue_id or args.message_id):
        parser.error(
            "--rspamd-uid/--queue-id/--message-id require the structured "
            "metadata shape and cannot be combined with --legacy-multipart "
            "(the legacy 'doc' shape has no metadata part to carry them)"
        )
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
