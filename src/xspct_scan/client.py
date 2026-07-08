# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
xspct-scan-client — command-line client for the xspct-scan HTTP API.

Usage::

    xspct-scan-client [options] FILE [FILE ...]

Options::

    --url URL           Base URL of the daemon (default: http://localhost:8080)
    --api-key KEY       X-Api-Key header value for authenticated daemons
    --timeout SECS      Analysis timeout in seconds passed to the daemon (default: 30)
    --passwords LIST    Comma-separated passwords to try for encrypted files
    --rtf               Enable RTF object extraction (passes ?rtf=true)
    --poll              Poll /v1/query after a 202 response until the result is ready
    --poll-interval N   Seconds between poll attempts (default: 2)
    --json              Output raw JSON instead of a human-readable summary
    --output FILE       Write JSON result(s) to FILE (single result or JSON array)
    --no-color          Disable rich/colour output
    --insecure          Skip TLS certificate verification
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
from pathlib import Path
from typing import Any

import aiohttp

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich import box

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
    lines.append(f"Status:   {result.get('status', '-')}  ({_scan.get('duration_s', result.get('time_taken', '-'))} s)")

    flags: list[str] = []
    if _flags_v2.get("macros", result.get("has_macro")):
        flags.append("macro")
    if _flags_v2.get("encrypted", result.get("is_encrypted")):
        flags.append("encrypted")
    if _flags_v2.get("javascript", result.get("has_javascript")):
        flags.append("javascript")
    if _flags_v2.get("decrypted", result.get("decrypted")):
        _pw = _flags_v2.get("decryption_password") or result.get("decryption_password", "?")
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

    yara = (result.get("engines") or {}).get("yara", {}).get("matches") or result.get("yara_matches") or []
    if yara:
        names = ", ".join(m.get("rule", "?") for m in yara[:6])
        suffix = f" … +{len(yara) - 6}" if len(yara) > 6 else ""
        lines.append(f"YARA ({len(yara)}): {names}{suffix}")

    archive = (result.get("engines") or {}).get("archive", {}).get("files") or result.get("archive_files") or []
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
        _pw = _flags_v2.get("decryption_password") or result.get("decryption_password", "?")
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

    yara = (result.get("engines") or {}).get("yara", {}).get("matches") or result.get("yara_matches") or []
    if yara:
        names = ", ".join(m.get("rule", "?") for m in yara[:6])
        suffix = f" … +{len(yara) - 6}" if len(yara) > 6 else ""
        tbl.add_row("YARA", f"[red]{len(yara)}[/red]: {names}{suffix}")

    archive = (result.get("engines") or {}).get("archive", {}).get("files") or result.get("archive_files") or []
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
                    return _normalize_result_payload(body)
                # 404 → still processing; keep polling
        except aiohttp.ClientError:
            pass
    _print_error(f"Polling timed out for hash {file_hash}")
    return None


async def scan_file(
    session: aiohttp.ClientSession,
    path: Path,
    base_url: str,
    timeout: int,
    passwords: str | None,
    rtf: bool,
    api_key: str | None,
    poll: bool,
    poll_interval: float,
    no_color: bool,
    force_analyzers: str | None = None,
) -> dict[str, Any] | None:
    """POST *path* to /v1/scan. Returns the result dict or None on error."""
    headers: dict[str, str] = {}
    if api_key:
        headers["X-Api-Key"] = api_key

    params: dict[str, str] = {"timeout": str(timeout)}
    if rtf:
        params["rtf"] = "true"
    if force_analyzers:
        params["force_analyzers"] = force_analyzers

    try:
        with path.open("rb") as fh:
            form = aiohttp.FormData()
            form.add_field(
                "doc", fh, filename=path.name, content_type="application/octet-stream"
            )
            if passwords:
                form.add_field("passwords", passwords)
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace) -> int:
    files = [Path(f) for f in args.files]
    missing = [f for f in files if not f.exists()]
    if missing:
        for f in missing:
            _print_error(f"File not found: {f}")
        return 1

    ssl_ctx: bool | ssl.SSLContext = False if args.insecure else True

    results: list[dict[str, Any]] = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
        tasks = [
            scan_file(
                session=session,
                path=p,
                base_url=args.url.rstrip("/"),
                timeout=args.timeout,
                passwords=args.passwords,
                rtf=args.rtf,
                api_key=args.api_key,
                poll=args.poll,
                poll_interval=args.poll_interval,
                no_color=args.no_color,
                force_analyzers=args.force_analyzers,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="xspct-scan-client",
        description="Submit files to an xspct-scan daemon for analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  xspct-scan-client invoice.pdf\n"
            "  xspct-scan-client --url http://scan.internal:8080 --json report.zip\n"
            "  xspct-scan-client --poll --timeout 60 large_archive.zip\n"
            "  xspct-scan-client --api-key s3cr3t --output result.json sample.doc\n"
        ),
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="Files to scan")
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        metavar="URL",
        help="Daemon base URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        default=None,
        help="X-Api-Key header value",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECS",
        help="Analysis timeout in seconds sent to the daemon (default: 30)",
    )
    parser.add_argument(
        "--passwords",
        metavar="LIST",
        default=None,
        help="Comma-separated passwords to try for encrypted files",
    )
    parser.add_argument(
        "--rtf",
        action="store_true",
        help="Enable RTF object extraction",
    )
    parser.add_argument(
        "--force-analyzers",
        metavar="LIST",
        default=None,
        dest="force_analyzers",
        help=(
            "Comma-separated analyzer paths to bypass exclusion gates for this request.\n"
            "Example: image.ocr  (disables the camera/size OCR gate)\n"
            "Equivalent to --force-ocr when set to 'image.ocr'"
        ),
    )
    parser.add_argument(
        "--force-ocr",
        action="store_const",
        const="image.ocr",
        dest="force_analyzers",
        help="Force OCR even when the camera-photo/size exclusion gate would skip it",
    )
    parser.add_argument(
        "--poll",
        action="store_true",
        help="Poll /v1/query until the result is ready when a 202 is returned",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        metavar="SECS",
        help="Seconds between poll attempts (default: 2)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of a formatted summary",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write JSON result(s) to FILE",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured rich output",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification",
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
