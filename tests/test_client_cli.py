# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""CLI configuration and argument parsing tests."""

import argparse
import sys
from pathlib import Path

import pytest

from xspct_scan import client as xspct_client


def test_load_client_config_rejects_invalid_content(tmp_path: Path) -> None:
    config_path = tmp_path / "client.yml"
    config_path.write_text("- not\n- a mapping\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="1"):
        xspct_client._load_client_config(config_path)

    config_path.write_text("url: [not closed\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="1"):
        xspct_client._load_client_config(config_path)


def test_find_config_path_prioritizes_explicit_then_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    explicit_path = tmp_path / "explicit.yml"
    environment_path = tmp_path / "environment.yml"
    fallback_path = tmp_path / "fallback.yml"
    for path in (explicit_path, environment_path, fallback_path):
        path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(xspct_client, "_CONFIG_SEARCH_PATHS", (fallback_path,))
    monkeypatch.setenv(xspct_client._CONFIG_ENV_VAR, str(environment_path))

    assert xspct_client._find_config_path(None) == environment_path
    assert xspct_client._find_config_path(str(explicit_path)) == explicit_path


def test_apply_config_defaults_fills_missing_values() -> None:
    args = argparse.Namespace()

    xspct_client._apply_config_defaults(
        args,
        {"url": "http://configured:8080", "api_key": "config-key", "timeout": 60},
    )

    assert args.url == "http://configured:8080"
    assert args.api_key == "config-key"
    assert args.timeout == 60
    assert args.poll is False
    assert args.poll_interval == 2.0


def test_apply_config_defaults_preserves_explicit_false_values() -> None:
    args = argparse.Namespace(
        json=False,
        no_color=False,
        poll=False,
        insecure=False,
        invalidate_cache=False,
        legacy_multipart=False,
    )

    xspct_client._apply_config_defaults(
        args,
        {
            "json": True,
            "no_color": True,
            "poll": True,
            "insecure": True,
            "invalidate_cache": True,
            "legacy_multipart": True,
        },
    )

    assert args.json is False
    assert args.no_color is False
    assert args.poll is False
    assert args.insecure is False
    assert args.invalidate_cache is False
    assert args.legacy_multipart is False


def test_main_short_options_override_boolean_config_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "client.yml"
    config_path.write_text(
        "json: true\nno_color: true\npoll: true\ninsecure: true\n"
        "invalidate_cache: true\nlegacy_multipart: true\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    async def fake_run(args: argparse.Namespace) -> int:
        captured.update(vars(args))
        return 0

    monkeypatch.setattr(xspct_client, "_run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "xspct_scan_client",
            "-c",
            str(config_path),
            "-q",
            "deadbeef",
            "--no-json",
            "--color",
            "--no-poll",
            "--secure",
            "--use-cache",
            "--structured-multipart",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        xspct_client.main()

    assert exc_info.value.code == 0
    assert captured["query"] == "deadbeef"
    assert captured["json"] is False
    assert captured["no_color"] is False
    assert captured["poll"] is False
    assert captured["insecure"] is False
    assert captured["invalidate_cache"] is False
    assert captured["legacy_multipart"] is False


def test_load_client_config_coerces_and_rejects_bad_types(tmp_path: Path) -> None:
    """Config values get the coercion argparse gives CLI flags."""
    config_path = tmp_path / "client.yml"

    # Numeric strings are accepted, as are YAML-native lists for csv keys.
    config_path.write_text(
        'timeout: "60"\npoll_interval: "1.5"\npasswords:\n  - a\n  - b\n',
        encoding="utf-8",
    )
    cfg = xspct_client._load_client_config(config_path)
    assert cfg == {"timeout": 60, "poll_interval": 1.5, "passwords": "a,b"}

    # Anything that cannot be coerced fails with a message, not a traceback
    # deep inside the request path.
    for bad in (
        "timeout: abc\n",
        "timeout: 1.5\n",
        "poll_interval: [1]\n",
        "url: 8080\n",
    ):
        config_path.write_text(bad, encoding="utf-8")
        with pytest.raises(SystemExit, match="1"):
            xspct_client._load_client_config(config_path)


def test_load_client_config_rejects_non_boolean_flags(tmp_path: Path) -> None:
    """A quoted "false" is a truthy string — it must not enable the flag."""
    config_path = tmp_path / "client.yml"
    config_path.write_text('insecure: "false"\n', encoding="utf-8")

    with pytest.raises(SystemExit, match="1"):
        xspct_client._load_client_config(config_path)


def test_load_client_config_warns_about_unknown_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A mistyped api_key silently drops auth, so it must be reported."""
    config_path = tmp_path / "client.yml"
    config_path.write_text("url: http://h:1/\napi-key: s3cr3t\n", encoding="utf-8")

    cfg = xspct_client._load_client_config(config_path)

    assert cfg == {"url": "http://h:1/"}
    err = capsys.readouterr().err
    assert "api-key" in err
    assert "api_key" in err  # suggests the correct spelling


def test_load_client_config_rejects_non_utf8_file(tmp_path: Path) -> None:
    config_path = tmp_path / "client.yml"
    config_path.write_bytes(b"\xa8\xff\x00binary")

    with pytest.raises(SystemExit, match="1"):
        xspct_client._load_client_config(config_path)


def test_find_config_path_rejects_missing_environment_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A typo'd env var must not silently fall back to localhost defaults."""
    monkeypatch.setattr(xspct_client, "_CONFIG_SEARCH_PATHS", ())
    monkeypatch.setenv(xspct_client._CONFIG_ENV_VAR, str(tmp_path / "missing.yml"))

    with pytest.raises(SystemExit, match="1"):
        xspct_client._find_config_path(None)


def test_module_docstring_documents_every_option() -> None:
    """The docstring ships as docs/reference/client.md — keep it in sync."""
    parser = xspct_client._build_parser()
    docstring = xspct_client.__doc__ or ""
    for action in parser._actions:
        for option in action.option_strings:
            if option in ("-h", "--help"):
                continue
            assert option in docstring, f"{option} missing from module docstring"


def test_short_option_aliases_are_unique_and_stable() -> None:
    """Short flags are part of the CLI contract once released.

    -a/-i deliberately differ from curl's -k/-s: -i is bound to --insecure so
    that skipping TLS verification is not one slip away from an unrelated flag.
    """
    parser = xspct_client._build_parser()
    by_short = {
        option: action.dest
        for action in parser._actions
        for option in action.option_strings
        if len(option) == 2 and option != "-h"
    }

    assert by_short["-a"] == "api_key"
    assert by_short["-i"] == "insecure"
    assert by_short["-R"] == "invalidate_cache"

    shorts = [
        option
        for action in parser._actions
        for option in action.option_strings
        if len(option) == 2
    ]
    assert len(shorts) == len(set(shorts))


class _PollResponse:
    """Minimal aiohttp response stub for _poll_result."""

    def __init__(self, status: int, body: object) -> None:
        self.status = status
        self._body = body

    async def json(self, content_type: object = None) -> object:
        return self._body

    async def __aenter__(self) -> "_PollResponse":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _PollSession:
    """Serves a scripted sequence of /v1/query responses."""

    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls = 0

    def get(self, *args: object, **kwargs: object) -> _PollResponse:
        self.calls += 1
        status, body = self._responses.pop(0)
        return _PollResponse(status, body)


async def test_poll_result_keeps_polling_while_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/v1/query answers 200 for an in-flight scan, not 404.

    Returning on the first 200 handed back an unfinished report as if it were
    the final result.
    """

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(xspct_client.asyncio, "sleep", no_sleep)

    finished = {"status": "finished", "report": {"verdict": {"score": 7}}}
    session = _PollSession(
        [
            (200, {"status": "processing", "file_hash": "a" * 64}),
            (404, {"status": "not_found"}),
            (200, {"status": "processing", "file_hash": "a" * 64}),
            (200, finished),
        ]
    )

    result = await xspct_client._poll_result(session, "http://d", "a" * 64, {}, 0.0)

    assert session.calls == 4
    assert result == {"verdict": {"score": 7}, "status": "finished"}


async def test_poll_result_returns_none_when_never_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout must not pass a partial report off as the verdict."""

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(xspct_client.asyncio, "sleep", no_sleep)

    processing = (200, {"status": "processing", "file_hash": "b" * 64})
    session = _PollSession([processing] * 3)

    result = await xspct_client._poll_result(
        session, "http://d", "b" * 64, {}, 0.0, max_attempts=3
    )

    assert result is None
    assert session.calls == 3


async def test_poll_result_rejects_non_object_body(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A 200 carrying a JSON array must not reach the dict-only normalizer."""

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(xspct_client.asyncio, "sleep", no_sleep)
    session = _PollSession([(200, ["unexpected"])])

    result = await xspct_client._poll_result(session, "http://d", "c" * 64, {}, 0.0)

    assert result is None
    assert "expected a JSON object" in capsys.readouterr().err
