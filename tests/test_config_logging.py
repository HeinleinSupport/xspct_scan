# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Config loading, logging setup, and session-ID helper tests."""

import logging
from unittest.mock import MagicMock

import pytest

import xspct_scan.daemon as xspct


class TestSessionHelpers:
    def test_session_id_is_6_hex_chars(self):
        sid = xspct.generate_session_id()
        assert len(sid) == 6
        assert all(c in "0123456789abcdef" for c in sid)

    def test_session_ids_are_unique(self):
        ids = {xspct.generate_session_id() for _ in range(200)}
        assert len(ids) > 1

    def test_make_session_format_no_rspamd(self):
        req = MagicMock()
        req.headers = {}
        s = xspct.make_session(req)
        assert s.startswith("<") and s.endswith(">")
        assert len(s) == 8  # <xxxxxx>

    def test_make_session_includes_rspamd_id(self):
        req = MagicMock()
        req.headers = {xspct.config["xspct_rspamd_header"]: "rspamd99"}
        s = xspct.make_session(req)
        assert "-" in s
        assert "rspamd" in s


class TestLoadConfig:
    def test_none_path_is_noop(self):
        # Should not raise and should normalise api_key
        xspct.config["xspct_api_key"] = "single-key"
        xspct.load_config(None)
        assert isinstance(xspct.config["xspct_api_key"], list)
        assert xspct.config["xspct_api_key"] == ["single-key"]

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            xspct.load_config(str(tmp_path / "nonexistent.yml"))

    def test_valid_yaml_updates_config(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_listen_port: 9999\n")
        original = xspct.config["xspct_listen_port"]
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_listen_port"] == 9999
        finally:
            xspct.config["xspct_listen_port"] = original

    def test_sub_dict_is_merged_not_replaced(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_redis_cache:\n  host: redis.custom.example\n")
        original_port = xspct.config["xspct_redis_cache"]["port"]
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_redis_cache"]["host"] == "redis.custom.example"
            assert xspct.config["xspct_redis_cache"]["port"] == original_port
        finally:
            xspct.config["xspct_redis_cache"]["host"] = "localhost"

    def test_invalid_yaml_exits(self, tmp_path):
        cfg = tmp_path / "bad.yml"
        cfg.write_text(": invalid: yaml: {unclosed\n")
        with pytest.raises(SystemExit):
            xspct.load_config(str(cfg))

    def test_string_api_key_normalised_to_list(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_api_key: my-secret-key\n")
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_api_key"] == ["my-secret-key"]
        finally:
            xspct.config["xspct_api_key"] = []

    def test_empty_string_api_key_normalised_to_empty_list(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text('xspct_api_key: ""\n')
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_api_key"] == []
        finally:
            xspct.config["xspct_api_key"] = []


# ===========================================================================
# UNIT TESTS — configure_logging
# ===========================================================================


class TestConfigureLogging:
    def test_calling_twice_does_not_duplicate_handlers(self):
        xspct.configure_logging()
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers if not isinstance(h, logging.NullHandler)
        ]
        assert len(real_handlers) == 1

    def test_log_level_applied(self):
        xspct.config["xspct_log_level"] = logging.WARNING
        xspct.configure_logging()
        assert xspct.logger.level == logging.WARNING
        xspct.config["xspct_log_level"] = 20  # restore
        xspct.configure_logging()

    def test_handler_is_stream_handler(self):
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers if not isinstance(h, logging.NullHandler)
        ]
        assert isinstance(real_handlers[0], logging.StreamHandler)


# ===========================================================================
# UNIT TESTS — get_detected_type (image / archive types)
# ===========================================================================
