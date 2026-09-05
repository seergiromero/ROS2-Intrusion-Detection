"""
MIT License

Copyright (c) 2026 Sergi Romero Valderas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))
import clear_results as cr  # noqa: E402


@pytest.fixture
def workspace(tmp_path):
    """Create a minimal RIDS workspace with a config and pre-populated results."""
    cfg = tmp_path / "rids.yaml"
    cfg.write_text(
        "paths:\n"
        "  snapshots: results/phase1/snapshots.jsonl\n"
        "  alerts: results/phase2/alerts.jsonl\n",
        encoding="utf-8",
    )
    snapshots = tmp_path / "results" / "phase1" / "snapshots.jsonl"
    alerts = tmp_path / "results" / "phase2" / "alerts.jsonl"
    snapshots.parent.mkdir(parents=True)
    alerts.parent.mkdir(parents=True)
    snapshots.write_text('{"snapshot_id": 0}\n{"snapshot_id": 1}\n', encoding="utf-8")
    alerts.write_text('{"alert": 1}\n', encoding="utf-8")
    return {"root": tmp_path, "config": cfg, "snapshots": snapshots, "alerts": alerts}


# ---------------------------------------------------------------------------
# Truncate mode
# ---------------------------------------------------------------------------

class TestTruncate:
    def test_truncates_both_files(self, workspace):
        rc = cr.main(["--config", str(workspace["config"])])
        assert rc == 0
        assert workspace["snapshots"].read_text(encoding="utf-8") == ""
        assert workspace["alerts"].read_text(encoding="utf-8") == ""

    def test_files_still_exist_after_truncate(self, workspace):
        cr.main(["--config", str(workspace["config"])])
        assert workspace["snapshots"].exists()
        assert workspace["alerts"].exists()

    def test_snapshots_only(self, workspace):
        rc = cr.main(["--config", str(workspace["config"]), "--snapshots-only"])
        assert rc == 0
        assert workspace["snapshots"].read_text(encoding="utf-8") == ""
        assert workspace["alerts"].read_text(encoding="utf-8") == '{"alert": 1}\n'

    def test_alerts_only(self, workspace):
        rc = cr.main(["--config", str(workspace["config"]), "--alerts-only"])
        assert rc == 0
        assert workspace["snapshots"].read_text(encoding="utf-8") == '{"snapshot_id": 0}\n{"snapshot_id": 1}\n'
        assert workspace["alerts"].read_text(encoding="utf-8") == ""

    def test_mutually_exclusive_flags(self, workspace):
        with pytest.raises(SystemExit):
            cr.main([
                "--config", str(workspace["config"]),
                "--snapshots-only", "--alerts-only",
            ])


# ---------------------------------------------------------------------------
# Remove mode
# ---------------------------------------------------------------------------

class TestRemove:
    def test_removes_both_files(self, workspace):
        rc = cr.main(["--config", str(workspace["config"]), "--remove"])
        assert rc == 0
        assert not workspace["snapshots"].exists()
        assert not workspace["alerts"].exists()

    def test_remove_snapshots_only(self, workspace):
        rc = cr.main(["--config", str(workspace["config"]), "--remove", "--snapshots-only"])
        assert rc == 0
        assert not workspace["snapshots"].exists()
        assert workspace["alerts"].exists()

    def test_remove_missing_file_is_ok(self, workspace):
        workspace["snapshots"].unlink()
        rc = cr.main(["--config", str(workspace["config"]), "--remove"])
        assert rc == 0
        # alerts (which existed) should be gone.
        assert not workspace["alerts"].exists()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_does_not_touch_files(self, workspace, capsys):
        rc = cr.main(["--config", str(workspace["config"]), "--dry-run"])
        assert rc == 0
        assert workspace["snapshots"].read_text(encoding="utf-8") == '{"snapshot_id": 0}\n{"snapshot_id": 1}\n'
        assert workspace["alerts"].read_text(encoding="utf-8") == '{"alert": 1}\n'
        captured = capsys.readouterr()
        assert "would truncate" in captured.out

    def test_dry_run_remove(self, workspace, capsys):
        rc = cr.main(["--config", str(workspace["config"]), "--dry-run", "--remove"])
        assert rc == 0
        assert workspace["snapshots"].exists()
        assert workspace["alerts"].exists()
        captured = capsys.readouterr()
        assert "would remove" in captured.out


# ---------------------------------------------------------------------------
# Missing files
# ---------------------------------------------------------------------------

class TestMissingFiles:
    def test_truncate_missing_file_is_ok(self, workspace, capsys):
        workspace["snapshots"].unlink()
        rc = cr.main(["--config", str(workspace["config"])])
        assert rc == 0
        # alerts should still be cleared.
        assert workspace["alerts"].read_text(encoding="utf-8") == ""
        captured = capsys.readouterr()
        assert "missing, nothing to do" in captured.out


# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------

class TestConfigDiscovery:
    def test_resolves_paths_relative_to_config(self, tmp_path):
        """If the YAML says 'results/foo.jsonl', the script resolves that
        path against the YAML's directory, not the cwd.
        """
        cfg = tmp_path / "myconfig.yaml"
        cfg.write_text(
            "paths:\n"
            "  snapshots: custom/sub/snap.jsonl\n"
            "  alerts: custom/sub/alerts.jsonl\n",
            encoding="utf-8",
        )
        snap = tmp_path / "custom" / "sub" / "snap.jsonl"
        alert = tmp_path / "custom" / "sub" / "alerts.jsonl"
        snap.parent.mkdir(parents=True, exist_ok=True)
        alert.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text("a\n", encoding="utf-8")
        alert.write_text("b\n", encoding="utf-8")

        rc = cr.main(["--config", str(cfg)])
        assert rc == 0
        assert snap.read_text(encoding="utf-8") == ""
        assert alert.read_text(encoding="utf-8") == ""

    def test_falls_back_to_defaults_if_yaml_missing(self, tmp_path, capsys):
        missing = tmp_path / "no-such.yaml"
        rc = cr.main(["--config", str(missing), "--dry-run"])
        assert rc == 0
        captured = capsys.readouterr()
        # Defaults from the script match the package defaults.
        assert "snapshots.jsonl" in captured.out
        assert "alerts.jsonl" in captured.out
