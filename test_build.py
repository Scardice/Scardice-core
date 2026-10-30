import importlib.util
import sys
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
BUILD_SCRIPT = ROOT / "build.py"


def load_builder(test_case):
    if not BUILD_SCRIPT.is_file():
        test_case.fail("build.py must provide the Python build CLI")
    spec = importlib.util.spec_from_file_location("scardice_build", BUILD_SCRIPT)
    test_case.assertIsNotNone(spec)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConfigGroupTests(unittest.TestCase):
    def setUp(self):
        self.build = load_builder(self)
        self.config = {
            "default_group": "default",
            "groups": {
                "default": {
                    "appname": "Scardice",
                    "build_mode": "single",
                    "cgo": False,
                    "targets": ["host/host"],
                },
                "linux-release": {
                    "appname": "Scardice Stable",
                    "build_mode": "multi",
                    "targets": ["linux/amd64", "linux/arm64"],
                    "cgo": True,
                },
            },
        }

    def test_selected_group_inherits_default_and_overrides_its_values(self):
        group_name, settings = self.build.resolve_config_group(self.config, "linux-release")

        self.assertEqual(group_name, "linux-release")
        self.assertEqual(
            settings,
            {
                "appname": "Scardice Stable",
                "build_mode": "multi",
                "cgo": True,
                "targets": ["linux/amd64", "linux/arm64"],
            },
        )

    def test_cli_accepts_a_named_config_group(self):
        args = self.build.parse_arguments(["--config-group", "linux-release"])

        self.assertEqual(args.config_group, "linux-release")

    def test_missing_group_selects_the_declared_default(self):
        group_name, settings = self.build.resolve_config_group(self.config, None)

        self.assertEqual(group_name, "default")
        self.assertEqual(settings["targets"], ["host/host"])

    def test_checked_in_default_and_dev_groups_are_available(self):
        config = self.build.load_config(ROOT / "build-config.json")
        group_name, default = self.build.resolve_config_group(config, None)
        dev_group, dev = self.build.resolve_config_group(config, "dev")

        self.assertEqual(group_name, "default")
        self.assertEqual(dev_group, "dev")
        self.assertFalse(default["development"])
        self.assertTrue(dev["development"])

    def test_unknown_group_is_rejected(self):
        with self.assertRaises(self.build.BuildError):
            self.build.resolve_config_group(self.config, "missing")

    def test_explicit_group_is_noninteractive_even_on_a_terminal(self):
        self.assertFalse(self.build.should_prompt_for_settings("linux-release", stdin_isatty=True))

    def test_default_group_prompts_only_on_a_terminal(self):
        self.assertTrue(self.build.should_prompt_for_settings(None, stdin_isatty=True))
        self.assertFalse(self.build.should_prompt_for_settings(None, stdin_isatty=False))

    def test_host_target_expands_and_target_order_is_preserved(self):
        targets = self.build.parse_targets(
            ["host/host", "linux/arm64"], host_goos="windows", host_goarch="amd64"
        )

        self.assertEqual(targets, [("windows", "amd64"), ("linux", "arm64")])

    def test_windows_host_uses_native_compiler_for_windows_cross_arch(self):
        with patch.object(
            self.build,
            "find_command",
            side_effect=lambda name: "cl.exe" if name == "cl.exe" else None,
        ):
            self.build.check_cgo_dependencies(
                [("windows", "amd64")], "windows", "arm64", cgo=True
            )

            self.assertIsNone(
                self.build.cross_compiler(
                    "windows", "amd64", "windows", "arm64", cgo=True
                )
            )

    def test_unsupported_target_is_rejected(self):
        with self.assertRaises(self.build.BuildError):
            self.build.parse_targets(["plan9/amd64"], host_goos="linux", host_goarch="amd64")

    def test_target_defaults_and_mode_validation(self):
        resolve = getattr(self.build, "resolve_targets_for_mode", None)
        self.assertIsNotNone(resolve, "build mode must reject empty multi-target profiles")

        self.assertEqual(
            resolve("single", [], host_goos="linux", host_goarch="amd64"),
            [("linux", "amd64")],
        )
        with self.assertRaises(self.build.BuildError):
            resolve("multi", [], host_goos="linux", host_goarch="amd64")

    def test_frontend_staging_restores_existing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            built_ui = root / "dist"
            static_frontend = root / "static" / "frontend"
            built_ui.mkdir()
            static_frontend.mkdir(parents=True)
            (built_ui / "index.html").write_text("built-ui", encoding="utf-8")
            (static_frontend / "index.html").write_text("user-version", encoding="utf-8")
            (static_frontend / "user-only.txt").write_text("keep", encoding="utf-8")

            with self.build.staged_frontend_assets(built_ui, static_frontend):
                self.assertEqual(
                    (static_frontend / "index.html").read_text(encoding="utf-8"), "built-ui"
                )
                self.assertFalse((static_frontend / "user-only.txt").exists())

            self.assertEqual(
                (static_frontend / "index.html").read_text(encoding="utf-8"), "user-version"
            )
            self.assertEqual(
                (static_frontend / "user-only.txt").read_text(encoding="utf-8"), "keep"
            )

    def test_archives_include_the_package_root_and_builtins_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_name = "Scardice_1.0_linux_amd64"
            package = root / package_name
            data_dir = package / "data"
            data_dir.mkdir(parents=True)
            (package / "Scardice-core").write_bytes(b"binary")
            (data_dir / "manifest.json").write_text("{}", encoding="utf-8")
            zip_path = root / "package.zip"
            tar_path = root / "package.tar.gz"

            self.build._archive_zip(package, package_name, zip_path)
            self.build._archive_tar_gz(package, package_name, tar_path)

            with zipfile.ZipFile(zip_path) as archive:
                self.assertEqual(
                    archive.read(f"{package_name}/data/manifest.json"), b"{}"
                )
            with tarfile.open(tar_path, "r:gz") as archive:
                binary = archive.extractfile(f"{package_name}/Scardice-core")
                self.assertEqual(binary.read(), b"binary")

    def test_config_requires_a_defined_default_group(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "build-config.json"
            config_path.write_text(
                '{"default_group":"missing","groups":{"release":{}}}', encoding="utf-8"
            )

            with self.assertRaises(self.build.BuildError):
                self.build.load_config(config_path)


    def test_proxy_skips_axel_and_uses_python_download(self):
        proxy_environment = {
            name: ""
            for name in (
                "BUILD_PROXY",
                "ALL_PROXY",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "all_proxy",
                "https_proxy",
                "http_proxy",
            )
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "asset.bin"
            settings = {
                "download_connect_timeout": 10,
                "download_max_time": 60,
                "download_speed_limit": 0,
                "download_speed_time": 30,
                "download_retries": 1,
                "download_axel_timeout": 60,
                "runtime_axel_connections": 8,
            }

            def write_download(_url, path, _opener, _settings):
                path.write_bytes(b"through-proxy")

            with patch.dict(self.build.os.environ, proxy_environment):
                with patch.object(
                    self.build,
                    "resolve_download_proxy",
                    return_value=("http://proxy.example:8080", True),
                ), patch.object(
                    self.build,
                    "find_command",
                    side_effect=lambda name: "axel" if name == "axel" else None,
                ), patch.object(
                    self.build, "_download_via_python", side_effect=write_download
                ), patch.object(self.build.subprocess, "run") as run:
                    self.assertTrue(
                        self.build.download_file_with_cache(
                            "https://downloads.example/asset.bin",
                            destination,
                            "runtime asset",
                            settings,
                            redownload=False,
                        )
                    )

                    run.assert_not_called()
            self.assertEqual(destination.read_bytes(), b"through-proxy")

    def test_relative_dev_output_uses_an_absolute_output_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            previous_cwd = Path.cwd()

            def write_binary(output, *_args):
                output.write_bytes(b"binary")

            try:
                self.build.os.chdir(root)
                with patch.dict(self.build.os.environ, {"BUILD_DEV_OUTPUT_DIR": "relative-output"}):
                    with patch.object(self.build, "build_binary", side_effect=write_binary):
                        output = self.build.build_development(
                            {"compatible_names": False, "cgo": False},
                            ("linux", "amd64"),
                            root / "cache",
                            "",
                        )
            finally:
                self.build.os.chdir(previous_cwd)

            expected = root / "relative-output" / "Scardice-core"
            self.assertEqual(output, expected)
            self.assertTrue(output.is_absolute())

    def test_interactive_prompts_default_for_sparse_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("builtins.input", side_effect=[""] * 9):
                with patch.object(self.build, "_cache_has_runtime_assets", return_value=False):
                    with patch.object(self.build, "find_command", return_value=None):
                        settings = self.build.interactive_settings(
                            {}, "linux", "amd64", Path(temp_dir)
                        )

        self.assertEqual(settings["version_prerelease"], "-dev")
        self.assertEqual(settings["app_channel"], "dev")
        self.assertEqual(settings["appname"], "Scardice")

    def test_interactive_version_path_is_rejected_before_build(self):
        invalid_settings = {
            "version_main": "../outside",
            "version_prerelease": "-dev",
            "app_channel": "dev",
            "appname": "Scardice",
            "build_mode": "single",
            "targets": ["host/host"],
        }

        with patch.object(self.build, "get_host_target", return_value=("linux", "amd64")):
            with patch.object(self.build, "should_prompt_for_settings", return_value=True):
                with patch.object(self.build, "interactive_settings", return_value=invalid_settings):
                    with patch.object(self.build, "check_cgo_dependencies") as check_cgo:
                        result = self.build.main([])

        self.assertEqual(result, 1)
        check_cgo.assert_not_called()

    def test_version_fields_reject_path_separators(self):
        for key in ("version_main", "version_prerelease"):
            for value in ("../outside", "..\\outside"):
                with self.subTest(key=key, value=value):
                    config = {"default_group": "default", "groups": {"default": {key: value}}}

                    with self.assertRaises(self.build.BuildError):
                        self.build.validate_config(config)

    def test_path_containment_rejects_escaped_package_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "package-work"
            escaped = parent / ".." / "outside"

            with self.assertRaises(self.build.BuildError):
                self.build._ensure_path_within(parent, escaped, "package")


if __name__ == "__main__":
    unittest.main()
