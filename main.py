from __future__ import annotations
import argparse, glob as _glob, os, re, sys, time
from pathlib import Path
from typing import List
from modules.config import setup_config
from modules.logging import setup_logger
from modules.platforms.android_rsa import run_android_rsa
from modules.platforms.android import run_android
from modules.platforms.ios import run_ios
from modules.platforms.tv import run_tv
from modules.platforms.tv_otp import run_tv_otp
from modules.platforms.web import run_web
from modules.platforms.mgk import run_mgk

log = setup_logger("MSL HANDSHAKE")


class _ColoredHelpFormatter(argparse.HelpFormatter):
    """HelpFormatter with ANSI colors applied after layout so column widths are unaffected."""

    _RST    = "\033[0m"
    _BOLD   = "\033[1m"
    _CYAN   = "\033[36m"
    _GREEN  = "\033[32m"
    _YELLOW = "\033[33m"

    @staticmethod
    def _tty() -> bool:
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    def _c(self, codes: str, text: str) -> str:
        return f"{codes}{text}{self._RST}" if self._tty() else text

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = self._c(f"{self._YELLOW}{self._BOLD}", "usage") + ": "
        return super()._format_usage(usage, actions, groups, prefix)

    def start_section(self, heading: str | None) -> None:
        if heading:
            heading = self._c(f"{self._CYAN}{self._BOLD}", heading)
        super().start_section(heading)

    def _format_action(self, action: argparse.Action) -> str:
        text = super()._format_action(action)
        if not self._tty():
            return text
        # Color flag/option text (e.g. "-h, --help" or "--platform {…}")
        # Applied after layout so len() calculations are already done.
        return re.sub(
            r"^(\s+)(-\S.*?)(\s{2,}|$)",
            lambda m: m.group(1) + self._c(self._GREEN, m.group(2)) + m.group(3),
            text,
            flags=re.MULTILINE,
        )


class _ColoredArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with colored --help and colored error messages."""

    def error(self, message: str) -> None:
        log.error(message)
        self.print_usage(sys.stderr)
        sys.exit(2)


_WVD_LOOP_DELAY = 10  # seconds between WVD iterations to avoid throttling


def _run_wvd_loop(run_fn, wvd_paths: List[Path], **kwargs) -> None:
    passed: List[str] = []
    failed: List[str] = []
    for wvd_path in wvd_paths:
        if passed or failed:
            log.info("Waiting %ds before next WVD to avoid throttling...", _WVD_LOOP_DELAY)
            time.sleep(_WVD_LOOP_DELAY)
        log.info("--- [%d/%d] WVD: %s ---", len(passed) + len(failed) + 1, len(wvd_paths), wvd_path.name)
        try:
            run_fn(wvd_path=wvd_path, **kwargs)
            passed.append(wvd_path.name)
        except SystemExit:
            failed.append(wvd_path.name)
            log.warning("WVD failed, continuing to next...")
        except Exception as exc:
            failed.append(wvd_path.name)
            log.warning("WVD raised %s: %s — continuing to next...", type(exc).__name__, exc)

    log.info("=== Results: %d/%d passed ===", len(passed), len(wvd_paths))
    for name in passed:
        log.info("  PASS: %s", name)
    for name in failed:
        log.warning("  FAIL: %s", name)

    if not passed:
        sys.exit(1)


def main():
    WVD_PLATFORMS = {"android", "ios", "tv", "tv_otp"}

    parser = _ColoredArgumentParser(
        description="Netflix MSL multi-platform login",
        formatter_class=_ColoredHelpFormatter,
    )
    parser.add_argument("--platform", required=True, choices=["android", "android_rsa", "ios", "tv", "tv_otp", "web", "mgk"], help="Target platform")
    parser.add_argument("--wvd", type=str, help="Path or glob pattern to .wvd file(s) (e.g. devices/*.wvd)")
    parser.add_argument("--kpekph", type=str, default=None, help="KpeKph value (Kpe:Kph) or file path (mgk platform); auto-discovered if omitted")
    parser.add_argument("--esnid", type=str, help="ESN identity string or file path (mgk platform)")
    parser.add_argument("--new-msl", action="store_true", help="Force new MSL key exchange")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS verification")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (e.g. http://ip:port or http://user:pass@ip:port)")

    args = parser.parse_args()

    wvd_paths: List[Path] = []
    if args.platform in WVD_PLATFORMS:
        if not args.wvd:
            parser.error(f"--wvd is required for {args.platform} platform")
        wvd_paths = sorted(
            Path(p) for p in _glob.glob(args.wvd) if p.endswith(".wvd")
        )
        if not wvd_paths:
            parser.error(f"No .wvd files found matching: {args.wvd}")
        log.info("Found %d .wvd file(s) to test", len(wvd_paths))

    kwargs = {"new_msl": args.new_msl, "no_verify": args.no_verify, "proxy": args.proxy}

    if args.platform == "android_rsa":
        run_android_rsa(**kwargs)

    elif args.platform == "android":
        _run_wvd_loop(run_android, wvd_paths, **kwargs)

    elif args.platform == "ios":
        _run_wvd_loop(run_ios, wvd_paths, **kwargs)

    elif args.platform == "tv":
        _run_wvd_loop(run_tv, wvd_paths, **kwargs)

    elif args.platform == "tv_otp":
        _run_wvd_loop(run_tv_otp, wvd_paths, **kwargs)

    elif args.platform == "web":
        run_web(**kwargs)

    elif args.platform == "mgk":
        if not args.esnid:
            parser.error("--esnid is required for mgk platform")
        run_mgk(kpekph_path=args.kpekph, esnid=args.esnid, **kwargs)


if __name__ == "__main__":
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('clear')
    main()
