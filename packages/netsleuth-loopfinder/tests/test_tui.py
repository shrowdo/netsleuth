"""Pilot tests for the loop-finder TUI and the NetSleuth menu app."""

import asyncio
import json
import os

import pytest

pytest.importorskip("textual")

from textual.widgets import Checkbox, Input, Static  # noqa: E402

from netsleuth_loopfinder.tui import (  # noqa: E402
    LoopFinderTUI,
    ResultsScreen,
    RunningScreen,
    SetupScreen,
    demo_topology_path,
)

SIZE = (80, 24)


def run(coro):
    return asyncio.run(coro)


async def _wait_for(pilot, predicate, timeout=20.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError(f"timed out; current screen: {pilot.app.screen!r}")
        await pilot.pause(0.05)


def _static_text(screen, selector) -> str:
    return str(screen.query_one(selector, Static).render())


async def _run_demo(pilot):
    app = pilot.app
    await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
    app.screen.query_one("#lf-demo", Checkbox).value = True
    await pilot.pause()
    await pilot.press("ctrl+r")
    await _wait_for(pilot, lambda: isinstance(app.screen, ResultsScreen))
    return app.screen


def test_setup_validates_bad_input():
    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            screen = app.screen
            screen.query_one("#lf-host", Input).value = "not-an-ip"
            await pilot.press("ctrl+r")
            await pilot.pause()
            assert isinstance(app.screen, SetupScreen)
            err = _static_text(screen, "#lf-error")
            assert "not an IPv4 address" in err
            assert "username" in err.lower()

            screen.query_one("#lf-host", Input).value = "10.0.0.1"
            screen.query_one("#lf-port", Input).value = "70000"
            screen.query_one("#lf-username", Input).value = "admin"
            await pilot.press("ctrl+r")
            await pilot.pause()
            assert isinstance(app.screen, SetupScreen)
            assert "port" in _static_text(screen, "#lf-error").lower()

    run(scenario())


def test_enter_moves_between_fields_and_typing_q_does_not_quit():
    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            await pilot.press("q", "enter")  # host field: 'q' is text, Enter -> next field
            await pilot.pause()
            assert app.is_running
            assert app.screen.query_one("#lf-host", Input).value == "q"
            assert app.focused is app.screen.query_one("#lf-username", Input)

    run(scenario())


def test_demo_mode_reaches_results_with_critical_verdict():
    assert os.path.exists(demo_topology_path())

    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            screen = await _run_demo(pilot)
            level, _ = screen.result.verdict
            assert level == "critical"
            banner = _static_text(screen, "#lf-verdict")
            assert "PROBLEM FOUND" in banner
            assert screen.query_one("#lf-verdict").has_class("lf-critical")
            # Results render and scroll without error.
            await pilot.press("end")
            await pilot.pause()
            # n = new scan: back to setup with the form intact.
            await pilot.press("n")
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            assert app.screen.query_one("#lf-demo", Checkbox).value is True

    run(scenario())


def test_export_writes_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            screen = await _run_demo(pilot)
            await pilot.press("e")
            await pilot.pause()
            return screen.last_export

    path = run(scenario())
    assert path == str(tmp_path / "results.json")
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert data["verdict"]["level"] == "critical"
    assert data["actions"]


def test_worker_error_is_shown_not_crash():
    def boom(log, found, failed):
        log("[green]about to fail [unclosed markup[/green]")
        raise RuntimeError("SSH exploded")

    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            running = RunningScreen(boom, "test", live=True)
            app.push_screen(running)
            await _wait_for(pilot, lambda: running.done)
            assert "SSH exploded" in running.error
            assert app.screen is running
            await pilot.press("escape")
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))

    run(scenario())


def test_cancel_stops_late_results():
    import threading

    release = threading.Event()

    def slow(log, found, failed):
        release.wait(10)
        from netsleuth_loopfinder.analysis import run_mock
        return run_mock(demo_topology_path())

    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            running = RunningScreen(slow, "test", live=False)
            app.push_screen(running)
            await pilot.pause()
            await pilot.press("escape")
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            release.set()
            await pilot.pause(0.5)
            assert isinstance(app.screen, SetupScreen)

    run(scenario())


def test_netsleuth_app_opens_loop_finder_and_escape_returns():
    netsleuth_app = pytest.importorskip("netsleuth.tui.app")

    async def scenario():
        app = netsleuth_app.NetSleuthApp()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, netsleuth_app.HomeScreen))
            await pilot.press("enter")
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            assert "netsleuth lf --listen" in _static_text(app.screen, "#lf-hint")
            await pilot.press("escape")
            await _wait_for(pilot, lambda: isinstance(app.screen, netsleuth_app.HomeScreen))
            assert app.is_running
            # And the full demo flow works in-process inside the menu app too.
            await pilot.press("enter")
            await _run_demo(pilot)

    run(scenario())


def test_standalone_escape_quits():
    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            await pilot.press("escape")
            await pilot.pause()
            return app.is_running

    assert run(scenario()) is False


def test_scan_network_lists_hosts_with_banner(monkeypatch):
    from textual.widgets import Select

    import netsleuth_loopfinder.scan as scan

    monkeypatch.setattr(scan, "get_local_subnets", lambda: ["10.9.9.0/24"])
    monkeypatch.setattr(scan, "scan_subnet_for_ssh", lambda subnet, with_banner=True: [
        {"ip": "10.9.9.1", "banner": "SSH-2.0-Cisco-1.25"},
        {"ip": "10.9.9.2", "banner": "SSH-2.0-OpenSSH_8.0"},
    ])

    async def scenario():
        app = LoopFinderTUI()
        async with app.run_test(size=SIZE) as pilot:
            await _wait_for(pilot, lambda: isinstance(app.screen, SetupScreen))
            screen = app.screen
            screen.action_scan_network()
            await _wait_for(pilot, lambda: not screen._scanning)
            assert "Found 2" in _static_text(screen, "#lf-scan-status")
            select = screen.query_one("#lf-scan-select", Select)
            select.value = "10.9.9.2"
            await pilot.pause()
            assert screen.query_one("#lf-host", Input).value == "10.9.9.2"

    run(scenario())
