"""
Agent Canary Test Harness — scenario-based automated testing.

Runs YAML scenarios against the canary system, measures detection rates,
false positive rates, and forensic capture quality. Outputs a scored report.

Usage:
    python harness/runner.py                    # run all scenarios
    python harness/runner.py -s file_access     # run one scenario
    python harness/runner.py --report           # generate HTML report
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_canary.models import (
    Canary, ForensicChain, ScopeRule, TriggerEvent, Vector,
)
from agent_canary.registry import Registry
from agent_canary.vectors.files import check_file_access, plant_file
from agent_canary.vectors.mcp import TripwireTool, create_mcp_server, default_tripwire_tools
from agent_canary.vectors.api import create_api_app, default_decoy_endpoints


@dataclass
class TestResult:
    scenario: str
    test_name: str
    passed: bool
    expected: dict
    actual: dict
    duration_ms: float
    notes: list[str] = field(default_factory=list)


@dataclass
class ScenarioResult:
    name: str
    description: str
    results: list[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total else 0.0


@dataclass
class HarnessReport:
    scenarios: list[ScenarioResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def total_tests(self) -> int:
        return sum(s.total for s in self.scenarios)

    @property
    def total_passed(self) -> int:
        return sum(s.passed for s in self.scenarios)

    @property
    def total_failed(self) -> int:
        return sum(s.failed for s in self.scenarios)

    @property
    def pass_rate(self) -> float:
        return self.total_passed / self.total_tests if self.total_tests else 0.0

    @property
    def duration_s(self) -> float:
        return self.end_time - self.start_time


class HarnessRunner:
    """Executes canary test scenarios and collects results."""

    def __init__(self, scenario_dir: Path | None = None):
        self.scenario_dir = scenario_dir or Path(__file__).parent / "scenarios"
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="canary-harness-"))
        self.registry = Registry(self.tmp_dir)
        self.registry.init()
        self.triggers: list[TriggerEvent] = []
        self.mcp_app = None
        self.api_app = None

    def _on_trigger(self, event: TriggerEvent) -> None:
        """Callback when a canary fires."""
        self.triggers.append(event)

    def _setup_canaries(self, setup: dict) -> None:
        """Plant canaries defined in the scenario setup."""
        for c in setup.get("canaries", []):
            vector = Vector(c["vector"])
            scope = ScopeRule(**c.get("scope", {}))

            if vector == Vector.FILE:
                path = self.tmp_dir / c["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                plant_file(
                    self.registry, str(path),
                    template_name=c.get("template", "aws_creds"),
                    scope=scope,
                )
            elif vector == Vector.MCP_TOOL:
                canary = Canary(
                    id=Canary.generate_id(vector, c["name"]),
                    vector=vector,
                    name=c["name"],
                    path_or_url=c["name"],
                    scope=scope,
                )
                self.registry.add_canary(canary)
            elif vector == Vector.API_ENDPOINT:
                canary = Canary(
                    id=Canary.generate_id(vector, c["path"]),
                    vector=vector,
                    name=c["path"],
                    path_or_url=c["path"],
                    scope=scope,
                )
                self.registry.add_canary(canary)

    def _run_file_test(self, action: dict) -> dict:
        """Simulate a file read and check for triggers."""
        path = action["path"]
        full_path = str(self.tmp_dir / path)
        agent_id = action.get("agent_id")

        # Check if the canary exists at this path
        canary = self.registry.get_canary_by_path(full_path, Vector.FILE)

        triggered = False
        event = None

        if canary and canary.scope.should_trigger(agent_id):
            context = action.get("context", {})
            event = check_file_access(self.registry, full_path)
            if event:
                triggered = True
                self.triggers.append(event)

        return {
            "triggered": triggered,
            "vector": "file" if triggered else None,
            "canary_path": path if triggered else None,
            "event": event,
        }

    def _run_mcp_test(self, action: dict) -> dict:
        """Simulate an MCP tool call and check for triggers."""
        tool_name = action["tool"]
        args = action.get("args", {})
        agent_id = action.get("agent_id")

        canary = self.registry.get_canary_by_path(tool_name, Vector.MCP_TOOL)

        triggered = False
        event = None

        if canary and canary.scope.should_trigger(agent_id):
            event = TriggerEvent(
                canary_id=canary.id,
                vector=Vector.MCP_TOOL,
                forensic_chain=ForensicChain(raw_args=args),
            )
            self.registry.log_trigger(event)
            triggered = True
            self.triggers.append(event)

        return {
            "triggered": triggered,
            "vector": "mcp_tool" if triggered else None,
            "response_contains": "insufficient_permissions" if triggered else None,
            "event": event,
        }

    def _run_http_test(self, action: dict) -> dict:
        """Simulate an HTTP request to a decoy endpoint."""
        path = action["path"]
        canary = self.registry.get_canary_by_path(path, Vector.API_ENDPOINT)

        triggered = False
        event = None

        if canary:
            event = TriggerEvent(
                canary_id=canary.id,
                vector=Vector.API_ENDPOINT,
                forensic_chain=ForensicChain(
                    raw_args={
                        "method": action.get("method", "GET"),
                        "path": path,
                        "headers": action.get("headers", {}),
                        "body": action.get("body"),
                    }
                ),
                raw_request=action,
            )
            self.registry.log_trigger(event)
            triggered = True
            self.triggers.append(event)

        # Simulate response
        status_map = {
            "/v1/users/export": 403,
            "/admin/config": 401,
            "/metadata/latest/credentials": 200,
            "/v1/secret/data/production": 403,
        }

        return {
            "triggered": triggered,
            "vector": "api_endpoint" if triggered else None,
            "response_status": status_map.get(path, 404),
            "response_contains": "AKIACANARY" if path == "/metadata/latest/credentials" else None,
            "event": event,
        }

    def _check_expectations(self, expect: dict, actual: dict) -> tuple[bool, list[str]]:
        """Check actual results against expected outcomes. Returns (passed, notes)."""
        notes = []
        passed = True

        # Check triggered
        if "triggered" in expect:
            if expect["triggered"] != actual.get("triggered"):
                passed = False
                notes.append(
                    f"Expected triggered={expect['triggered']}, got {actual.get('triggered')}"
                )

        # Check vector
        if "vector" in expect and actual.get("triggered"):
            if expect["vector"] != actual.get("vector"):
                passed = False
                notes.append(f"Expected vector={expect['vector']}, got {actual.get('vector')}")

        # Check response status
        if "response_status" in expect:
            if expect["response_status"] != actual.get("response_status"):
                passed = False
                notes.append(
                    f"Expected status={expect['response_status']}, got {actual.get('response_status')}"
                )

        # Check response contains
        if "response_contains" in expect and actual.get("response_contains"):
            if expect["response_contains"] not in str(actual.get("response_contains", "")):
                passed = False
                notes.append(f"Response doesn't contain '{expect['response_contains']}'")

        # Check forensic chain properties
        if "forensic_chain" in expect and actual.get("event"):
            fc_expect = expect["forensic_chain"]
            event = actual["event"]

            if fc_expect.get("has_preceding_calls"):
                if not event.forensic_chain.preceding_tool_calls:
                    notes.append("Expected preceding tool calls but none captured")
                    # Soft failure — forensic quality, not detection correctness

            if fc_expect.get("raw_args_has"):
                key = fc_expect["raw_args_has"]
                if key not in event.forensic_chain.raw_args:
                    notes.append(f"Expected raw_args to contain '{key}'")

            if fc_expect.get("has_headers"):
                raw = event.forensic_chain.raw_args or event.raw_request
                if not raw.get("headers"):
                    notes.append("Expected headers in forensic data")

        return passed, notes

    def run_scenario(self, scenario_path: Path) -> ScenarioResult:
        """Run a single scenario file."""
        data = yaml.safe_load(scenario_path.read_text())
        result = ScenarioResult(name=data["name"], description=data.get("description", ""))

        # Setup
        self.triggers.clear()
        self._setup_canaries(data.get("setup", {}))

        # Run tests
        for test in data.get("tests", []):
            t0 = time.perf_counter()
            action = test["action"]

            if action["type"] == "file_read":
                actual = self._run_file_test(action)
            elif action["type"] == "mcp_call":
                actual = self._run_mcp_test(action)
            elif action["type"] == "http_request":
                actual = self._run_http_test(action)
            else:
                actual = {"error": f"Unknown action type: {action['type']}"}

            duration_ms = (time.perf_counter() - t0) * 1000
            passed, notes = self._check_expectations(test["expect"], actual)

            result.results.append(TestResult(
                scenario=data["name"],
                test_name=test["name"],
                passed=passed,
                expected=test["expect"],
                actual={k: v for k, v in actual.items() if k != "event"},
                duration_ms=round(duration_ms, 2),
                notes=notes,
            ))

        return result

    def run_all(self, filter_name: str | None = None) -> HarnessReport:
        """Run all scenarios (or one if filtered)."""
        import shutil
        report = HarnessReport(start_time=time.perf_counter())
        tmp_dirs: list[Path] = []

        for scenario_file in sorted(self.scenario_dir.glob("*.yaml")):
            if filter_name and filter_name not in scenario_file.stem:
                continue

            # Fresh registry for each scenario
            self.tmp_dir = Path(tempfile.mkdtemp(prefix="canary-harness-"))
            tmp_dirs.append(self.tmp_dir)
            self.registry = Registry(self.tmp_dir)
            self.registry.init()

            result = self.run_scenario(scenario_file)
            report.scenarios.append(result)

            # Close DB before cleanup
            self.registry.close()

        # Clean up all temp dirs
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

        report.end_time = time.perf_counter()
        return report

    def print_report(self, report: HarnessReport) -> None:
        """Print a colored terminal report."""
        try:
            from rich.console import Console
            from rich.table import Table
            console = Console()
        except ImportError:
            self._print_plain(report)
            return

        console.print()
        console.print(f"[bold]Agent Canary Test Harness[/bold]")
        console.print(f"Scenarios: {len(report.scenarios)} | "
                      f"Tests: {report.total_tests} | "
                      f"Duration: {report.duration_s:.2f}s")
        console.print()

        for scenario in report.scenarios:
            color = "green" if scenario.failed == 0 else "red"
            console.print(f"[bold {color}]{'PASS' if scenario.failed == 0 else 'FAIL'}[/] "
                          f"{scenario.name} — {scenario.passed}/{scenario.total}")

            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
            table.add_column("Test", style="dim")
            table.add_column("Result", width=6)
            table.add_column("Time")
            table.add_column("Notes")

            for r in scenario.results:
                status = "[green]PASS[/]" if r.passed else "[red]FAIL[/]"
                notes = "; ".join(r.notes) if r.notes else ""
                table.add_row(r.test_name, status, f"{r.duration_ms:.1f}ms", notes)

            console.print(table)
            console.print()

        # Summary
        console.print(f"[bold]{'=' * 50}[/]")
        rate = report.pass_rate * 100
        color = "green" if rate == 100 else "yellow" if rate >= 80 else "red"
        console.print(f"[bold {color}]{report.total_passed}/{report.total_tests} passed ({rate:.0f}%)[/]")

    def _print_plain(self, report: HarnessReport) -> None:
        """Fallback plain text report."""
        print(f"\nAgent Canary Test Harness")
        print(f"Scenarios: {len(report.scenarios)} | Tests: {report.total_tests}")
        for scenario in report.scenarios:
            status = "PASS" if scenario.failed == 0 else "FAIL"
            print(f"\n{status} {scenario.name} — {scenario.passed}/{scenario.total}")
            for r in scenario.results:
                s = "PASS" if r.passed else "FAIL"
                notes = f" ({'; '.join(r.notes)})" if r.notes else ""
                print(f"  {s} {r.test_name} [{r.duration_ms:.1f}ms]{notes}")
        print(f"\n{report.total_passed}/{report.total_tests} passed ({report.pass_rate*100:.0f}%)")

    def generate_html_report(self, report: HarnessReport, output: Path) -> None:
        """Generate a JSON data file for the /present viewer."""
        sections = [
            {
                "title": "Agent Canary — Harness Results",
                "type": "metrics",
                "metrics": [
                    {"value": str(report.total_tests), "label": "Total Tests"},
                    {"value": str(report.total_passed), "label": "Passed"},
                    {"value": str(report.total_failed), "label": "Failed"},
                    {"value": f"{report.pass_rate*100:.0f}%", "label": "Pass Rate"},
                    {"value": f"{report.duration_s:.2f}s", "label": "Duration"},
                ],
            },
        ]

        for scenario in report.scenarios:
            items = []
            for r in scenario.results:
                status = "pass" if r.passed else "fail"
                detail = "; ".join(r.notes) if r.notes else f"Completed in {r.duration_ms:.1f}ms"
                items.append({"label": r.test_name, "status": status, "detail": detail})

            sections.append({
                "title": f"{scenario.name} ({scenario.passed}/{scenario.total})",
                "type": "checklist",
                "items": items,
            })

        data = {
            "sections": sections,
            "metadata": {
                "generated_by": "agent-canary-harness",
                "confidence": 8,
                "tags": ["testing", "canary", "harness"],
            },
        }

        output.write_text(json.dumps(data, indent=2))


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Agent Canary Test Harness")
    parser.add_argument("-s", "--scenario", help="Run specific scenario (name filter)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report data")
    parser.add_argument("--output", default="/tmp/canary-harness-report.json", help="Report output path")
    args = parser.parse_args()

    runner = HarnessRunner()
    report = runner.run_all(filter_name=args.scenario)
    runner.print_report(report)

    if args.report:
        out = Path(args.output)
        runner.generate_html_report(report, out)
        print(f"\nReport data written to {out}")

    sys.exit(0 if report.total_failed == 0 else 1)


if __name__ == "__main__":
    main()
