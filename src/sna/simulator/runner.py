"""Simulator runner — collects baseline, generates scenarios, feeds SNA API.

Usage:
    sna simulate                    # Run 10 scenarios (default)
    sna simulate --rounds 50        # Run 50 scenarios
    sna simulate --interval 5       # 5 seconds between rounds
    sna simulate --continuous       # Run until stopped
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict

import httpx
import structlog
import yaml

from sna.simulator.baseline import NetworkBaseline, collect_baseline
from sna.simulator.scenarios import EvaluatePayload, pick_scenario

logger = structlog.get_logger()


async def load_inventory_from_yaml(path: str) -> dict[str, dict]:
    """Load the inventory YAML and return device name -> {host, platform} mapping."""
    import aiofiles

    async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
        raw = await f.read()
    data = yaml.safe_load(raw)
    return data.get("devices", {})


async def submit_evaluation(
    client: httpx.AsyncClient,
    api_url: str,
    api_key: str,
    payload: EvaluatePayload,
) -> dict | None:
    """Submit a single evaluation to the SNA API."""
    body = {
        "tool_name": payload.tool_name,
        "confidence_score": payload.confidence_score,
        "device_targets": payload.device_targets,
        "parameters": payload.parameters,
    }

    try:
        resp = await client.post(
            f"{api_url}/evaluate",
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            await logger.aerror(
                "evaluation_failed",
                status=resp.status_code,
                body=resp.text,
                tool=payload.tool_name,
            )
            return None
    except Exception as exc:
        await logger.aerror("evaluation_request_error", error=str(exc))
        return None


def format_verdict(payload: EvaluatePayload, result: dict) -> str:
    """Format a verdict result for console output."""
    verdict = result.get("verdict", "?")
    tier = result.get("risk_tier", "?")
    reason = result.get("reason", "")

    # Color codes
    colors = {"PERMIT": "\033[32m", "ESCALATE": "\033[33m", "BLOCK": "\033[31m"}
    reset = "\033[0m"
    color = colors.get(verdict, "")

    lines = [
        f"  {color}[{verdict}]{reset} {payload.tool_name} → {', '.join(payload.device_targets)}",
        f"         Tier: {tier} | Confidence: {payload.confidence_score:.2f}",
        f"         {payload.scenario_description}",
        f"         Reason: {reason}",
    ]
    return "\n".join(lines)


async def run_simulator(
    rounds: int = 10,
    interval: float = 2.0,
    continuous: bool = False,
    api_url: str = "http://localhost:8001",
    api_key: str | None = None,
    inventory_path: str | None = None,
) -> None:
    """Main simulator loop.

    1. Load inventory
    2. Collect baseline state from all devices
    3. Generate and submit scenarios
    """
    # Resolve config
    if api_key is None:
        api_key = os.environ.get("SNA_API_KEY", "")
    if not api_key:
        print("Error: SNA_API_KEY not set. Pass --api-key or set the environment variable.")
        return

    if inventory_path is None:
        inventory_path = os.environ.get("INVENTORY_FILE_PATH", "./inventory/eveng-lab.yaml")

    username = os.environ.get("SNA_DEVICE_R1_USERNAME", "admin")
    password = os.environ.get("SNA_DEVICE_R1_PASSWORD", "admin")

    # --- Phase 1: Load inventory ---
    print("\n╔══════════════════════════════════════════════════╗")
    print("║       SNA Network Event Simulator               ║")
    print("╚══════════════════════════════════════════════════╝\n")

    print(f"  API:       {api_url}")
    print(f"  Inventory: {inventory_path}")
    print(f"  Rounds:    {'continuous' if continuous else rounds}")
    print(f"  Interval:  {interval}s\n")

    inventory = await load_inventory_from_yaml(inventory_path)
    print(f"  Loaded {len(inventory)} devices from inventory\n")

    # --- Phase 2: Collect baseline ---
    print("  ⏳ Collecting baseline state from all devices...")
    baseline = await collect_baseline(inventory, username, password)
    print(f"  ✓ Baseline collected: {len(baseline.devices)} devices")
    print(f"    Routers:  {', '.join(baseline.routers)}")
    print(f"    Switches: {', '.join(baseline.switches)}")
    print(f"    VLANs in use: {sorted(baseline.used_vlans) if baseline.used_vlans else 'none'}")
    print(f"    Known prefixes: {len(baseline.used_prefixes)}\n")

    # Show interface summary
    for name, state in baseline.devices.items():
        up = sum(1 for i in state.interfaces if i.status == "up")
        down = sum(1 for i in state.interfaces if i.status != "up")
        no_desc = sum(1 for i in state.interfaces if i.status == "up" and not i.has_description)
        protocols = []
        if state.has_ospf:
            protocols.append("OSPF")
        if state.has_bgp:
            protocols.append("BGP")
        proto_str = f" [{', '.join(protocols)}]" if protocols else ""
        print(f"    {name:12s}  {up} up / {down} down  |  {no_desc} missing desc{proto_str}")

    print()

    # --- Phase 3: Run scenarios ---
    print("─" * 60)
    print("  Starting scenario generation...\n")

    stats = {"PERMIT": 0, "ESCALATE": 0, "BLOCK": 0, "errors": 0}
    round_num = 0

    async with httpx.AsyncClient() as client:
        while continuous or round_num < rounds:
            round_num += 1
            payloads = pick_scenario(baseline)

            if not payloads:
                continue

            scenario_name = payloads[0].scenario_name
            print(f"  Round {round_num} — {scenario_name} ({len(payloads)} action{'s' if len(payloads) != 1 else ''})")

            for payload in payloads:
                result = await submit_evaluation(client, api_url, api_key, payload)
                if result:
                    verdict = result.get("verdict", "?")
                    stats[verdict] = stats.get(verdict, 0) + 1
                    print(format_verdict(payload, result))
                else:
                    stats["errors"] += 1

            print()

            if continuous or round_num < rounds:
                await asyncio.sleep(interval)

    # --- Summary ---
    print("─" * 60)
    total = stats["PERMIT"] + stats["ESCALATE"] + stats["BLOCK"]
    print(f"\n  Simulation complete: {total} evaluations across {round_num} rounds\n")
    print(f"    \033[32mPERMIT:   {stats['PERMIT']}\033[0m")
    print(f"    \033[33mESCALATE: {stats['ESCALATE']}\033[0m")
    print(f"    \033[31mBLOCK:    {stats['BLOCK']}\033[0m")
    if stats["errors"]:
        print(f"    Errors:   {stats['errors']}")
    print()
