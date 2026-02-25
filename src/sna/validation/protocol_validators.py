"""Routing protocol session state validators.

Post-change validators that verify BGP/OSPF sessions and routing tables
are healthy after configuration changes.
"""

from __future__ import annotations

from sna.validation.parsers import parse_bgp_summary, parse_ospf_neighbors, parse_routing_table
from sna.validation.validator import ValidationResult, ValidationStatus, Validator


class BGPNeighborUpValidator(Validator):
    """Validates BGP neighbor sessions are in Established state after changes.

    Checks after_state["bgp_summary"] for neighbor session state.
    PASS if all neighbors are Established, FAIL if any are Down/Idle/Active.
    SKIP if no bgp_summary in state.
    """

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="bgp_neighbor_up",
                message="After state not available",
            )

        bgp_output = after_state.get("bgp_summary")
        if bgp_output is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="bgp_neighbor_up",
                message="No bgp_summary in after state",
            )

        neighbors = parse_bgp_summary(str(bgp_output))
        if not neighbors:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="bgp_neighbor_up",
                message="No BGP neighbors found in output",
            )

        non_established = [n for n in neighbors if n.state != "Established"]
        if non_established:
            details = {
                "failed_neighbors": [
                    {"neighbor": n.neighbor, "state": n.state, "remote_as": n.remote_as}
                    for n in non_established
                ],
            }
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="bgp_neighbor_up",
                message=f"{len(non_established)} BGP neighbor(s) not Established on {device_target}",
                details=details,
            )

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="bgp_neighbor_up",
            message=f"All {len(neighbors)} BGP neighbor(s) Established on {device_target}",
        )


class OSPFNeighborValidator(Validator):
    """Validates OSPF neighbor adjacencies are in FULL state after changes.

    PASS if all neighbors are FULL, FAIL if any are not FULL.
    SKIP if no ospf_neighbors in state.
    """

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="ospf_neighbor_full",
                message="After state not available",
            )

        ospf_output = after_state.get("ospf_neighbors")
        if ospf_output is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="ospf_neighbor_full",
                message="No ospf_neighbors in after state",
            )

        neighbors = parse_ospf_neighbors(str(ospf_output))
        if not neighbors:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="ospf_neighbor_full",
                message="No OSPF neighbors found in output",
            )

        non_full = [n for n in neighbors if n.state != "FULL"]
        if non_full:
            details = {
                "failed_neighbors": [
                    {"neighbor_id": n.neighbor_id, "state": n.state, "interface": n.interface}
                    for n in non_full
                ],
            }
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="ospf_neighbor_full",
                message=f"{len(non_full)} OSPF neighbor(s) not FULL on {device_target}",
                details=details,
            )

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="ospf_neighbor_full",
            message=f"All {len(neighbors)} OSPF neighbor(s) FULL on {device_target}",
        )


class PrefixCountValidator(Validator):
    """Validates BGP prefix count is within expected range after changes.

    PASS if prefix count > 0 and within tolerance of before_state count.
    FAIL if prefix count dropped to 0 or decreased > 50%.
    SKIP if no bgp_summary in state.
    """

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="prefix_count",
                message="After state not available",
            )

        after_output = after_state.get("bgp_summary")
        if after_output is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="prefix_count",
                message="No bgp_summary in after state",
            )

        after_neighbors = parse_bgp_summary(str(after_output))
        after_total = sum(n.prefixes_received for n in after_neighbors)

        if after_total == 0:
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="prefix_count",
                message=f"BGP prefix count dropped to 0 on {device_target}",
                details={"after_prefix_count": 0},
            )

        # Compare with before state if available
        if before_state and before_state.get("bgp_summary"):
            before_neighbors = parse_bgp_summary(str(before_state["bgp_summary"]))
            before_total = sum(n.prefixes_received for n in before_neighbors)

            if before_total > 0 and after_total < before_total * 0.5:
                return ValidationResult(
                    status=ValidationStatus.FAIL,
                    testcase_name="prefix_count",
                    message=(
                        f"BGP prefix count dropped >50% on {device_target}: "
                        f"{before_total} → {after_total}"
                    ),
                    details={
                        "before_prefix_count": before_total,
                        "after_prefix_count": after_total,
                    },
                )

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="prefix_count",
            message=f"BGP prefix count healthy on {device_target}: {after_total} prefixes",
            details={"after_prefix_count": after_total},
        )


class RouteConvergenceValidator(Validator):
    """Validates routing table contains expected routes after changes.

    Checks that all prefixes present in before_state routing table
    are still present in after_state. PASS if all preserved.
    FAIL if any prefixes are missing.
    """

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if before_state is None or after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="route_convergence",
                message="Before/after state not available",
            )

        before_output = before_state.get("routing_table")
        after_output = after_state.get("routing_table")

        if before_output is None or after_output is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="route_convergence",
                message="No routing_table in state",
            )

        before_routes = parse_routing_table(str(before_output))
        after_routes = parse_routing_table(str(after_output))

        before_prefixes = {r.prefix for r in before_routes}
        after_prefixes = {r.prefix for r in after_routes}

        missing = before_prefixes - after_prefixes
        if missing:
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="route_convergence",
                message=f"{len(missing)} route(s) missing after change on {device_target}",
                details={"missing_prefixes": sorted(missing)},
            )

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="route_convergence",
            message=f"All {len(before_prefixes)} route(s) preserved on {device_target}",
        )
