"""Dynamic confidence adjustment — history-based factor computation.

Computes a history_factor from recent verdict history (PERMIT ratio in window).
Used to dynamically adjust confidence thresholds based on agent track record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def compute_history_factor(
    verdicts: list[tuple[str, datetime]],
    window_days: int = 30,
    now: datetime | None = None,
) -> float:
    """Compute history factor from recent verdict history.

    The history factor is the ratio of PERMIT verdicts to total verdicts
    within the lookback window. Higher ratio = better track record.

    Args:
        verdicts: List of (verdict_string, timestamp) tuples.
        window_days: Number of days to look back.
        now: Current time (defaults to UTC now).

    Returns:
        Float between 0.0 and 1.0 representing the PERMIT ratio.
        Returns 0.0 if no verdicts in window.
    """
    if now is None:
        now = datetime.now(UTC)

    cutoff = now - timedelta(days=window_days)

    in_window = [v for v, ts in verdicts if ts >= cutoff]
    if not in_window:
        return 0.0

    permit_count = sum(1 for v in in_window if v == "PERMIT")
    return permit_count / len(in_window)
