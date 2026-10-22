"""Settings. Every value can be overridden with an environment variable."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _f(name: str, default: float) -> float:
    return float(os.getenv(name, default))


def _b(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Thresholds
    rx_low_warn_dbm: float = _f("RX_LOW_WARN_DBM", -10.0)     # optic receive power: preventive warning
    rx_low_alarm_dbm: float = _f("RX_LOW_ALARM_DBM", -13.0)   # near the receiver's low-power alarm
    crc_per_min: float = _f("CRC_PER_MIN", 50)                # input/CRC errors per minute that count as degradation
    util_high_pct: float = _f("UTIL_HIGH_PCT", 85)            # circuit utilisation alarm
    re_cpu_high_pct: float = _f("RE_CPU_HIGH_PCT", 85)        # routing engine CPU alarm
    temp_high_c: float = _f("TEMP_HIGH_C", 60)                # chassis temperature alarm
    bgp_flap_count: int = int(_f("BGP_FLAP_COUNT", 3))         # flaps in the last hour that count as flapping

    # AI
    ai_provider: str = os.getenv("AI_PROVIDER", "auto")        # auto | mock | anthropic
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY")
    ai_model: str = os.getenv("AI_MODEL", "claude-sonnet-4-5")

    # Slack (mock unless a webhook URL is set)
    slack_webhook_url: str | None = os.getenv("SLACK_WEBHOOK_URL") or None
    slack_channel: str = os.getenv("SLACK_CHANNEL", "#noc-core")
    alert_min_severity: str = os.getenv("ALERT_MIN_SEVERITY", "P2")   # page/alert on P1..this
    public_url: str = os.getenv("PUBLIC_URL", "http://localhost:8000")

    # On-call escalation: real seconds per escalation minute (60 = real time; lower it for demos)
    escalation_minute_seconds: float = _f("ESCALATION_MINUTE_SECONDS", 60)

    # Simulator
    sim_enabled: bool = _b("SIM_ENABLED", True)
    sim_interval_seconds: float = _f("SIM_INTERVAL_SECONDS", 15)
    sim_fault_chance: float = _f("SIM_FAULT_CHANCE", 0.12)
    sim_seed: int = int(_f("SIM_SEED", 7))

    # Optional live lab (NETCONF to real or virtual Junos devices). Empty = mock network.
    # Format: "r1=172.20.20.2,r2=172.20.20.3"
    lab_devices: str = os.getenv("LAB_DEVICES", "")
    lab_username: str = os.getenv("LAB_USERNAME", "")
    lab_password: str = os.getenv("LAB_PASSWORD", "")
    lab_ssh_key: str = os.getenv("LAB_SSH_KEY", "")
    lab_poll_seconds: float = _f("LAB_POLL_SECONDS", 30)


settings = Settings()
