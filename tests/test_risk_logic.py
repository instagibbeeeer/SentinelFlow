from conftest import load_module

risk = load_module("sentinelflow_risk", "spark/risk.py")


def test_attack_crosses_threshold():
    assert risk.score_risk(failed_logins=14, privilege_changes=1, download_bytes=5_100_000_000, countries=1) >= .9


def test_normal_activity_stays_below_threshold():
    assert risk.score_risk(failed_logins=1, privilege_changes=0, download_bytes=20_000_000, countries=1) < risk.ALERT_THRESHOLD


def test_risk_is_capped_at_one():
    assert risk.score_risk(failed_logins=100, privilege_changes=10, download_bytes=10_000_000_000, countries=4) == 1.0


def test_reason_generation_matches_signals():
    reasons = risk.alert_reasons(14, 1, 5_100_000_000, 2)
    assert "14 failed logins" in reasons
    assert "privilege change" in reasons
    assert "large download 5100000000 bytes" in reasons
    assert "multiple countries" in reasons
