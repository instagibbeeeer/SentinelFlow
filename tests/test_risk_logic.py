def risk(failed=0, priv=0, download=0, countries=1):
    return min(1.0, failed*.055 + priv*.25 + (.30 if download>1_000_000_000 else 0) + (.10 if countries>1 else 0))

def test_attack_crosses_threshold():
    assert risk(failed=14, priv=1, download=5_100_000_000, countries=2) >= .9

def test_normal_does_not_cross_threshold():
    assert risk(failed=1, priv=0, download=20_000_000, countries=1) < .65
