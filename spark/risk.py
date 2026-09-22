FAILED_LOGIN_WEIGHT = 0.055
PRIVILEGE_CHANGE_WEIGHT = 0.25
LARGE_DOWNLOAD_WEIGHT = 0.30
MULTI_COUNTRY_WEIGHT = 0.10
LARGE_DOWNLOAD_BYTES = 1_000_000_000
ALERT_THRESHOLD = 0.65


def score_risk(failed_logins=0, privilege_changes=0, download_bytes=0, countries=1):
    score = failed_logins * FAILED_LOGIN_WEIGHT + privilege_changes * PRIVILEGE_CHANGE_WEIGHT
    if download_bytes > LARGE_DOWNLOAD_BYTES:
        score += LARGE_DOWNLOAD_WEIGHT
    if countries > 1:
        score += MULTI_COUNTRY_WEIGHT
    return min(1.0, score)


def alert_reasons(failed_logins=0, privilege_changes=0, download_bytes=0, countries=1):
    reasons = []
    if failed_logins >= 8:
        reasons.append(f"{failed_logins} failed logins")
    if privilege_changes:
        reasons.append("privilege change")
    if download_bytes > LARGE_DOWNLOAD_BYTES:
        reasons.append(f"large download {download_bytes} bytes")
    if countries > 1:
        reasons.append("multiple countries")
    return reasons
