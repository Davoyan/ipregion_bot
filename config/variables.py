import os


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


BOT_API_TOKEN = os.getenv("BOT_API_TOKEN")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
IPREGISTRY_API_TOKEN = os.getenv("IPREGISTRY_API_TOKEN")
MAXMIND_DB_CITY_URL = os.getenv("MAXMIND_DB_CITY_URL")
MAXMIND_DB_ASN_URL = os.getenv("MAXMIND_DB_ASN_URL")

MAXMIND_DB_CITY = "/app/databases/GeoLite2-City.mmdb"
MAXMIND_DB_ASN = "/app/databases/GeoLite2-ASN.mmdb"

ENABLE_SUBSCRIPTION_CHECK = _as_bool(os.getenv("ENABLE_SUBSCRIPTION_CHECK"))
OUTBOUND_PROXY = (os.getenv("OUTBOUND_PROXY") or "").strip() or None
