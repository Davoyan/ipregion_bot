import os

BOT_API_TOKEN = os.getenv("BOT_API_TOKEN")

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")

IPREGISTRY_API_TOKEN = os.getenv("IPREGISTRY_API_TOKEN")

IPQS_API_TOKEN = os.getenv("IPQS_API_TOKEN")
IPQS_WHITELIST = os.getenv("IPQS_WHITELIST", "True").lower() in ("true", "1", "yes")

raw_users = os.getenv("IPQS_WHITELIST_USERS", "")
IPQS_WHITELIST_USERS = [int(u.strip()) for u in raw_users.split(",") if u.strip()]

MAXMIND_DB_CITY_URL = os.getenv("MAXMIND_DB_CITY_URL")
MAXMIND_DB_ASN_URL = os.getenv("MAXMIND_DB_ASN_URL")

MAXMIND_DB_CITY = "/app/databases/GeoLite2-City.mmdb"
MAXMIND_DB_ASN  = "/app/databases/GeoLite2-ASN.mmdb"