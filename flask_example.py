import ipaddress
from flask import Flask, request, jsonify
from http_blocker import HTTPBlocker, BlockRule, make_default_rules

app = Flask(__name__)
blocker = HTTPBlocker(default_allow=True)
blocker.set_rate_limit(max_reqs=120, window=60)

# Start with default attack signatures
for r in make_default_rules():
    blocker.add_rule(r)

# Lock /admin/ to the corporate LAN only
blocker.add_rule(BlockRule(
    name="admin-lockdown",
    path_regex=__import__("re").compile(r"^/admin/"),
    ip_cidrs_exclude=[ipaddress.ip_network("10.0.0.0/8")],
    status=404,   # 404 not 403 so we don't confirm the path exists
))

# Block write methods on /public/*
blocker.add_rule(BlockRule(
    name="public-readonly",
    methods={"POST", "PUT", "PATCH", "DELETE"},
    path_regex=__import__("re").compile(r"^/public/"),
    status=405,
))


@app.before_request
def _check_request():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
    client_ip = client_ip.split(",")[0].strip()

    body = request.get_data(cache=True) if request.method in ("POST", "PUT", "PATCH") else b""

    decision = blocker.inspect(
        request.method,
        request.path,
        client_ip,
        dict(request.headers),
        body,
    )
    if not decision.allow:
        return jsonify({
            "error": "request blocked",
            "reason": decision.reason,
        }), decision.status


@app.get("/")
def home():
    return {"ok": True}


@app.get("/admin/dashboard")
def admin_dashboard():
    return {"admin": True}


@app.get("/public/info")
def public_info():
    return {"public": True}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
