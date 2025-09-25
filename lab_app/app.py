from __future__ import annotations

from flask import Flask, jsonify, request
import time

app = Flask(__name__)

STATE = {"version": 1, "emulate_5xx": False, "latency_ms": 0, "waf_block": False}
USERS = {"1": {"id": 1, "name": "Alice", "role": "user", "discount": 0.1}, "2": {"id": 2, "name": "Bob", "role": "admin", "discount": 0.2}}
TOKENS = {"valid-user": "1", "valid-admin": "2"}


@app.get("/")
def index():
    if STATE["waf_block"]:
        return "Blocked", 403
    if STATE["latency_ms"]:
        time.sleep(STATE["latency_ms"] / 1000.0)
    return "Lab app OK", 200


@app.get("/api/products")
def products():
    if STATE["waf_block"]:
        return jsonify({"error": "blocked"}), 403
    if STATE["emulate_5xx"]:
        return jsonify({"error": "transient"}), 503
    if STATE["latency_ms"]:
        time.sleep(STATE["latency_ms"] / 1000.0)
    data = [{"id": 1, "name": "Widget"}, {"id": 2, "name": "Gadget"}]
    if STATE["version"] >= 2:
        for d in data:
            d["price"] = 9.99
    return jsonify(data)


@app.get("/api/products/<int:pid>")
def product_detail(pid: int):
    if STATE["waf_block"]:
        return jsonify({"error": "blocked"}), 403
    if STATE["emulate_5xx"]:
        return jsonify({"error": "transient"}), 503
    if STATE["latency_ms"]:
        time.sleep(STATE["latency_ms"] / 1000.0)
    item = {"id": pid, "name": f"Item-{pid}"}
    if STATE["version"] >= 2:
        item["price"] = 4.99 * pid
    return jsonify(item)


@app.post("/admin/drift")
def drift():
    body = request.get_json(silent=True) or {}
    version = int(body.get("version", 1))
    STATE["version"] = version
    return jsonify({"ok": True, "version": version})


@app.post("/admin/emulator")
def emulator():
    body = request.get_json(silent=True) or {}
    STATE["emulate_5xx"] = bool(body.get("emulate_5xx", False))
    STATE["latency_ms"] = int(body.get("latency_ms", 0))
    STATE["waf_block"] = bool(body.get("waf_block", False))
    return jsonify({"ok": True, **STATE})


# PoC: auth bypass (cookie-only; missing server-side check)
@app.get("/poc/admin")
def poc_admin():
    token = request.headers.get("X-Token", "")
    uid = TOKENS.get(token)
    if uid == "2":  # admin
        return jsonify({"admin": True, "message": "Welcome"})
    # flawed: treats presence of any X-Token as authenticated
    if token:
        return jsonify({"admin": False, "message": "Weak bypass"})
    return jsonify({"error": "forbidden"}), 403


# PoC: data leak (over-permissive field exposure via query)
@app.get("/poc/user")
def poc_user():
    uid = request.args.get("id", "1")
    include_internal = request.args.get("internal", "false").lower() == "true"
    user = USERS.get(uid, USERS["1"]).copy()
    if not include_internal:
        user.pop("discount", None)
    return jsonify(user)


# PoC: logic flaw (discount miscalc)
@app.get("/poc/checkout")
def poc_checkout():
    uid = request.args.get("id", "1")
    price = float(request.args.get("price", "100"))
    user = USERS.get(uid, USERS["1"])  # defaults to user
    # flawed: doubles discount if a crafted flag is set
    crafted = request.args.get("crafted", "false").lower() == "true"
    discount = user["discount"] * (2 if crafted else 1)
    total = max(0.0, price * (1 - discount))
    return jsonify({"price": price, "discount": discount, "total": total})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
