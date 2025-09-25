from __future__ import annotations

from flask import Flask, jsonify, request
import time

app = Flask(__name__)

STATE = {"version": 1, "emulate_5xx": False, "latency_ms": 0, "waf_block": False}


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
