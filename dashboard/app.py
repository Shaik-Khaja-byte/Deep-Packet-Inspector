import json
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from .inspector import inspect_pcap
from .runner import run_engine


BLOCK_APPS = ["YouTube", "Instagram", "Facebook", "Discord", "GitHub", "Spotify"]


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024
    data_dir = Path(app.instance_path) / "analyses"
    data_dir.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html", block_apps=BLOCK_APPS)

    @app.get("/debug")
    def debug():
        return render_template("debug.html")

    @app.post("/api/analyze")
    def analyze():
        uploaded = request.files.get("pcap")
        if not uploaded or uploaded.filename == "":
            return jsonify({"error": "Upload a PCAP file first."}), 400

        selected_apps = request.form.getlist("block_apps")
        analysis_id = uuid.uuid4().hex
        analysis_dir = data_dir / analysis_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        input_name = secure_filename(uploaded.filename) or "capture.pcap"
        input_path = analysis_dir / input_name
        output_path = analysis_dir / "output.pcap"
        uploaded.save(input_path)

        engine = run_engine(input_path, output_path, selected_apps)
        inspected = inspect_pcap(input_path, selected_apps)

        domains = _merge_domains(engine.get("domains", []), inspected.get("domains", []))
        result = {
            "id": analysis_id,
            "input_file": input_name,
            "blocked_apps": selected_apps,
            "statistics": engine["statistics"],
            "applications": engine["applications"],
            "domains": domains,
            "packets": inspected["packets"],
            "dns": inspected["dns"],
            "flows": inspected["flows"],
            "quic": inspected["quic"],
            "block_summary": {
                "blocked_application": ", ".join(selected_apps) if selected_apps else "None",
                "packets_removed": engine["statistics"].get("dropped", 0),
                "remaining_packets": engine["statistics"].get("forwarded", 0),
            },
            "logs": engine["logs"],
            "engine": {
                "return_code": engine["return_code"],
                "stderr": engine["stderr"],
                "command": engine["command"],
            },
            "downloads": {
                "pcap": f"/download/output/{analysis_id}",
                "json": f"/download/json/{analysis_id}",
            },
        }

        result_path = analysis_dir / "analysis.json"
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return jsonify(result), 500 if engine["return_code"] else 200

    @app.get("/api/results/<analysis_id>")
    def results(analysis_id):
        path = data_dir / analysis_id / "analysis.json"
        if not path.exists():
            return jsonify({"error": "Analysis not found."}), 404
        return send_file(path, mimetype="application/json")

    @app.get("/download/output/<analysis_id>")
    def download_output(analysis_id):
        path = data_dir / analysis_id / "output.pcap"
        if not path.exists():
            return jsonify({"error": "Output PCAP not found."}), 404
        return send_file(path, as_attachment=True, download_name="output.pcap")

    @app.get("/download/json/<analysis_id>")
    def download_json(analysis_id):
        path = data_dir / analysis_id / "analysis.json"
        if not path.exists():
            return jsonify({"error": "Analysis JSON not found."}), 404
        return send_file(path, as_attachment=True, download_name="analysis.json")

    return app


def _merge_domains(*domain_lists):
    merged = {}
    for domains in domain_lists:
        for row in domains:
            host = row.get("hostname")
            if host:
                merged[host] = row.get("app", "Unknown")
    return [{"hostname": host, "app": app} for host, app in sorted(merged.items())]


if __name__ == "__main__":
    create_app().run(debug=True)
