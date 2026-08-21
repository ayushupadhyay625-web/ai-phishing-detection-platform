from flask import Flask, jsonify, request
from flask_cors import CORS

from detector import analyze_email, analyze_url


app = Flask(__name__)

CORS(app)


@app.get("/")
def home():
    return jsonify(
        {
            "success": True,
            "message": "Phishing Detection ML Service is running",
        }
    )


@app.get("/api/health")
def health():
    return jsonify(
        {
            "success": True,
            "status": "healthy",
            "service": "Python Phishing Detection Service",
            "model_status": "hybrid_detection_engine_loaded",
            "detection_method": "advanced-url-threat-engine-v2",
        }
    )


@app.post("/api/predict/email")
def predict_email():
    request_data = request.get_json(silent=True) or {}

    if not request_data.get("body"):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Email body is required",
                }
            ),
            400,
        )

    result = analyze_email(request_data)

    return jsonify(
        {
            "success": True,
            "scan_type": "email",
            **result,
        }
    )


@app.post("/api/predict/url")
def predict_url():
    request_data = request.get_json(silent=True) or {}

    submitted_url = request_data.get("url", "").strip()

    if not submitted_url:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "URL is required",
                }
            ),
            400,
        )

    result = analyze_url(submitted_url)

    return jsonify(
        {
            "success": True,
            "scan_type": "url",
            "submitted_url": submitted_url,
            "detection_method": "hybrid-explainable-engine-v1",
            **result,
        }
    )


@app.errorhandler(404)
def route_not_found(error):
    return (
        jsonify(
            {
                "success": False,
                "message": "API route not found",
            }
        ),
        404,
    )


@app.errorhandler(500)
def internal_server_error(error):
    return (
        jsonify(
            {
                "success": False,
                "message": "Internal detection service error",
            }
        ),
        500,
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True,
    )