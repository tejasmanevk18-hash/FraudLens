"""
app.py — FraudLens Flask backend.

Architecture:
    User -> Frontend (HTML/CSS/JS) -> Flask -> MySQL / ML model -> JSON/HTML -> Frontend

Database: MySQL (fraudlens database, users table)

Run:
    python app.py
"""

import io
import json
import os
from datetime import datetime
from functools import wraps

# Heavy libraries (joblib, pandas, sklearn, cv2) are imported lazily
# within the route handlers or helpers to avoid blocking app startup.
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

# MySQL database module
from db import (
    check_user_by_email, create_user, get_user_by_id, get_all_users,
    save_sms_scan, save_link_scan, save_qr_scan,
    get_scan_history, get_scan_stats, DatabaseUnavailableError
)

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

# In production, set FLASK_SECRET_KEY as a real environment variable.
# Falling back to a random key means sessions reset each restart — fine
# for a dev/demo project, but call this out clearly.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "sms_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "model", "vectorizer.pkl")

# Models are loaded lazily on first SMS-detection request to avoid
# blocking startup when sklearn/scipy imports are heavy or missing.
sms_model = None
sms_vectorizer = None
_models_load_attempted = False

def ensure_models_loaded():
    """Attempt to load the ML model and vectorizer once. If loading
    fails, leave sms_model/sms_vectorizer as None so the app falls back
    to rule-based analysis.
    """
    global sms_model, sms_vectorizer, _models_load_attempted
    if _models_load_attempted:
        return
    _models_load_attempted = True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        app.logger.warning("Model files not found; using rule-based fallback.")
        return

    try:
        import joblib
        sms_model = joblib.load(MODEL_PATH)
        sms_vectorizer = joblib.load(VECTORIZER_PATH)
        app.logger.info("[FraudLens] SMS model loaded successfully.")
    except Exception:
        app.logger.exception("Could not load SMS model; falling back to rules.")
        sms_model = None
        sms_vectorizer = None

# Database initialization removed — MySQL connection is handled per-request.
# See db.py for database functions.


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("You don't have permission to view that page.", "error")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return wrapped


def current_user_from_session():
    """Get current user info from Flask session.
    
    When MySQL is set up, replace this with a database query.
    """
    if "user_id" not in session:
        return None
    return {
        "id": session.get("user_id"),
        "full_name": session.get("full_name", ""),
        "email": session.get("email", ""),
        "is_admin": session.get("is_admin", False),
        "created_at": session.get("created_at", "")
    }


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user_from_session()
    stats = get_scan_stats(user["id"])
    recent = get_scan_history(user["id"])
    return render_template("dashboard.html", user=user, stats=stats, recent=recent)


@app.route("/sms_detector")
@login_required
def sms_detector():
    user = current_user_from_session()
    return render_template("sms_detector.html", user=user)


@app.route("/link_checker")
@login_required
def link_checker():
    user = current_user_from_session()
    return render_template("link_checker.html", user=user)


@app.route("/qr_scanner")
@login_required
def qr_scanner():
    user = current_user_from_session()
    return render_template("qr_scanner.html", user=user)


@app.route("/safety_hub")
@login_required
def safety_hub():
    user = current_user_from_session()
    return render_template("safety_hub.html", user=user)


@app.route("/users")
@admin_required
def users_page():
    admin_user = current_user_from_session()
    # Query all users from MySQL database
    all_users = get_all_users()
    return render_template("users.html", user=admin_user, all_users=all_users)


# ---------------------------------------------------------------------------
# Auth API (JSON, called by script.js via fetch)
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register_submit():
    data = request.get_json(silent=True) or request.form
    app.logger.debug("Register attempt with email: %s", data.get("email"))

    full_name = (data.get("fullName") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm_password = data.get("confirmPassword") or ""

    if len(full_name) < 2:
        return jsonify(success=False, field="fullNameInput", message="Please enter your full name."), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify(success=False, field="emailInput", message="Please enter a valid email address."), 400
    if len(password) < 8:
        return jsonify(success=False, field="passwordInput", message="Password must be at least 8 characters."), 400
    if password != confirm_password:
        return jsonify(success=False, field="confirmPasswordInput", message="Passwords do not match."), 400

    # --- Check for existing user in MySQL ---
    # NOTE: previously, a DatabaseUnavailableError here silently fell back
    # to a fake "local_" session and returned success=True WITHOUT ever
    # inserting into MySQL. That's why registrations appeared to work on
    # the website but no row showed up in the `users` table. We now log
    # the real error and return a clear failure instead of faking success.
    try:
        existing_user = check_user_by_email(email)
    except DatabaseUnavailableError as e:
        app.logger.error("MySQL unavailable during registration (check_user_by_email): %s", e)
        return jsonify(
            success=False,
            message="We couldn't reach the database right now. Please try again in a moment."
        ), 503

    if existing_user:
        return jsonify(success=False, field="emailInput",
                        message="An account with this email already exists."), 409

    password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    # --- Create the user in MySQL ---
    # Same fix applied here: no more silent local/offline fallback.
    try:
        new_user = create_user(full_name, email, password_hash)
    except DatabaseUnavailableError as e:
        app.logger.error("MySQL unavailable while creating account (create_user): %s", e)
        return jsonify(
            success=False,
            message="We couldn't reach the database right now. Please try again in a moment."
        ), 503

    if not new_user:
        app.logger.error("Failed to create user: %s", email)
        return jsonify(success=False, field="emailInput",
                        message="Could not create account. Please try again."), 500

    session["user_id"] = new_user["id"]
    session["full_name"] = new_user["full_name"]
    session["email"] = new_user["email"]
    session["is_admin"] = False

    return jsonify(success=True, message="Account created successfully! Redirecting to login…",
                    redirect=url_for("login")), 201


@app.route("/login", methods=["POST"])
def login_submit():
    data = request.get_json(silent=True) or request.form
    app.logger.debug("Login attempt with email: %s", data.get("email"))

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if "@" not in email:
        return jsonify(success=False, field="emailInput", message="Please enter a valid email address."), 400
    if not password:
        return jsonify(success=False, field="passwordInput", message="Please enter your password."), 400

    try:
        user = check_user_by_email(email)
    except DatabaseUnavailableError:
        app.logger.error("MySQL unavailable during login: %s", email)
        return jsonify(success=False, message="We couldn't reach the database right now. Please try again in a moment."), 503

    if not user:
        return jsonify(success=False, message="Invalid email or password."), 401

    if not user.get("is_active"):
        return jsonify(success=False, message="Your account is inactive. Please contact support."), 403

    stored_hash = user.get("password")
    if not stored_hash or not check_password_hash(stored_hash, password):
        return jsonify(success=False, message="Invalid email or password."), 401

    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["is_admin"] = False

    app.logger.info("User logged in successfully: %s (id=%s)", user["email"], user["id"])
    return jsonify(success=True, message="Login successful! Redirecting…", redirect=url_for("dashboard")), 200


# ---------------------------------------------------------------------------
# Excel / CSV export (admin only)
# ---------------------------------------------------------------------------
@app.route("/export-users")
@admin_required
def export_users_excel():
    # Export endpoint disabled. When MySQL is set up, implement user export if needed.
    return jsonify(success=False, message="User export disabled."), 404


@app.route("/export-users-csv")
@admin_required
def export_users_csv():
    return jsonify(success=False, message="User export disabled."), 404


@app.route('/api/whoami')
def api_whoami():
    """Return current session user info for frontend auth guard."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify(logged_in=False)

    try:
        user = get_user_by_id(user_id)
    except DatabaseUnavailableError:
        return jsonify(logged_in=False)

    if not user:
        # User no longer exists or was deleted
        session.clear()
        return jsonify(logged_in=False)

    return jsonify(logged_in=True, user={
        'id': user['id'],
        'full_name': user['full_name'],
        'email': user['email'],
        'is_active': user.get('is_active'),
        'created_at': user.get('created_at'),
        'is_admin': False  # No admin field in users table
    })


# ---------------------------------------------------------------------------
# API — SMS detection
# ---------------------------------------------------------------------------
@app.route("/api/detect-sms", methods=["POST"])
@login_required
def api_detect_sms():
    # Import sms_utils lazily to avoid heavy imports during startup
    import sms_utils

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify(success=False, message="Please enter a message to analyze."), 400
    if len(message) > 1000:
        return jsonify(success=False, message="Message is too long (max 1000 characters)."), 400

    indicators = sms_utils.extract_indicators(message)

    # Ensure models are loaded lazily; if loading fails we'll use rule-based
    # detection so the endpoint remains responsive.
    ensure_models_loaded()

    if sms_model is not None and sms_vectorizer is not None:
        try:
            cleaned = sms_utils.clean_text(message)
            vec = sms_vectorizer.transform([cleaned])
            prediction = sms_model.predict(vec)[0]  # 'spam' or 'ham'
            proba = sms_model.predict_proba(vec)[0]
            classes = list(sms_model.classes_)
            confidence = float(proba[classes.index(prediction)])
        except Exception:
            app.logger.exception("Error during model prediction; falling back to rules.")
            prediction = "spam" if len(indicators) >= 2 else "ham"
            confidence = 0.6 if indicators else 0.5
    else:
        # Graceful fallback if the model file is missing.
        prediction = "spam" if len(indicators) >= 2 else "ham"
        confidence = 0.6 if indicators else 0.5

    risk_score = sms_utils.combine_risk_score(confidence, prediction, len(indicators))
    level = sms_utils.risk_level(risk_score)
    recommendation = sms_utils.recommendation_for(level)

    if not indicators:
        indicators = ["No strong scam indicators detected"]

    saved = save_sms_scan(
        session["user_id"], message,
        "Scam" if prediction == "spam" else "Not Scam",
        risk_score
    )
    if not saved:
        return jsonify(success=False, message="Could not save SMS scan record."), 500

    return jsonify(
        success=True,
        prediction="Scam" if prediction == "spam" else "Not Scam",
        status=level,
        risk_score=risk_score,
        confidence=round(confidence, 2),
        indicators=indicators,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# API — Link checker
# ---------------------------------------------------------------------------
@app.route("/api/check-link", methods=["POST"])
@login_required
def api_check_link():
    # Import link_utils lazily to avoid heavy imports during startup
    import link_utils

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify(success=False, message="Please enter a URL to check."), 400
    if len(url) > 2000:
        return jsonify(success=False, message="URL is too long."), 400

    risk_score, indicators = link_utils.analyze_url(url)
    level = link_utils.risk_level(risk_score)
    recommendation = link_utils.recommendation_for(level)

    saved = save_link_scan(session["user_id"], url, level, risk_score)
    if not saved:
        return jsonify(success=False, message="Could not save Link scan record."), 500

    return jsonify(
        success=True,
        url=url,
        status=level,
        risk_score=risk_score,
        indicators=indicators,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# API — QR scanner
# ---------------------------------------------------------------------------
def analyze_qr_content(decoded_data):
    import qr_utils
    import link_utils

    payload_type = qr_utils.classify_payload(decoded_data)
    if payload_type in ("URL", "UPI_PAYMENT"):
        risk_score, indicators = link_utils.analyze_url(decoded_data)
        level = link_utils.risk_level(risk_score)
        recommendation = link_utils.recommendation_for(level)
    else:
        risk_score, indicators = 10, ["QR contains plain text (not a link)"]
        level = "Safe"
        recommendation = "This QR code does not point to a link. Still, be cautious about acting on unexpected instructions."

    saved = save_qr_scan(session["user_id"], decoded_data, level, risk_score)
    if not saved:
        return {
            "success": False,
            "message": "Could not save QR scan record."
        }

    return {
        "success": True,
        "decoded_data": decoded_data,
        "type": payload_type,
        "status": level,
        "risk_score": risk_score,
        "indicators": indicators,
        "recommendation": recommendation,
    }


@app.route("/api/analyze-qr", methods=["POST"])
@login_required
def api_analyze_qr():
    data = request.get_json(silent=True) or {}
    decoded_data = (data.get("decoded_data") or "").strip()
    if not decoded_data:
        return jsonify(success=False, message="No QR content was decoded."), 400
    if len(decoded_data) > 5000:
        return jsonify(success=False, message="QR content is too long."), 400
    return jsonify(analyze_qr_content(decoded_data))


@app.route("/api/scan-qr", methods=["POST"])
@login_required
def api_scan_qr():
    # Import qr_utils lazily to avoid heavy imports during startup
    import qr_utils
    import link_utils

    if "qr_image" not in request.files:
        return jsonify(success=False, message="Please upload a QR code image."), 400

    file = request.files["qr_image"]
    if file.filename == "":
        return jsonify(success=False, message="No file selected."), 400
    if not qr_utils.allowed_file(file.filename):
        return jsonify(success=False, message="Unsupported file type. Use PNG, JPG, JPEG or WEBP."), 400

    file_bytes = file.read()
    decoded_data, error = qr_utils.decode_qr_from_bytes(file_bytes)
    if error:
        if request.headers.get("X-QR-Camera") == "1" and "no qr code" in error.lower():
            return jsonify(success=False, message=error), 200
        return jsonify(success=False, message=error), 422

    return jsonify(analyze_qr_content(decoded_data))


# ---------------------------------------------------------------------------
# Error handling — never leak stack traces to the user
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify(success=False, message="Uploaded file is too large (max 5 MB)."), 413


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


if __name__ == "__main__":
    # Production-safe host/port binding while keeping the same local
    # development debug trace behavior available when run directly.
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=False, host=host, port=port, use_reloader=False)