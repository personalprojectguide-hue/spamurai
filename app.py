import os
import json
import time
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, abort
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

CLIENT_SECRETS_FILE = "credentials.json"
USERS_FILE = "users.json"
ADMIN_EMAIL = "personalprojectguide@gmail.com"

SCOPES = [
    "https://mail.google.com/",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)


def save_user(user):
    users = load_users()
    email = user["email"]
    if email not in users:
        users[email] = {
            "name": user["name"],
            "picture": user["picture"],
            "joined": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        }
    else:
        users[email]["last_seen"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def get_flow():
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="https://spamurai.up.railway.app/oauth/callback",
    )


def credentials_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }


def get_credentials():
    if "credentials" not in session:
        return None
    try:
        creds = Credentials(**session["credentials"])
        if creds.expired and creds.refresh_token:
            creds.refresh(google.auth.transport.requests.Request())
            session["credentials"] = credentials_to_dict(creds)
        return creds
    except Exception:
        session.clear()
        return None


def gmail_service():
    creds = get_credentials()
    if not creds:
        return None
    try:
        return build("gmail", "v1", credentials=creds)
    except Exception:
        return None


@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)


@app.route("/login")
def login():
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth/callback")
def oauth_callback():
    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = credentials_to_dict(creds)
    service = build("oauth2", "v2", credentials=creds)
    user_info = service.userinfo().get().execute()
    user = {
        "email": user_info.get("email"),
        "name": user_info.get("name"),
        "picture": user_info.get("picture"),
    }
    session["user"] = user
    save_user(user)
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if not get_credentials():
        return redirect(url_for("index"))
    user = session.get("user")
    return render_template("dashboard.html", user=user)


@app.route("/admin")
def admin():
    user = session.get("user")
    if not user or user["email"] != ADMIN_EMAIL:
        abort(403)
    users = load_users()
    return render_template("admin.html", users=users, total_users=len(users))


@app.route("/api/scan")
def api_scan():
    try:
        service = gmail_service()
        if not service:
            return jsonify({"error": "Not authenticated"}), 401

        sender_data = {}

        # Step 1: get all message IDs — exclude sent & drafts, only count received mail
        all_ids = []
        page_token = None
        while True:
            params = {
                "userId": "me",
                "maxResults": 500,
                "q": "-in:sent -in:drafts",
                "fields": "messages/id,nextPageToken",
            }
            if page_token:
                params["pageToken"] = page_token
            result = service.users().messages().list(**params).execute()
            for m in result.get("messages", []):
                all_ids.append(m["id"])
            page_token = result.get("nextPageToken")
            if not page_token:
                break

        # Deduplicate
        all_ids = list(dict.fromkeys(all_ids))

        # Step 2: fetch From headers in batches of 100
        # No sleeps, no retries — both cause gunicorn worker timeouts
        for i in range(0, len(all_ids), 100):
            chunk = all_ids[i:i + 100]

            def make_callback():
                def cb(request_id, response, exception):
                    if exception or not response:
                        return
                    headers = response.get("payload", {}).get("headers", [])
                    from_val = next(
                        (h["value"] for h in headers if h["name"].lower() == "from"), ""
                    )
                    if not from_val:
                        return
                    if "<" in from_val:
                        name = from_val.split("<")[0].strip().strip('"')
                        addr = from_val.split("<")[1].strip(">").strip()
                    else:
                        name = from_val.strip()
                        addr = from_val.strip()
                    key = addr.lower()
                    if key not in sender_data:
                        sender_data[key] = {"name": name or addr, "email": addr, "count": 0}
                    sender_data[key]["count"] += 1
                return cb

            batch = service.new_batch_http_request(callback=make_callback())
            for mid in chunk:
                batch.add(
                    service.users().messages().get(
                        userId="me",
                        id=mid,
                        format="metadata",
                        metadataHeaders=["From"],
                    )
                )
            try:
                batch.execute()
            except Exception:
                pass

        sorted_senders = sorted(
            sender_data.values(),
            key=lambda x: x["count"],
            reverse=True,
        )
        total_emails = sum(s["count"] for s in sorted_senders)

        return jsonify({
            "total_emails": total_emails,
            "total_senders": len(sorted_senders),
            "senders": list(sorted_senders),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete", methods=["POST"])
def api_delete():
    service = gmail_service()
    if not service:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"error": "No email provided"}), 400

    total_deleted = 0
    while True:
        result = service.users().messages().list(
            userId="me",
            q=f"from:{email} in:anywhere",
            maxResults=500,
        ).execute()
        messages = result.get("messages", [])
        if not messages:
            break
        ids = [m["id"] for m in messages]
        service.users().messages().batchDelete(
            userId="me",
            body={"ids": ids},
        ).execute()
        total_deleted += len(ids)

    return jsonify({"deleted": total_deleted})


@app.route("/api/nuke", methods=["POST"])
def api_nuke():
    service = gmail_service()
    if not service:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.json
    emails = data.get("emails", [])
    total_deleted = 0

    for email in emails:
        while True:
            result = service.users().messages().list(
                userId="me",
                q=f"from:{email} in:anywhere",
                maxResults=500,
            ).execute()
            messages = result.get("messages", [])
            if not messages:
                break
            ids = [m["id"] for m in messages]
            service.users().messages().batchDelete(
                userId="me",
                body={"ids": ids},
            ).execute()
            total_deleted += len(ids)

    return jsonify({"deleted": total_deleted, "senders_nuked": len(emails)})


@app.route("/api/unsubscribe", methods=["POST"])
def api_unsubscribe():
    service = gmail_service()
    if not service:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"error": "No email provided"}), 400

    total_marked = 0
    page_token = None
    while True:
        params = {
            "userId": "me",
            "q": f"from:{email} in:anywhere",
            "maxResults": 500,
        }
        if page_token:
            params["pageToken"] = page_token
        result = service.users().messages().list(**params).execute()
        messages = result.get("messages", [])
        ids = [m["id"] for m in messages]
        if ids:
            service.users().messages().batchModify(
                userId="me",
                body={
                    "ids": ids,
                    "addLabelIds": ["SPAM"],
                    "removeLabelIds": ["INBOX"],
                },
            ).execute()
            total_marked += len(ids)
        page_token = result.get("nextPageToken")
        if not page_token:
            break

    return jsonify({"marked_spam": total_marked})


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/tos")
def tos():
    return render_template("tos.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)