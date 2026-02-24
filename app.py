import os
import json
import time
from collections import defaultdict
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
    except Exception as e:
        print(f"Error building Gmail service: {e}")
        return None


def execute_batch_with_retry(service, msg_ids, sender_data, max_retries=5):
    """
    Fetch sender headers for all msg_ids. Raises an exception if after max_retries
    any IDs remain unprocessed.
    """
    ids_to_fetch = list(msg_ids)

    for attempt in range(max_retries):
        if not ids_to_fetch:
            break

        failed_ids = []

        def make_callback(chunk_ids):
            id_map = {str(idx): msg_id for idx, msg_id in enumerate(chunk_ids)}
            def process_batch(request_id, response, exception):
                msg_id = id_map.get(str(request_id))
                if exception or response is None:
                    if msg_id:
                        failed_ids.append(msg_id)
                    return
                headers = response.get("payload", {}).get("headers", [])
                from_header = next(
                    (h["value"] for h in headers if h["name"].lower() == "from"), ""
                )
                if not from_header:
                    return
                if "<" in from_header:
                    name = from_header.split("<")[0].strip().strip('"')
                    email = from_header.split("<")[1].strip(">").strip()
                else:
                    name = from_header
                    email = from_header
                key = email.lower()
                sender_data[key]["count"] += 1
                sender_data[key]["name"] = name or email
                sender_data[key]["email"] = email
            return process_batch

        callback = make_callback(ids_to_fetch)
        batch = service.new_batch_http_request(callback=callback)
        for msg_id in ids_to_fetch:
            batch.add(
                service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="metadata",
                    metadataHeaders=["From"],
                )
            )
        try:
            batch.execute()
        except Exception:
            # Entire batch failed – mark all for retry
            failed_ids = list(ids_to_fetch)

        ids_to_fetch = failed_ids
        if ids_to_fetch and attempt < max_retries - 1:
            wait_time = min(2 ** attempt, 5)  # exponential backoff, max 5s to avoid timeout
            print(f"Retry {attempt + 1}/{max_retries - 1}: Waiting {wait_time}s before retrying {len(ids_to_fetch)} messages...")
            time.sleep(wait_time)

    # If any IDs still remain, raise an error so the scan fails explicitly
    if ids_to_fetch:
        raise RuntimeError(f"Failed to fetch {len(ids_to_fetch)} messages after {max_retries} retries")
    return ids_to_fetch


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
            return jsonify({"error": "Not authenticated or API error"}), 401

        sender_data = defaultdict(lambda: {"count": 0, "name": "", "email": ""})

        # Step 1: Collect ALL message IDs via full pagination
        # Exclude sent and drafts — we only want emails received from other people
        all_ids = []
        page_token = None
        while True:
            try:
                params = {"userId": "me", "maxResults": 500, "q": "-in:sent -in:drafts"}
                if page_token:
                    params["pageToken"] = page_token
                result = service.users().messages().list(**params).execute()
                messages = result.get("messages", [])
                all_ids.extend([m["id"] for m in messages])
                page_token = result.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                return jsonify({"error": f"Failed to list messages: {str(e)}"}), 500

        # Deduplicate IDs — Gmail API can return the same message across pages
        all_ids = list(dict.fromkeys(all_ids))

        # Step 2: Fetch sender headers in batches of 500
        batch_size = 100
        for i in range(0, len(all_ids), batch_size):
            chunk = all_ids[i:i + batch_size]
            time.sleep(0.3)  # small delay to avoid rate limit bursts
            execute_batch_with_retry(service, chunk, sender_data, max_retries=3)

        sorted_senders = sorted(
            [
                {"name": v["name"], "email": k, "count": v["count"]}
                for k, v in sender_data.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )

        total_emails = sum(s["count"] for s in sorted_senders)

        return jsonify(
            {
                "total_emails": total_emails,
                "total_senders": len(sorted_senders),
                "senders": sorted_senders,
            }
        )

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
        time.sleep(0.5)
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
        # in:anywhere matches the same scope the scan used
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
            time.sleep(0.5)
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