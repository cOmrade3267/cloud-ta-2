from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import uuid
import re
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
BUCKET_NAME = os.getenv("BUCKET_NAME")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("storage"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        try:
            result = supabase.auth.sign_up({"email": email, "password": password})
            if result.user:
                return jsonify({"success": True, "message": "Account created! Please log in."})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        try:
            user = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            if user.user:
                session["user"] = {"id": user.user.id, "email": user.user.email}
                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "message": "Invalid credentials"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/storage")
def storage():
    if "user" not in session:
        return redirect(url_for("login"))

    user_email = session["user"]["email"]
    safe_email = re.sub(r"[^a-zA-Z0-9_-]", "_", user_email)
    current_path = request.args.get("path", "").strip("/")
    base_path = f"{safe_email}/{current_path}".rstrip("/")

    try:
        response = supabase.storage.from_(BUCKET_NAME).list(
            path=base_path if base_path else safe_email,
            options={
                "limit": 100,
                "offset": 0,
                "sortBy": {"column": "name", "order": "asc"},
            },
        )

        folders, files = [], []
        for item in response:
            name = item["name"]
            if item["metadata"] is None:
                folders.append(name)
            else:
                display_name = name
                if "_" in name and len(name.split("_", 1)) == 2:
                    display_name = name.split("_", 1)[1]
                
                # Get file size
                size_bytes = item.get("metadata", {}).get("size", 0)
                size_str = format_file_size(size_bytes)
                
                files.append({
                    "real_name": name,
                    "display_name": display_name,
                    "size": size_str,
                    "updated_at": item.get("updated_at", "")
                })
    except Exception as e:
        flash(f"Error listing files: {e}", "danger")
        folders, files = [], []

    parent_path = "/".join(current_path.split("/")[:-1]) if "/" in current_path else ""

    return render_template(
        "dashboard.html",
        user_email=user_email,
        safe_email=safe_email,
        files=files,
        folders=folders,
        current_path=current_path,
        parent_path=parent_path,
    )


def format_file_size(bytes_size):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    user_email = session["user"]["email"]
    file = request.files.get("file")
    current_path = request.form.get("current_path", "").strip("/")
    original_name = request.form.get("original_name")

    if not file or file.filename == "":
        return jsonify({"success": False, "message": "No file selected"}), 400

    safe_email = re.sub(r"[^a-zA-Z0-9_-]", "_", user_email)
    base_filename = original_name if original_name else file.filename
    clean_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", base_filename)

    folder_prefix = f"{safe_email}/{current_path}" if current_path else safe_email
    unique_name = f"{folder_prefix}/{uuid.uuid4()}_{clean_filename}"

    try:
        file_data = file.read()
        supabase.storage.from_(BUCKET_NAME).upload(
            path=unique_name,
            file=file_data,
            file_options={"content-type": "application/json"},
        )
        return jsonify({"success": True, "message": "File uploaded successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/create_folder", methods=["POST"])
def create_folder():
    if "user" not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    folder_name = request.form.get("folder_name")
    current_path = request.form.get("current_path", "").strip("/")
    user_email = session["user"]["email"]

    if not folder_name:
        return jsonify({"success": False, "message": "Folder name required"}), 400

    safe_email = re.sub(r"[^a-zA-Z0-9_-]", "_", user_email)
    base_prefix = f"{safe_email}/{current_path}".rstrip("/")
    folder_path = (
        f"{base_prefix}/{folder_name}/.keep" if base_prefix else f"{safe_email}/{folder_name}/.keep"
    )

    try:
        supabase.storage.from_(BUCKET_NAME).upload(path=folder_path, file=b"")
        return jsonify({"success": True, "message": "Folder created"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/download_encrypted/<path:filename>")
def download_encrypted(filename):
    if "user" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_email = session["user"]["email"]
    safe_email = re.sub(r"[^a-zA-Z0-9_-]", "_", user_email)
    full_path = f"{safe_email}/{filename}"

    try:
        file_bytes = supabase.storage.from_(BUCKET_NAME).download(path=full_path)
        return app.response_class(file_bytes, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/shared/<owner_safe>/<path:filename>")
def shared_page(owner_safe, filename):
    return render_template("shared.html", owner_safe=owner_safe, filename=filename)


@app.route("/shared_file/<owner_safe>/<path:filename>")
def shared_file(owner_safe, filename):
    full_path = f"{owner_safe}/{filename}"
    try:
        file_bytes = supabase.storage.from_(BUCKET_NAME).download(path=full_path)
        return app.response_class(file_bytes, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/delete/<path:filename>", methods=["POST"])
def delete(filename):
    if "user" not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    user_email = session["user"]["email"]
    safe_email = re.sub(r"[^a-zA-Z0-9_-]", "_", user_email)
    file_path = f"{safe_email}/{filename}"

    try:
        supabase.storage.from_(BUCKET_NAME).remove([file_path])
        return jsonify({"success": True, "message": "File deleted"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)