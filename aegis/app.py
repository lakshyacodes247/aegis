import os
import json
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from groq import Groq
from supabase import create_client, Client
from flask_cors import CORS  # <-- ADD THIS

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # <-- ENABLE CORS FOR ALL ORIGINS

# Initialize clients
client = Groq()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# Minimal required input fields
REQUIRED_KEYS = {"vulnerability_id", "description", "code_snippet", "language"}

# ---------------- SYSTEM PROMPT ----------------
SYSTEM_PROMPT = """
You are an expert security engineer. Given a vulnerability described in JSON,
produce a valid JSON response containing exactly these keys:
- "vulnerability_id": same ID from input
- "fixed_code": a code snippet that fixes the issue (in the same language)
- "fix_description": a short plain-text sentence describing the change

If the vulnerability cannot be safely fixed or involves disallowed content, respond with:
{"vulnerability_id": "<same id>", "fixed_code": "", "fix_description": "REFUSED: unsafe or disallowed content"}

Do not output any text outside the JSON object.
"""

# ---------------- VALIDATION ----------------
def validate_input(data):
    if not isinstance(data, dict):
        return False, "JSON body must be an object"
    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    for k in REQUIRED_KEYS:
        if not isinstance(data[k], str) or not data[k].strip():
            return False, f"Field '{k}' must be a non-empty string"
    return True, None

# ---------------- MESSAGE BUILDER ----------------
def build_messages(input_json):
    user_content = f"Here is the vulnerability JSON:\n{json.dumps(input_json)}\nReturn only the required JSON."
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

# ---------------- LLM CALL ----------------
def call_llm(messages, model="llama-3.3-70b-versatile", temperature=0.0, max_tokens=512):
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"}
        )
        assistant_text = resp.choices[0].message.content
        return True, assistant_text
    except Exception as e:
        return False, str(e)

# ---------------- MAIN ENDPOINT ----------------
@app.route("/analyze_vulnerability", methods=["POST"])
def analyze_vulnerability():
    # Parse input
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    ok, err = validate_input(data)
    if not ok:
        return jsonify({"error": err}), 400

    vuln_id = data["vulnerability_id"].strip()

    # ---------------- CHECK IF ALREADY EXISTS ----------------
    try:
        existing = supabase.table("vulnerabilities").select("vulnerability_id, fix_description, fixed_code").eq("vulnerability_id", vuln_id).execute()
        if existing.data and len(existing.data) > 0:
            print("Found existing record for vulnerability_id:", vuln_id)
            return jsonify(existing.data[0]), 200
    except Exception as e:
        print("Database check failed:", e)
        return jsonify({"error": "Database lookup failed", "detail": str(e)}), 500

    # ---------------- CALL LLM ----------------
    messages = build_messages(data)
    success, assistant_text = call_llm(messages)
    if not success:
        return jsonify({"error": "LLM call failed", "detail": assistant_text}), 502

    # ---------------- PARSE LLM RESPONSE ----------------
    try:
        parsed = json.loads(assistant_text)
    except json.JSONDecodeError:
        return jsonify({"error": "LLM returned invalid JSON", "raw": assistant_text}), 502

    expected_keys = {"vulnerability_id", "fixed_code", "fix_description"}
    if not expected_keys.issubset(parsed.keys()):
        return jsonify({"error": "Missing keys in LLM output", "raw": parsed}), 502

    parsed["vulnerability_id"] = vuln_id

    # ---------------- DATABASE INSERT ----------------
    try:
        insert_data = {
            "vulnerability_id": vuln_id,
            "description": data["description"],
            "code_snippet": data["code_snippet"],
            "language": data["language"],
            "fix_description": parsed["fix_description"],
            "fixed_code": parsed["fixed_code"]
        }

        db_response = (
            supabase.table("vulnerabilities")
            .insert(insert_data)
            .execute()
        )

        print("Insert successful:", db_response)

    except Exception as e:
        if "duplicate key value" in str(e):
            return jsonify({
                "error": f"Vulnerability ID '{vuln_id}' already exists. Use a unique ID."
            }), 409
        print("Database insert error:", e)
        return jsonify({"error": "Database insert failed", "detail": str(e)}), 500

    # Return the model's JSON output
    return jsonify(parsed), 200

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


