import os
import json
from flask import Flask, request, jsonify
from openai import OpenAI  # <-- Import the modern client
from dotenv import load_dotenv
from groq import Groq
from supabase import create_client, Client

# Load .env for local dev if present
load_dotenv()

# Initialize OpenAI Client
# API key is read automatically from OPENAI_API_KEY env var
client = Groq()

app = Flask(__name__)

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# Minimal input keys we agreed on
REQUIRED_KEYS = {"vulnerability_id", "description", "code_snippet", "language"}

# System prompt that forces the model to reply ONLY with the exact minimal JSON schema.
# We still tell it to output JSON, which is required for JSON mode.
SYSTEM_PROMPT = """
You are an expert security engineer. Your task: given a vulnerability described in JSON,
produce a JSON response.
Output must be valid JSON and must contain these keys exactly:
- "vulnerability_id": same ID from input
- "fixed_code": a code snippet that fixes the issue (in the same language)
- "fix_description": a short plain-text sentence describing the change

If you cannot provide a safe fix or the input asks for exploit code, respond with:
{"vulnerability_id": "<same id>", "fixed_code": "", "fix_description": "REFUSED: unsafe or disallowed content"}

Do not output any text outside the JSON object.
"""

def validate_input(data):
    if not isinstance(data, dict):
        return False, "JSON body must be an object"
    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    # basic types check
    for k in REQUIRED_KEYS:
        if not isinstance(data[k], str) or not data[k].strip():
            return False, f"Field '{k}' must be a non-empty string"
    return True, None

def build_messages(input_json):
    # We send system prompt + user content (the input JSON stringified)
    user_content = f"Here is the vulnerability JSON:\n{json.dumps(input_json)}\nReturn only the required JSON."
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

def call_llm(messages, model="llama-3.3-70b-versatile", temperature=0.0, max_tokens=512):
    """
    Calls OpenAI ChatCompletion endpoint and returns the assistant content.
    Uses modern v1.0.0+ SDK syntax and JSON Mode.
    """
    try:
        # **Use the modern client and syntax**
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            # **This forces the model to output valid JSON**
            response_format={"type": "json_object"}
        )
        # **Extract assistant message text from the modern response object**
        assistant_text = resp.choices[0].message.content
        return True, assistant_text
    except Exception as e:
        # The new SDK raises more specific errors, but this catch-all is fine
        return False, str(e)

@app.route("/analyze_vulnerability", methods=["POST"])
def analyze_vulnerability():
    # Parse and validate input
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    ok, err = validate_input(data)
    if not ok:
        return jsonify({"error": err}), 400

    # Call the LLM
    messages = build_messages(data)
    success, assistant_text = call_llm(messages)
    if not success:
        return jsonify({"error": "LLM call failed", "detail": assistant_text}), 502

    # Parse LLM output
    try:
        parsed = json.loads(assistant_text)
    except json.JSONDecodeError:
        return jsonify({"error": "LLM returned non-JSON output", "raw": assistant_text}), 502

    expected_output_keys = {"vulnerability_id", "fixed_code", "fix_description"}
    if not expected_output_keys.issubset(parsed.keys()):
        return jsonify({"error": "LLM output missing required keys", "raw": parsed}), 502

    # Ensure vulnerability_id matches
    if str(parsed["vulnerability_id"]).strip() != str(data["vulnerability_id"]).strip():
        parsed["vulnerability_id"] = data["vulnerability_id"]

    # ✅ Insert both input + output into Supabase (Postgres)
    try:
        insert_data = {
            "vulnerability_id": data["vulnerability_id"],
            "description": data["description"],
            "code_snippet": data["code_snippet"],
            "language": data["language"],
            "fix_description": parsed["fix_description"],
            "fixed_code": parsed["fixed_code"],
        }

        db_response = (
            supabase.table("vulnerabilities")
            .insert(insert_data)
            .execute()
        )

        print("Supabase insert successful:", db_response)

    except Exception as e:
        print("Error inserting into Supabase:", e)
        return jsonify({
            "error": "Failed to insert record into Supabase",
            "detail": str(e),
        }), 500

    # Return LLM output
    return jsonify(parsed), 200


# ------------------ RUN APP ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)