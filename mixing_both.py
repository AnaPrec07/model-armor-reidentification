"""
armor_kms_pii.py
────────────────
Inspect PII via Model Armor, encrypt matches with KMS.
Tokens are prefixed with the info type so you can spot them instantly:

  "Patricia Rodriguez"  →  "PII_PERSON_NAME::AaHdUBUA26r..."
  "6123-4567"           →  "PII_PHONE_NUMBER::XxYy..."

pip install google-cloud-modelarmor google-cloud-kms
"""

import base64
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1, kms

# ── config ────────────────────────────────────────────────────────────────────
KMS_KEY             = "projects/MY_PROJECT/locations/global/keyRings/MY_RING/cryptoKeys/MY_KEY"
PROJECT_ID          = "MY_PROJECT"
LOCATION            = "us-central1"
MODEL_ARMOR_TEMPLATE_ID = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/MY_TEMPLATE_ID"

TOKEN_PREFIX = "PII_"        # visible label prepended to every encrypted token
TOKEN_SEP    = "::"          # separator between label and ciphertext

# ── clients ───────────────────────────────────────────────────────────────────
ma_client = modelarmor_v1.ModelArmorClient(
    transport="rest",
    client_options=ClientOptions(
        api_endpoint=f"modelarmor.{LOCATION}.rep.googleapis.com"
    ),
)

kms_client = kms.KeyManagementServiceClient()


# ── KMS primitives (your original functions, unchanged) ───────────────────────

def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns a base64 token you can store."""
    response = kms_client.encrypt(
        request={"name": KMS_KEY, "plaintext": plaintext.encode()}
    )
    return base64.b64encode(response.ciphertext).decode()


def decrypt(token: str) -> str:
    """Decrypt a base64 token back to the original string."""
    response = kms_client.decrypt(
        request={"name": KMS_KEY, "ciphertext": base64.b64decode(token)}
    )
    return response.plaintext.decode()


# ── token helpers ─────────────────────────────────────────────────────────────

def make_token(info_type: str, ciphertext_b64: str) -> str:
    """
    Build a labeled token:  PII_PERSON_NAME::AaHdUBUA26r...
    The label lets you scan masked text at a glance without decrypting anything.
    """
    return f"{TOKEN_PREFIX}{info_type}{TOKEN_SEP}{ciphertext_b64}"


def parse_token(token: str) -> tuple[str, str] | None:
    """
    Split PII_PERSON_NAME::AaHdUBUA26r... into ("PERSON_NAME", "AaHdUBUA26r...")
    Returns None if the string is not a valid token.
    """
    if not token.startswith(TOKEN_PREFIX) or TOKEN_SEP not in token:
        return None
    without_prefix = token[len(TOKEN_PREFIX):]
    info_type, _, ciphertext_b64 = without_prefix.partition(TOKEN_SEP)
    return info_type, ciphertext_b64


# ── Model Armor ───────────────────────────────────────────────────────────────

def sanitize_with_model_armor(text: str, user_id: str):
    """
    Your original function, kept intact.
    Returns (text, None) if safe, (None, reason) if flagged.
    """
    try:
        request_ma = modelarmor_v1.types.SanitizeUserPromptRequest(
            name=MODEL_ARMOR_TEMPLATE_ID,
            user_prompt_data=modelarmor_v1.types.DataItem(text=text)
        )
        response = ma_client.sanitize_user_prompt(request=request_ma)

        if int(response.sanitization_result.filter_match_state) == 2:
            return None, "Policy Violation: The content was flagged as unsafe."

        return text, None

    except Exception as e:
        print(f"Model Armor Error: {e}")
        return text, None   # fail-open


def _extract_pii_findings(text: str) -> list[dict]:
    """
    Run Model Armor and pull out only the SDP/DLP findings.
    Returns [{"info_type": "PERSON_NAME", "quote": "Patricia Rodriguez"}, ...]

    Requires your Model Armor template to have a DLP inspection config
    with include_quote = True.
    """
    try:
        request_ma = modelarmor_v1.types.SanitizeUserPromptRequest(
            name=MODEL_ARMOR_TEMPLATE_ID,
            user_prompt_data=modelarmor_v1.types.DataItem(text=text)
        )
        response = ma_client.sanitize_user_prompt(request=request_ma)

        sdp = response.sanitization_result.filter_results.get("sdp")
        if not sdp:
            return []

        findings = []
        for f in sdp.sdp_filter_result.inspect_result.findings:
            if f.quote:
                findings.append({
                    "info_type": f.info_type.name,
                    "quote": f.quote,
                })
        return findings

    except Exception as e:
        print(f"Model Armor Error: {e}")
        return []


# ── main service ──────────────────────────────────────────────────────────────

def inspect_and_encrypt(text: str, user_id: str = "") -> dict:
    """
    1. Run safety check — block jailbreaks, RAI violations, etc.
    2. Find PII via Model Armor's DLP inspection template.
    3. Encrypt each unique PII value with KMS.
    4. Replace values in text with labeled tokens.

    Token format:  PII_PERSON_NAME::AaHdUBUA26r...
                   ───┬──────────  ─────┬────────
                      │                 └─ KMS ciphertext (base64)
                      └─ info type label (for fast scanning)

    Returns:
        {
          "masked_text": "Call PII_PERSON_NAME::AaHd... at PII_PHONE_NUMBER::XxYy...",
          "token_map":   {"PII_PERSON_NAME::AaHd...": "Patricia Rodriguez", ...},
          "blocked": False,
          "block_reason": None,
        }

    Store token_map in Firestore / Secret Manager keyed to session_id.
    """
    # Step 1: safety check
    _, violation = sanitize_with_model_armor(text, user_id)
    if violation:
        return {
            "masked_text": None,
            "token_map": {},
            "blocked": True,
            "block_reason": violation,
        }

    # Step 2: find PII
    findings = _extract_pii_findings(text)

    token_map   = {}   # labeled_token → original  (persist this)
    reverse_map = {}   # original → labeled_token  (for replacement)

    # Step 3: encrypt each unique match
    for finding in findings:
        original  = finding["quote"]
        info_type = finding["info_type"]

        if original in reverse_map:
            continue   # same value seen twice, reuse the token

        ciphertext_b64  = encrypt(original)
        labeled_token   = make_token(info_type, ciphertext_b64)

        token_map[labeled_token] = original
        reverse_map[original]    = labeled_token

    # Step 4: replace in text (longest first to avoid partial overlaps)
    masked = text
    for original in sorted(reverse_map, key=len, reverse=True):
        masked = masked.replace(original, reverse_map[original])

    return {
        "masked_text": masked,
        "token_map": token_map,
        "blocked": False,
        "block_reason": None,
    }


def restore(masked_text: str, token_map: dict) -> str:
    """
    Decrypt all labeled tokens back to original PII values.
    token_map is what was returned by inspect_and_encrypt().
    """
    for labeled_token, original in token_map.items():
        masked_text = masked_text.replace(labeled_token, original)
    return masked_text


def decrypt_token(labeled_token: str) -> str:
    """
    Decrypt a single labeled token without needing the full token_map.
    Useful for spot-checking or audit logging.

    decrypt_token("PII_PERSON_NAME::AaHdUBUA26r...")
    → "Patricia Rodriguez"
    """
    parsed = parse_token(labeled_token)
    if not parsed:
        raise ValueError(f"Not a valid PII token: {labeled_token!r}")
    _, ciphertext_b64 = parsed
    return decrypt(ciphertext_b64)


# ── usage ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = "Call Patricia Rodriguez at 6123-4567 or juan@banco.com"

    result = inspect_and_encrypt(sample, user_id="agent-session-001")

    if result["blocked"]:
        print("BLOCKED:", result["block_reason"])
    else:
        print("Masked  :", result["masked_text"])
        # → Call PII_PERSON_NAME::AaHd... at PII_PHONE_NUMBER::XxYy... or PII_EMAIL_ADDRESS::ZzWw...

        # Restore from token_map
        restored = restore(result["masked_text"], result["token_map"])
        print("Restored:", restored)
        # → Call Patricia Rodriguez at 6123-4567 or juan@banco.com

        # Or decrypt a single token on demand
        for token in result["token_map"]:
            print(f"  {token[:40]}...  →  {decrypt_token(token)}")
