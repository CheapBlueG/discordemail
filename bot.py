import discord
from discord.ext import commands
from discord import app_commands
import requests
import re
import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Bot Setup ──────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

TOKENS_FILE = "saved_tokens.json"

def load_saved_tokens():
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_token(email, refresh_token, client_id):
    tokens = load_saved_tokens()
    tokens[email.lower()] = {"refresh_token": refresh_token, "client_id": client_id}
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=4)

DEFAULT_TENANT = os.getenv("AZURE_TENANT", "consumers")

TOKEN_URL = f"https://login.microsoftonline.com/{DEFAULT_TENANT}/oauth2/v2.0/token"
GRAPH_URL = "https://graph.microsoft.com/v1.0"

# ── Code Extraction (with standalone digit fallback) ───────────────────────────
CODE_PATTERNS = [
    r'(\d{6})',
    r'code\s*[:\-\s]+(\d{4,8})',
    r'verification\s*code\s*[:\-\s]+(\d{4,8})',
    r'pin\s*[:\-\s]+(\d{4,8})',
    r'otp\s*[:\-\s]+(\d{4,8})',
]

def extract_code(text: str) -> str | None:
    text_lower = text.lower()
    for pattern in CODE_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            return match.group(1)

    # Fallback: any standalone 4-8 digit number (catches 9065 in the new email)
    match = re.search(r'(?<!\d)(\d{4,8})(?!\d)', text)
    if match:
        return match.group(1)

    return None

def strip_html(html: str) -> str:
    text = re.sub(r'<style[^>]*>.*?</style>|<script[^>]*>.*?</script>|<[^>]+>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()

# ── Token Acquisition ──────────────────────────────────────────────────────────
def get_token(refresh_token: str = None, client_id: str = None, email: str = None, password: str = None):
    client_id = client_id or os.getenv("AZURE_CLIENT_ID", "")
    if not client_id:
        return None, "**Client ID missing!**"

    if refresh_token:
        data = {
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": "https://graph.microsoft.com/.default",
        }
    else:
        data = {
            "client_id": client_id,
            "scope": "https://graph.microsoft.com/.default",
            "username": email,
            "password": password,
            "grant_type": "password",
        }

    try:
        resp = requests.post(TOKEN_URL, data=data, timeout=15)
        result = resp.json()
    except Exception as e:
        return None, f"Network error: {e}"

    if "access_token" in result:
        return result["access_token"], None

    err = result.get("error_description", str(result))
    if any(x in err for x in ["50126", "invalid_grant"]):
        return None, "**Invalid credentials or expired refresh_token**"
    elif "7000218" in err:
        return None, "**Public client flows not enabled in Azure**"
    else:
        return None, f"**Auth error:** {err[:300]}"


# ── Fetch Uber Code (newest + priority for new header) ─────────────────────────
def fetch_uber_code(refresh_token: str = None, client_id: str = None, email: str = None, password: str = None):
    token, error = get_token(refresh_token, client_id, email, password)
    if error:
        return {"success": False, "error": error}

    headers = {"Authorization": f"Bearer {token}"}

    # Get the real email address
    me_resp = requests.get(f"{GRAPH_URL}/me?$select=mail,userPrincipalName", headers=headers)
    me = me_resp.json()
    account_email = me.get("mail") or me.get("userPrincipalName") or email or "Unknown"

    # Save for quick use
    if refresh_token and client_id and account_email != "Unknown":
        save_token(account_email, refresh_token, client_id)

    # Fetch emails
    params = {
        "$top": 200,
        "$select": "subject,body,from,receivedDateTime",
    }

    try:
        resp = requests.get(f"{GRAPH_URL}/me/messages", headers={**headers, "ConsistencyLevel": "eventual"}, params=params, timeout=15)
    except Exception as e:
        return {"success": False, "error": f"Network error: {e}"}

    if resp.status_code != 200:
        return {"success": False, "error": f"Graph error {resp.status_code}: {resp.text[:200]}"}

    messages = resp.json().get("value", [])

    if not messages:
        return {"success": False, "error": "No emails found in inbox", "email": account_email}

    # Sort by date descending (newest first)
    def parse_date(d):
        try:
            return datetime.fromisoformat(d.replace("Z", "+00:00"))
        except:
            return datetime.min

    messages.sort(key=lambda x: parse_date(x.get("receivedDateTime", "")), reverse=True)

    # Priority for new header
    for msg in messages:
        subject = msg.get("subject", "").lower()
        if "your uber verification code" in subject or "verification code" in subject:
            body = msg.get("body", {})
            body_text = strip_html(body.get("content", "")) if body.get("contentType") == "html" else body.get("content", "")
            code = extract_code(subject + " " + body_text)
            if code:
                return {
                    "success": True,
                    "code": code,
                    "subject": msg.get("subject", "")[:100],
                    "from": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                    "date": msg.get("receivedDateTime", "")[:19].replace("T", " "),
                    "email": account_email,
                }

    # Fallback to any Uber email
    for msg in messages:
        subject = msg.get("subject", "").lower()
        from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "").lower()
        if "uber" not in subject and "uber" not in from_addr:
            continue

        body = msg.get("body", {})
        body_text = strip_html(body.get("content", "")) if body.get("contentType") == "html" else body.get("content", "")
        code = extract_code(subject + " " + body_text)

        if code:
            return {
                "success": True,
                "code": code,
                "subject": msg.get("subject", "")[:100],
                "from": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                "date": msg.get("receivedDateTime", "")[:19].replace("T", " "),
                "email": account_email,
            }

    return {
        "success": False,
        "error": f"Found Uber emails but no verification code detected",
        "email": account_email,
    }


# ── Discord Command (smart one-line with memory) ───────────────────────────────

@bot.tree.command(name="code", description="Get Uber code — email or token:client_id")
@app_commands.describe(
    input="email@outlook.com   OR   refresh_token:client_id"
)
async def code_slash(interaction: discord.Interaction, input: str):
    await interaction.response.defer(ephemeral=True)

    saved = load_saved_tokens()

    if "@" in input and ":" not in input:
        email = input.strip().lower()
        if email in saved:
            rt = saved[email]["refresh_token"]
            cid = saved[email]["client_id"]
            result = fetch_uber_code(refresh_token=rt, client_id=cid)
        else:
            await interaction.followup.send(f"❌ No saved token for `{email}`.\nFirst use the full `refresh_token:client_id` once.", ephemeral=True)
            return
    elif ":" in input:
        try:
            refresh_token, client_id = [x.strip() for x in input.split(":", 1)]
            result = fetch_uber_code(refresh_token=refresh_token, client_id=client_id)
        except:
            await interaction.followup.send("❌ Wrong format.\nUse: `email@outlook.com` or `refresh_token:client_id`", ephemeral=True)
            return
    else:
        await interaction.followup.send("❌ Wrong format.\nUse: `email@outlook.com` or `refresh_token:client_id`", ephemeral=True)
        return

    if result["success"]:
        embed = discord.Embed(title="✅ Uber Code Found", color=0x00FF00)
        embed.add_field(name="Code", value=f"**{result['code']}**", inline=False)
        embed.add_field(name="Email", value=f"`{result['email']}`", inline=True)
        embed.add_field(name="Subject", value=result.get("subject", "N/A"), inline=False)
        embed.add_field(name="Date", value=result.get("date", "N/A"), inline=True)
    else:
        embed = discord.Embed(title="❌ Failed", description=result["error"], color=0xFF0000)
        embed.add_field(name="Email", value=f"`{result.get('email', 'Unknown')}`", inline=True)

    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.event
async def on_ready():
    print(f"✅ Bot online: {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"✅ Synced {len(synced)} commands")
    except Exception as e:
        print(f"❌ Sync failed: {e}")


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        print("❌ DISCORD_BOT_TOKEN missing in .env")
        exit(1)
    bot.run(token)