import discord
from discord.ext import commands
from discord import app_commands
import requests
import re
import os
import json
import io
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Bot Setup ──────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# ── Persistent Storage (Render Disk or local) ─────────────────────────────────
# Set DATA_DIR env var to your Render disk mount path, e.g. /var/data
DATA_DIR = os.getenv("DATA_DIR", ".")
os.makedirs(DATA_DIR, exist_ok=True)
TOKENS_FILE = os.path.join(DATA_DIR, "saved_tokens.json")

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

def save_tokens_bulk(new_tokens: dict):
    """Merge new tokens into existing file."""
    tokens = load_saved_tokens()
    tokens.update(new_tokens)
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=4)
    return len(new_tokens)

DEFAULT_TENANT = os.getenv("AZURE_TENANT", "consumers")
DEFAULT_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")

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

    match = re.search(r'(?<!\d)(\d{4,8})(?!\d)', text)
    if match:
        return match.group(1)

    return None

def strip_html(html: str) -> str:
    text = re.sub(r'<style[^>]*>.*?</style>|<script[^>]*>.*?</script>|<[^>]+>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()

# ── Token Acquisition ──────────────────────────────────────────────────────────
def get_token(refresh_token: str = None, client_id: str = None, email: str = None, password: str = None):
    client_id = client_id or DEFAULT_CLIENT_ID
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


# ── Fetch Uber Code ───────────────────────────────────────────────────────────
def fetch_uber_code(refresh_token: str = None, client_id: str = None, email: str = None, password: str = None):
    token, error = get_token(refresh_token, client_id, email, password)
    if error:
        return {"success": False, "error": error}

    headers = {"Authorization": f"Bearer {token}"}

    me_resp = requests.get(f"{GRAPH_URL}/me?$select=mail,userPrincipalName", headers=headers)
    me = me_resp.json()
    account_email = me.get("mail") or me.get("userPrincipalName") or email or "Unknown"

    if refresh_token and client_id and account_email != "Unknown":
        save_token(account_email, refresh_token, client_id)

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

    def parse_date(d):
        try:
            return datetime.fromisoformat(d.replace("Z", "+00:00"))
        except:
            return datetime.min

    messages.sort(key=lambda x: parse_date(x.get("receivedDateTime", "")), reverse=True)

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


# ── /code command ──────────────────────────────────────────────────────────────

@bot.tree.command(name="code", description="Get Uber code — email or token:client_id")
@app_commands.describe(input="email@outlook.com   OR   refresh_token:client_id")
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


# ── /upload command (bulk import from .txt file) ───────────────────────────────

@bot.tree.command(name="upload", description="Upload a .txt file with tokens (one per line)")
@app_commands.describe(file="TXT file: email:pass:refresh_token:client_id per line")
async def upload_slash(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(ephemeral=True)

    if not file.filename.endswith(".txt"):
        await interaction.followup.send("❌ Please upload a `.txt` file.", ephemeral=True)
        return

    try:
        content = (await file.read()).decode("utf-8")
    except Exception as e:
        await interaction.followup.send(f"❌ Could not read file: {e}", ephemeral=True)
        return

    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]

    if not lines:
        await interaction.followup.send("❌ File is empty or has no valid lines.", ephemeral=True)
        return

    new_tokens = {}
    errors = []

    for i, line in enumerate(lines, 1):
        # Format: email:pass:refresh_token:client_id
        # Refresh tokens can contain colons, so we parse smartly:
        # - part 0 = email
        # - part 1 = password
        # - last UUID-shaped part = client_id
        # - everything between part 1 and client_id = refresh_token
        parts = line.split(":")

        if len(parts) < 4:
            errors.append(f"Line {i}: not enough fields (need email:pass:token:clientid)")
            continue

        email = parts[0].strip()
        password = parts[1].strip()

        # Find client_id: last part matching UUID pattern, or just the last part
        client_id = None
        token_end = len(parts)
        for j in range(len(parts) - 1, 1, -1):
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', parts[j].strip(), re.IGNORECASE):
                client_id = parts[j].strip()
                token_end = j
                break

        if not client_id:
            client_id = parts[-1].strip()
            token_end = len(parts) - 1

        refresh_token = ":".join(parts[2:token_end]).strip()

        if not email or "@" not in email:
            errors.append(f"Line {i}: invalid email `{email}`")
            continue
        if not refresh_token:
            errors.append(f"Line {i}: missing refresh_token")
            continue

        new_tokens[email.lower()] = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "password": password,
        }

    added = 0
    if new_tokens:
        added = save_tokens_bulk(new_tokens)

    total_saved = len(load_saved_tokens())
    desc = f"✅ **{added}** account(s) imported\n📁 **{total_saved}** total saved"
    if errors:
        desc += f"\n⚠️ **{len(errors)}** error(s):\n" + "\n".join(errors[:10])
        if len(errors) > 10:
            desc += f"\n...and {len(errors) - 10} more"

    embed = discord.Embed(title="📤 Upload Results", description=desc, color=0x00FF00 if added else 0xFFAA00)
    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)


# ── /export command (download current tokens as txt) ───────────────────────────

@bot.tree.command(name="export", description="Export a number of saved tokens as a .txt file")
@app_commands.describe(amount="Number of accounts to export")
async def export_slash(interaction: discord.Interaction, amount: int):
    await interaction.response.defer(ephemeral=True)

    tokens = load_saved_tokens()
    if not tokens:
        await interaction.followup.send("❌ No saved tokens to export.", ephemeral=True)
        return

    if amount < 1:
        await interaction.followup.send("❌ Amount must be at least 1.", ephemeral=True)
        return

    items = list(tokens.items())
    total = len(items)
    items = items[:amount]

    lines = []
    for email, data in items:
        pw = data.get("password", "")
        lines.append(f"{email}:{pw}:{data['refresh_token']}:{data['client_id']}")

    content = "\n".join(lines)
    file = discord.File(io.BytesIO(content.encode("utf-8")), filename="tokens_backup.txt")

    desc = f"📁 Exported **{len(items)}** of **{total}** accounts"
    await interaction.followup.send(desc, file=file, ephemeral=True)


# ── /list command (show saved emails) ──────────────────────────────────────────

@bot.tree.command(name="list", description="List all saved email accounts")
async def list_slash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    tokens = load_saved_tokens()
    if not tokens:
        await interaction.followup.send("❌ No saved tokens.", ephemeral=True)
        return

    emails = list(tokens.keys())
    pages = [emails[i:i+20] for i in range(0, len(emails), 20)]

    desc = f"📁 **{len(emails)}** saved account(s):\n\n"
    desc += "\n".join(f"`{e}`" for e in pages[0])
    if len(pages) > 1:
        desc += f"\n\n...and {len(emails) - 20} more"

    embed = discord.Embed(title="📋 Saved Accounts", description=desc, color=0x5865F2)
    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)


# ── /remove command (admin only) ───────────────────────────────────────────────

def is_admin(interaction: discord.Interaction) -> bool:
    """Check if user has Administrator permission or a role named 'Admin'."""
    if interaction.user.guild_permissions.administrator:
        return True
    return any(role.name.lower() == "admin" for role in interaction.user.roles)

@bot.tree.command(name="remove", description="[Admin] Remove a saved email account")
@app_commands.describe(email="Email to remove")
async def remove_slash(interaction: discord.Interaction, email: str):
    await interaction.response.defer(ephemeral=True)

    if not is_admin(interaction):
        await interaction.followup.send("❌ You need the **Admin** role or **Administrator** permission to use this.", ephemeral=True)
        return

    tokens = load_saved_tokens()
    email = email.strip().lower()

    if email not in tokens:
        await interaction.followup.send(f"❌ `{email}` not found in saved tokens.", ephemeral=True)
        return

    del tokens[email]
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=4)

    await interaction.followup.send(f"✅ Removed `{email}`. **{len(tokens)}** accounts remaining.", ephemeral=True)


# ── Bot Ready ──────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    print(f"✅ Bot online: {bot.user}")
    print(f"📁 Data dir: {DATA_DIR}")
    print(f"📁 Tokens file: {TOKENS_FILE}")
    print(f"📁 Saved accounts: {len(load_saved_tokens())}")
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
