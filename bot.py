import discord
from discord.ext import commands
from discord import app_commands
import requests
import re
import os
import json
import io
import asyncio
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Bot Setup ──────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# ── Persistent Storage (Render Disk) ──────────────────────────────────────────
DATA_DIR = os.getenv("DATA_DIR", ".")
os.makedirs(DATA_DIR, exist_ok=True)
TOKENS_FILE = os.path.join(DATA_DIR, "saved_tokens.json")
USED_CODES_FILE = os.path.join(DATA_DIR, "used_codes.json")
EMAILS_FILE = os.path.join(DATA_DIR, "saved_emails.json")
WHITELIST_FILE = os.path.join(DATA_DIR, "mail_whitelist.json")

# Single lock for ALL file operations — no concurrent writes possible
file_lock = asyncio.Lock()

DEFAULT_TENANT = os.getenv("AZURE_TENANT", "consumers")
DEFAULT_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
LOG_CHANNEL_ID = 1399288304767074404

TOKEN_URL = f"https://login.microsoftonline.com/{DEFAULT_TENANT}/oauth2/v2.0/token"
GRAPH_URL = "https://graph.microsoft.com/v1.0"


# ── File helpers (ONLY call these inside file_lock) ───────────────────────────

def _read_tokens() -> dict:
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    return {}

def _write_tokens(tokens: dict):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=4)

def _read_used_codes() -> dict:
    """Returns {email: [code1, code2, ...]}"""
    if os.path.exists(USED_CODES_FILE):
        with open(USED_CODES_FILE, "r") as f:
            return json.load(f)
    return {}

def _write_used_codes(data: dict):
    with open(USED_CODES_FILE, "w") as f:
        json.dump(data, f, indent=4)

def _read_emails() -> list:
    """Returns list of {email, password, recovery} dicts."""
    if os.path.exists(EMAILS_FILE):
        with open(EMAILS_FILE, "r") as f:
            return json.load(f)
    return []

def _write_emails(data: list):
    with open(EMAILS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def _read_whitelist() -> list:
    """Returns list of whitelisted user IDs (as strings)."""
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            return json.load(f)
    return []

def _write_whitelist(data: list):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(data, f, indent=4)

def is_mail_authorized(interaction: discord.Interaction) -> bool:
    """Admins always pass. Whitelisted user IDs also pass."""
    if interaction.user.guild_permissions.administrator:
        return True
    if any(role.name.lower() == "admin" for role in interaction.user.roles):
        return True
    whitelist = _read_whitelist()
    return str(interaction.user.id) in whitelist

def _parse_email_line(line: str) -> dict | None:
    """Parse any supported combo into a normalized dict. Returns None on failure."""
    # Normalize delimiter — allow : or ;
    normalized = line.replace(";", ":")
    parts = [p.strip() for p in normalized.split(":")]
    parts = [p for p in parts if p]  # drop empty segments

    if len(parts) < 2:
        return None

    email = parts[0]
    if "@" not in email:
        return None

    password = parts[1]
    recovery = parts[2] if len(parts) >= 3 else ""

    return {"email": email.lower(), "password": password, "recovery": recovery}


# ── Code Extraction ───────────────────────────────────────────────────────────

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

def get_token(refresh_token: str, client_id: str):
    data = {
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": "https://graph.microsoft.com/.default",
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


# ── Fetch Uber Code (pure function — does NOT touch any files) ────────────────

def fetch_uber_code(refresh_token: str, client_id: str, used_codes: set = None, keyword: str = "uber"):
    """Fetches verification code from inbox by keyword. Returns result dict. Never writes files."""
    used_codes = used_codes or set()
    kw = keyword.lower().strip()

    token, error = get_token(refresh_token, client_id)
    if error:
        return {"success": False, "error": error}

    headers = {"Authorization": f"Bearer {token}"}

    try:
        me_resp = requests.get(f"{GRAPH_URL}/me?$select=mail,userPrincipalName", headers=headers, timeout=15)
        me = me_resp.json()
    except Exception as e:
        return {"success": False, "error": f"Network error: {e}"}

    account_email = me.get("mail") or me.get("userPrincipalName") or "Unknown"

    params = {
        "$top": 200,
        "$select": "subject,body,from,receivedDateTime",
    }

    try:
        resp = requests.get(
            f"{GRAPH_URL}/me/messages",
            headers={**headers, "ConsistencyLevel": "eventual"},
            params=params, timeout=15,
        )
    except Exception as e:
        return {"success": False, "error": f"Network error: {e}", "email": account_email}

    if resp.status_code != 200:
        return {"success": False, "error": f"Graph error {resp.status_code}: {resp.text[:200]}", "email": account_email}

    messages = resp.json().get("value", [])
    if not messages:
        return {"success": False, "error": "No emails found in inbox", "email": account_email}

    def parse_date(d):
        try:
            return datetime.fromisoformat(d.replace("Z", "+00:00"))
        except:
            return datetime.min

    messages.sort(key=lambda x: parse_date(x.get("receivedDateTime", "")), reverse=True)

    # Priority: verification code subject lines
    for msg in messages:
        subject = msg.get("subject", "").lower()
        if f"your {kw} verification code" in subject or "verification code" in subject:
            body = msg.get("body", {})
            body_text = strip_html(body.get("content", "")) if body.get("contentType") == "html" else body.get("content", "")
            code = extract_code(subject + " " + body_text)
            if code and code not in used_codes:
                return {
                    "success": True,
                    "code": code,
                    "subject": msg.get("subject", "")[:100],
                    "from": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                    "date": msg.get("receivedDateTime", "")[:19].replace("T", " "),
                    "email": account_email,
                }

    # Fallback: any Uber email
    for msg in messages:
        subject = msg.get("subject", "").lower()
        from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "").lower()
        if kw not in subject and kw not in from_addr:
            continue
        body = msg.get("body", {})
        body_text = strip_html(body.get("content", "")) if body.get("contentType") == "html" else body.get("content", "")
        code = extract_code(subject + " " + body_text)
        if code and code not in used_codes:
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
        "error": f"No new {kw} verification code found (all codes already used)",
        "email": account_email,
    }


# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

# ── /code ──────────────────────────────────────────────────────────────────────

@bot.tree.command(name="code", description="Get Uber code — email or token:client_id")
@app_commands.describe(
    input="email@outlook.com   OR   refresh_token:client_id",
    keyword="Sender keyword to search for (default: uber)",
)
async def code_slash(interaction: discord.Interaction, input: str, keyword: str = "uber"):
    await interaction.response.defer(ephemeral=True)

    # 1) Figure out which refresh_token + client_id to use
    if "@" in input and ":" not in input:
        email = input.strip().lower()
        async with file_lock:
            saved = _read_tokens()
        if email not in saved:
            await interaction.followup.send(
                f"❌ No saved token for `{email}`.\nUse `/upload` to add accounts first.",
                ephemeral=True,
            )
            return
        rt = saved[email]["refresh_token"]
        cid = saved[email]["client_id"]
    elif ":" in input:
        parts = input.split(":", 1)
        rt = parts[0].strip()
        cid = parts[1].strip()
    else:
        await interaction.followup.send("❌ Wrong format.\nUse: `email@outlook.com` or `refresh_token:client_id`", ephemeral=True)
        return

    # 2) Load used codes for this token (so we skip already-returned codes)
    async with file_lock:
        all_used = _read_used_codes()
    token_key = rt[:20]  # use first 20 chars of refresh token as key
    used_set = set(all_used.get(token_key, []))

    # 3) Fetch code (pure function, no file writes)
    result = fetch_uber_code(refresh_token=rt, client_id=cid, used_codes=used_set, keyword=keyword)

    # 4) If we got a code, mark it as used
    if result["success"]:
        async with file_lock:
            all_used = _read_used_codes()  # re-read fresh
            if token_key not in all_used:
                all_used[token_key] = []
            all_used[token_key].append(result["code"])
            _write_used_codes(all_used)

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


# ── /read ──────────────────────────────────────────────────────────────────────

def fetch_recent_emails(refresh_token: str, client_id: str, count: int = 3):
    """Fetches the last `count` emails in full. Returns list of email dicts."""
    token, error = get_token(refresh_token, client_id)
    if error:
        return None, error

    headers = {"Authorization": f"Bearer {token}"}

    try:
        me_resp = requests.get(f"{GRAPH_URL}/me?$select=mail,userPrincipalName", headers=headers, timeout=15)
        me = me_resp.json()
    except Exception as e:
        return None, f"Network error: {e}"

    account_email = me.get("mail") or me.get("userPrincipalName") or "Unknown"

    params = {
        "$top": count,
        "$orderby": "receivedDateTime desc",
        "$select": "subject,body,from,receivedDateTime",
    }

    try:
        resp = requests.get(f"{GRAPH_URL}/me/messages", headers=headers, params=params, timeout=15)
    except Exception as e:
        return None, f"Network error: {e}"

    if resp.status_code != 200:
        return None, f"Graph error {resp.status_code}: {resp.text[:200]}"

    messages = resp.json().get("value", [])
    results = []
    for msg in messages:
        body = msg.get("body", {})
        body_text = strip_html(body.get("content", "")) if body.get("contentType") == "html" else body.get("content", "")
        results.append({
            "account": account_email,
            "subject": msg.get("subject", "(no subject)")[:100],
            "from": msg.get("from", {}).get("emailAddress", {}).get("address", "Unknown"),
            "date": msg.get("receivedDateTime", "")[:19].replace("T", " "),
            "body": body_text[:900],  # cap per email so we stay under Discord limits
        })

    return results, None


@bot.tree.command(name="read", description="Read the full body of the last 3 emails")
@app_commands.describe(input="email@outlook.com   OR   refresh_token:client_id")
async def read_slash(interaction: discord.Interaction, input: str):
    await interaction.response.defer(ephemeral=True)

    # Resolve credentials
    if "@" in input and ":" not in input:
        email = input.strip().lower()
        async with file_lock:
            saved = _read_tokens()
        if email not in saved:
            await interaction.followup.send(
                f"❌ No saved token for `{email}`.\nUse `/upload` to add accounts first.",
                ephemeral=True,
            )
            return
        rt = saved[email]["refresh_token"]
        cid = saved[email]["client_id"]
    elif ":" in input:
        parts = input.split(":", 1)
        rt = parts[0].strip()
        cid = parts[1].strip()
    else:
        await interaction.followup.send("❌ Wrong format.\nUse: `email@outlook.com` or `refresh_token:client_id`", ephemeral=True)
        return

    emails, error = fetch_recent_emails(rt, cid, count=3)

    if error:
        embed = discord.Embed(title="❌ Failed", description=error, color=0xFF0000)
        embed.set_footer(text="Only you can see this")
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    if not emails:
        await interaction.followup.send("❌ No emails found in inbox.", ephemeral=True)
        return

    embeds = []
    for i, msg in enumerate(emails, 1):
        embed = discord.Embed(
            title=f"📧 Email {i} of {len(emails)}",
            description=f"**Account:** `{msg['account']}`",
            color=0x5865F2,
        )
        embed.add_field(name="From", value=f"`{msg['from']}`", inline=True)
        embed.add_field(name="Date", value=msg["date"], inline=True)
        embed.add_field(name="Subject", value=msg["subject"], inline=False)
        embed.add_field(name="Body", value=msg["body"] or "(empty)", inline=False)
        embed.set_footer(text="Only you can see this")
        embeds.append(embed)

    await interaction.followup.send(embeds=embeds, ephemeral=True)


# ── /upload ────────────────────────────────────────────────────────────────────

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

    # Parse all lines first (no file access needed)
    parsed = {}
    errors = []
    for i, line in enumerate(lines, 1):
        parts = line.split(":")
        if len(parts) < 4:
            errors.append(f"Line {i}: not enough fields")
            continue

        email = parts[0].strip()
        password = parts[1].strip()

        # Find client_id UUID from the end
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
            errors.append(f"Line {i}: invalid email")
            continue
        if not refresh_token:
            errors.append(f"Line {i}: missing token")
            continue

        parsed[email.lower()] = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "password": password,
        }

    # Single locked read-modify-write
    async with file_lock:
        tokens = _read_tokens()
        added = 0
        skipped = []
        for email, data in parsed.items():
            if email in tokens:
                skipped.append(f"`{email}` (duplicate)")
            else:
                tokens[email] = data
                added += 1
        _write_tokens(tokens)
        total_saved = len(tokens)

    desc = f"✅ **{added}** imported\n📁 **{total_saved}** total"
    if skipped:
        desc += f"\n⚠️ **{len(skipped)}** skipped:\n" + "\n".join(skipped[:10])
        if len(skipped) > 10:
            desc += f"\n...+{len(skipped) - 10} more"
    if errors:
        desc += f"\n❌ **{len(errors)}** error(s):\n" + "\n".join(errors[:10])

    embed = discord.Embed(title="📤 Upload Results", description=desc, color=0x00FF00 if added else 0xFFAA00)
    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)

    # Log
    try:
        ch = bot.get_channel(LOG_CHANNEL_ID)
        if ch:
            e = discord.Embed(title="📤 Upload Log", color=0x5865F2, timestamp=datetime.utcnow())
            e.add_field(name="User", value=f"{interaction.user} (`{interaction.user.id}`)", inline=True)
            e.add_field(name="Added", value=f"**{added}**", inline=True)
            e.add_field(name="Skipped", value=f"**{len(skipped)}**", inline=True)
            e.add_field(name="Total", value=f"**{total_saved}**", inline=True)
            await ch.send(embed=e)
    except Exception:
        pass


# ── /export (dispense + delete, atomic) ───────────────────────────────────────

@bot.tree.command(name="export", description="Dispense accounts as .txt and remove them")
@app_commands.describe(amount="Number of accounts to dispense")
async def export_slash(interaction: discord.Interaction, amount: int):
    await interaction.response.defer(ephemeral=True)

    if amount < 1:
        await interaction.followup.send("❌ Amount must be at least 1.", ephemeral=True)
        return

    # Single locked read-modify-write
    async with file_lock:
        tokens = _read_tokens()

        if not tokens:
            await interaction.followup.send("❌ No saved tokens.", ephemeral=True)
            return

        # Take first N
        keys_to_take = list(tokens.keys())[:amount]
        taken = {k: tokens.pop(k) for k in keys_to_take}

        _write_tokens(tokens)
        remaining = len(tokens)

    # Build file outside lock
    lines = []
    for email, data in taken.items():
        pw = data.get("password", "")
        lines.append(f"{email}:{pw}:{data['refresh_token']}:{data['client_id']}")

    content = "\n".join(lines)
    txt_file = discord.File(io.BytesIO(content.encode("utf-8")), filename="tokens_export.txt")

    desc = f"📤 Dispensed **{len(taken)}**\n📁 **{remaining}** remaining"
    await interaction.followup.send(desc, file=txt_file, ephemeral=True)

    # Log
    try:
        ch = bot.get_channel(LOG_CHANNEL_ID)
        if ch:
            e = discord.Embed(title="📦 Export Log", color=0xFF9900, timestamp=datetime.utcnow())
            e.add_field(name="User", value=f"{interaction.user} (`{interaction.user.id}`)", inline=True)
            e.add_field(name="Dispensed", value=f"**{len(taken)}**", inline=True)
            e.add_field(name="Remaining", value=f"**{remaining}**", inline=True)
            await ch.send(embed=e)
    except Exception:
        pass


# ── /list ──────────────────────────────────────────────────────────────────────

@bot.tree.command(name="list", description="List all saved email accounts")
async def list_slash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    async with file_lock:
        tokens = _read_tokens()

    if not tokens:
        await interaction.followup.send("❌ No saved tokens.", ephemeral=True)
        return

    emails = list(tokens.keys())
    desc = f"📁 **{len(emails)}** saved account(s):\n\n"
    desc += "\n".join(f"`{e}`" for e in emails[:20])
    if len(emails) > 20:
        desc += f"\n\n...and {len(emails) - 20} more"

    embed = discord.Embed(title="📋 Saved Accounts", description=desc, color=0x5865F2)
    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)


# ── /remove (admin only) ──────────────────────────────────────────────────────

def is_admin(interaction: discord.Interaction) -> bool:
    if interaction.user.guild_permissions.administrator:
        return True
    return any(role.name.lower() == "admin" for role in interaction.user.roles)

@bot.tree.command(name="remove", description="[Admin] Remove a saved email account")
@app_commands.describe(email="Email to remove")
async def remove_slash(interaction: discord.Interaction, email: str):
    await interaction.response.defer(ephemeral=True)

    if not is_admin(interaction):
        await interaction.followup.send("❌ You need **Admin** role or **Administrator** permission.", ephemeral=True)
        return

    async with file_lock:
        tokens = _read_tokens()
        email = email.strip().lower()
        if email not in tokens:
            await interaction.followup.send(f"❌ `{email}` not found.", ephemeral=True)
            return
        del tokens[email]
        _write_tokens(tokens)
        remaining = len(tokens)

    await interaction.followup.send(f"✅ Removed `{email}`. **{remaining}** remaining.", ephemeral=True)


# ── /stock (quick count) ──────────────────────────────────────────────────────

@bot.tree.command(name="stock", description="Check how many accounts are saved")
async def stock_slash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    async with file_lock:
        tokens = _read_tokens()
    embed = discord.Embed(title="📊 Stock", description=f"**{len(tokens)}** accounts available", color=0x5865F2)
    await interaction.followup.send(embed=embed, ephemeral=True)


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL DISPENSER
# ══════════════════════════════════════════════════════════════════════════════

# ── /addmails ─────────────────────────────────────────────────────────────────

@bot.tree.command(name="addmails", description="Bulk-add emails. Paste combos directly (email:pass:recovery etc.)")
@app_commands.describe(combos="Paste all combos here, one per line. Supports : or ; delimiters, with or without recovery.")
async def addmails_slash(interaction: discord.Interaction, combos: str):
    await interaction.response.defer(ephemeral=True)

    if not is_mail_authorized(interaction):
        await interaction.followup.send("❌ You are not whitelisted to use this command.", ephemeral=True)
        return

    lines = [l.strip() for l in combos.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        await interaction.followup.send("❌ No valid lines found.", ephemeral=True)
        return

    parsed = []
    errors = []
    for i, line in enumerate(lines, 1):
        entry = _parse_email_line(line)
        if entry:
            parsed.append(entry)
        else:
            errors.append(f"Line {i}: could not parse `{line[:60]}`")

    async with file_lock:
        existing = _read_emails()
        existing_emails = {e["email"] for e in existing}
        added = 0
        skipped = []
        for entry in parsed:
            if entry["email"] in existing_emails:
                skipped.append(f"`{entry['email']}` (duplicate)")
            else:
                existing.append(entry)
                existing_emails.add(entry["email"])
                added += 1
        _write_emails(existing)
        total = len(existing)

    desc = f"✅ **{added}** added\n📁 **{total}** total"
    if skipped:
        desc += f"\n⚠️ **{len(skipped)}** skipped:\n" + "\n".join(skipped[:10])
        if len(skipped) > 10:
            desc += f"\n...+{len(skipped) - 10} more"
    if errors:
        desc += f"\n❌ **{len(errors)}** error(s):\n" + "\n".join(errors[:10])

    embed = discord.Embed(title="📥 Mail Import Results", description=desc, color=0x00FF00 if added else 0xFFAA00)
    embed.set_footer(text="Only you can see this")
    await interaction.followup.send(embed=embed, ephemeral=True)

    try:
        ch = bot.get_channel(LOG_CHANNEL_ID)
        if ch:
            e = discord.Embed(title="📥 Mail Import Log", color=0x5865F2, timestamp=datetime.utcnow())
            e.add_field(name="User", value=f"{interaction.user} (`{interaction.user.id}`)", inline=True)
            e.add_field(name="Added", value=f"**{added}**", inline=True)
            e.add_field(name="Total", value=f"**{total}**", inline=True)
            await ch.send(embed=e)
    except Exception:
        pass


# ── /exportmail ───────────────────────────────────────────────────────────────

@bot.tree.command(name="exportmail", description="Dispense email accounts as .txt and remove them")
@app_commands.describe(amount="Number of accounts to dispense")
async def exportmail_slash(interaction: discord.Interaction, amount: int):
    await interaction.response.defer(ephemeral=True)

    if not is_mail_authorized(interaction):
        await interaction.followup.send("❌ You are not whitelisted to use this command.", ephemeral=True)
        return

    if amount < 1:
        await interaction.followup.send("❌ Amount must be at least 1.", ephemeral=True)
        return

    async with file_lock:
        emails = _read_emails()
        if not emails:
            await interaction.followup.send("❌ No saved email accounts.", ephemeral=True)
            return

        taken = emails[:amount]
        remaining_list = emails[amount:]
        _write_emails(remaining_list)
        remaining = len(remaining_list)

    # Format output: email:pass:recovery or email:pass if no recovery
    lines = []
    for entry in taken:
        if entry.get("recovery"):
            lines.append(f"{entry['email']}:{entry['password']}:{entry['recovery']}")
        else:
            lines.append(f"{entry['email']}:{entry['password']}")

    content = "\n".join(lines)
    txt_file = discord.File(io.BytesIO(content.encode("utf-8")), filename="emails_export.txt")

    desc = f"📤 Dispensed **{len(taken)}**\n📁 **{remaining}** remaining"
    await interaction.followup.send(desc, file=txt_file, ephemeral=True)

    try:
        ch = bot.get_channel(LOG_CHANNEL_ID)
        if ch:
            e = discord.Embed(title="📦 Mail Export Log", color=0xFF9900, timestamp=datetime.utcnow())
            e.add_field(name="User", value=f"{interaction.user} (`{interaction.user.id}`)", inline=True)
            e.add_field(name="Dispensed", value=f"**{len(taken)}**", inline=True)
            e.add_field(name="Remaining", value=f"**{remaining}**", inline=True)
            await ch.send(embed=e)
    except Exception:
        pass


# ── /stockmail ────────────────────────────────────────────────────────────────

@bot.tree.command(name="stockmail", description="Check how many email accounts are saved")
async def stockmail_slash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if not is_mail_authorized(interaction):
        await interaction.followup.send("❌ You are not whitelisted to use this command.", ephemeral=True)
        return
    async with file_lock:
        emails = _read_emails()
    embed = discord.Embed(title="📊 Mail Stock", description=f"**{len(emails)}** email accounts available", color=0x5865F2)
    await interaction.followup.send(embed=embed, ephemeral=True)


# ── /mailwhitelist (admin only) ───────────────────────────────────────────────

@bot.tree.command(name="mailwhitelist", description="[Admin] Manage whitelist for email dispenser commands")
@app_commands.describe(
    action="add / remove / list",
    user="The user to add or remove (not needed for list)",
)
async def mailwhitelist_slash(interaction: discord.Interaction, action: str, user: discord.Member = None):
    await interaction.response.defer(ephemeral=True)

    if not is_admin(interaction):
        await interaction.followup.send("❌ You need **Admin** role or **Administrator** permission.", ephemeral=True)
        return

    action = action.strip().lower()

    if action == "list":
        async with file_lock:
            whitelist = _read_whitelist()
        if not whitelist:
            await interaction.followup.send("📋 Whitelist is empty.", ephemeral=True)
            return
        lines = []
        for uid in whitelist:
            member = interaction.guild.get_member(int(uid))
            lines.append(f"<@{uid}> (`{uid}`)" if member else f"`{uid}` (not in server)")
        embed = discord.Embed(
            title="📋 Mail Whitelist",
            description="\n".join(lines),
            color=0x5865F2,
        )
        embed.set_footer(text=f"{len(whitelist)} user(s)")
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    if user is None:
        await interaction.followup.send("❌ Please specify a user for `add` or `remove`.", ephemeral=True)
        return

    uid = str(user.id)

    async with file_lock:
        whitelist = _read_whitelist()

        if action == "add":
            if uid in whitelist:
                await interaction.followup.send(f"⚠️ {user.mention} is already whitelisted.", ephemeral=True)
                return
            whitelist.append(uid)
            _write_whitelist(whitelist)
            await interaction.followup.send(f"✅ Added {user.mention} to the mail whitelist.", ephemeral=True)

        elif action == "remove":
            if uid not in whitelist:
                await interaction.followup.send(f"❌ {user.mention} is not in the whitelist.", ephemeral=True)
                return
            whitelist.remove(uid)
            _write_whitelist(whitelist)
            await interaction.followup.send(f"✅ Removed {user.mention} from the mail whitelist.", ephemeral=True)

        else:
            await interaction.followup.send("❌ Invalid action. Use `add`, `remove`, or `list`.", ephemeral=True)


# ── Bot Ready ──────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    print(f"✅ Bot online: {bot.user}")
    print(f"📁 Data dir: {DATA_DIR}")
    print(f"📁 Tokens: {TOKENS_FILE}")
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            print(f"📁 Accounts: {len(json.load(f))}")
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
