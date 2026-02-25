# 🔐 Uber Code Discord Bot

A Discord bot that fetches the latest Uber verification code from an Outlook/Hotmail email inbox.

## How It Works

1. User runs `/ubercode` with their Outlook email and password
2. Bot connects to Outlook via IMAP (SSL)
3. Searches inbox for emails from Uber
4. Extracts the verification/OTP code
5. Returns it **privately** (ephemeral message — only the user can see it)

## Setup

### 1. Create a Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **New Application** → give it a name
3. Go to **Bot** tab → click **Reset Token** → copy the token
4. Enable **Message Content Intent** under Privileged Gateway Intents
5. Go to **OAuth2 → URL Generator**:
   - Scopes: `bot`, `applications.commands`
   - Bot Permissions: `Send Messages`, `Manage Messages`, `Read Message History`
6. Copy the generated URL and open it to invite the bot to your server

### 2. Configure the Bot

```bash
cp .env.example .env
```

Edit `.env` and paste your bot token:
```
DISCORD_BOT_TOKEN=your_token_here
```

### 3. Install & Run

```bash
pip install -r requirements.txt
python bot.py
```

## Usage

### Slash Command (Recommended — credentials stay hidden)
```
/ubercode email:you@outlook.com password:yourpassword
```
The response is **ephemeral** — only you can see it.

### Prefix Command
```
!ubercode you@outlook.com yourpassword
```
The bot **deletes your message** immediately and **DMs you** the code.

## ⚠️ Important Notes

### Outlook Authentication
- If you have **2FA/MFA enabled**, you need to generate an **App Password**:
  1. Go to [Microsoft Account Security](https://account.microsoft.com/security)
  2. Select **Advanced security options**
  3. Under **App passwords**, click **Create a new app password**
  4. Use this app password instead of your regular password
- Make sure **IMAP is enabled** in your Outlook settings:
  1. Go to Outlook.com → Settings → **Mail → Sync email**
  2. Under **POP and IMAP**, toggle on IMAP

### Security Considerations
- The `/ubercode` slash command keeps credentials **completely hidden** from other users
- The `!ubercode` prefix command **auto-deletes** the user's message and sends results via DM
- Credentials are **never stored** — they're used once per request and discarded
- Consider running this bot on a trusted, private server only
