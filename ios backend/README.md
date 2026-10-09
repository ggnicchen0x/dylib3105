# 3105 License & Anti-Tamper Authentication Gateway

Production-grade FastAPI authentication, DRM licensing, and hardware-locking backend designed for the 3105 iOS Free Fire Max External Menu.

---

## 🔒 Security Architecture Overview

1. **Strict 1-Key = 1-Device Hardware Binding (HWID)**:
   - On first activation, the license key is cryptographically bound to a 256-bit salted hardware fingerprint (`IDFV + Machine Model + OS Version + Salt`).
   - Subsequent login requests from any other device are permanently rejected (`HTTP 409 CONFLICT`).
2. **Anti-Replay & HMAC Signature Verification**:
   - Every client request must include a UNIX timestamp and an `HMAC-SHA256` signature of `license_key:device_hash:timestamp`.
   - Requests with timestamp drift > 60 seconds or mismatched signatures are rejected.
3. **Session Heartbeat & Dynamic Validation**:
   - iOS client submits periodic heartbeat tokens (`/api/v1/auth/validate`).
   - If an admin revokes or bans a key/device on the backend, the running app terminates access immediately.
4. **Discord Webhook Intrusion Monitoring**:
   - Real-time alerts for key activations and unauthorized sharing / crack attempts with device models and IP logs.

---

## 🚀 Deployment on Bot Hosting (Python Egg)

### 1. Upload Files
Upload all files in the `backend/` directory to your Bot Hosting Python egg root.

### 2. Install Dependencies
Run in the server console:
```bash
pip install -r requirements.txt
```

### 3. Environment Variables (Optional)
Set these in your host panel or `.env`:
```env
PORT=8000
SECRET_KEY=3105_SEC_KEY_e4b0546a57c844ddb94cdbd2e2393df1_PROD
HMAC_SECRET=3105_HMAC_SIG_k9823hjd8923hjksdf78234
ADMIN_API_KEY=3105_ADMIN_ROOT_9021839012389
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### 4. Startup Command
In Bot Hosting startup command field:
```bash
python main.py
```
or
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

---

## 🔑 Generating License Keys

### Via CLI:
```bash
# Generate 10 lifetime keys
python gen_keys.py -n 10

# Generate 5 keys valid for 30 days
python gen_keys.py -n 5 -d 30 --notes "VIP Customer"
```

### Via Admin REST API:
```bash
curl -X POST "https://your-bot-host.com/api/v1/admin/generate-keys" \
  -H "x-admin-key: 3105_ADMIN_ROOT_9021839012389" \
  -H "Content-Type: application/json" \
  -d '{"count": 5, "duration_days": 30, "prefix": "3105-MAX", "notes": "VIP Reseller"}'
```
