# Guardrail API

AI-powered code security scanner — FastAPI backend.

## Local Development

```bash
cp .env.example .env
# Fill in all env variables
pip install -r requirements.txt
uvicorn main:app --reload
```

## Deploy to Railway

1. Push code to GitHub
2. Connect repo in Railway dashboard
3. Add all env variables from `.env.example`
4. Railway auto-deploys on every push to `main`

## Test the live API

```bash
curl -X POST https://your-railway-url.railway.app/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
    "language": "python",
    "api_key": "test-key-123"
  }'
```
