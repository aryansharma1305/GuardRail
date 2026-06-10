# 🛡️ Guardrail — AI Security Scanner

> Real-time security vulnerability detection for AI-generated code.
> Built for developers using Copilot, Cursor, and other AI coding tools.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![VS Code](https://img.shields.io/badge/VS%20Code-Extension-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)

---

## What is Guardrail?

Guardrail is a VS Code extension that scans your code for security 
vulnerabilities in real-time as you type. Powered by AI, it detects 
issues that linters miss — hardcoded secrets, SQL injection, insecure 
deserialization, and 25+ other vulnerability types.

---

## How It Works

1. You write code in VS Code or Cursor
2. Guardrail watches for changes (2 second debounce)
3. Sends code to FastAPI backend
4. AI analyzes for security vulnerabilities
5. Red underlines appear on vulnerable lines instantly
6. Click to see description + one-click fix

---

## Vulnerabilities Detected

### 🔑 Secrets & Keys
- Hardcoded API keys (OpenAI, AWS, Stripe, etc.)
- Hardcoded passwords and weak secrets
- Private keys and JWT secrets in source code
- Exposed database connection strings

### 💉 Injection Attacks
- SQL injection
- Command injection
- Path traversal
- Insecure deserialization (pickle, eval)
- NoSQL injection

### 🔐 Authentication & Authorization
- Broken JWT validation
- Missing rate limiting
- Weak password hashing (MD5, SHA1)
- Missing CSRF protection
- Session tokens in URLs

### 📊 Data Exposure
- Sensitive data in logs
- Stack traces exposed to users
- Open CORS policies
- Debug mode in production
- Weak cryptographic hashing

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| VS Code Extension | TypeScript |
| Backend API | Python + FastAPI |
| AI Engine | OpenRouter (qwen, nvidia, groq, gemini fallback chain) |
| Cache / Rate Limiting | Redis via Upstash |
| Database | PostgreSQL via Supabase (Phase 3) |
| Dashboard | Next.js 14 + Tailwind (Phase 3) |
| Deployment | Railway.app |

---

## Project Structure

```
guardrail/
├── extension/          # VS Code extension (TypeScript)
│   └── src/
│       ├── extension.ts
│       ├── analyzer.ts
│       ├── diagnostics.ts
│       ├── codeActions.ts
│       └── debounce.ts
├── api/                # FastAPI backend (Python)
│   ├── main.py
│   ├── routes/
│   ├── services/
│   └── models/
└── dashboard/          # Next.js dashboard (Phase 3)
```

---

## Local Development

### Backend API

```bash
cd api
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys
uvicorn main:app --reload
```

### VS Code Extension

```bash
cd extension
npm install
npm run compile
# Press F5 in VS Code to open Extension Development Host
```

### Environment Variables

```env
OPENROUTER_API_KEY=sk-or-...
GROQ_API_KEY=gsk_...
GEMINI_API_KEY=AIza...
MODEL_NAME=qwen/qwen3-coder:free
UPSTASH_REDIS_URL=https://xxx.upstash.io
UPSTASH_REDIS_TOKEN=your-token
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_KEY=your-key
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| POST | /analyze | Scan code for vulnerabilities |

### POST /analyze

Request:
```json
{
  "code": "your code here",
  "language": "python",
  "api_key": "your-api-key"
}
```

Response:
```json
{
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "SQL Injection",
      "severity": "critical",
      "line": 1,
      "description": "User input directly in SQL query",
      "fix": "Use parameterized queries",
      "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = ?', (id,))"
    }
  ],
  "scan_id": "uuid",
  "language": "python",
  "scanned_at": "2026-06-11T00:00:00Z"
}
```

---

## Supported Languages

Python, JavaScript, TypeScript, Java, PHP, Go

---

## Rate Limits

| Plan | Scans/day |
|------|-----------|
| Free | 50 |
| Pro | Unlimited |

---

## Roadmap

- [x] Phase 1 — FastAPI backend with AI scanning
- [x] Phase 2 — VS Code extension with inline diagnostics
- [ ] Phase 3 — Next.js dashboard with scan history
- [ ] Phase 4 — GitHub Action for CI/CD scanning
- [ ] Phase 5 — One-click repo audit tool

---

## Privacy

Code snippets are sent to the Guardrail API for analysis.
They are not stored permanently. Scan metadata (language, 
vulnerability count) is logged for usage tracking only.

---

## Contributing

Pull requests welcome. Please open an issue first to 
discuss what you would like to change.

---

## License

MIT License — see LICENSE file for details.

---

## Author

Built by Aryan Sharma  
GitHub: [@aryansharma1305](https://github.com/aryansharma1305)
