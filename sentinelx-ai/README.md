# SentinelX AI – Autonomous Security Operations Platform

<p align="center">
  <strong>Intelligent Threat Detection • Automated Response • AI-Powered SOC</strong>
</p>

---

## 🛡️ Overview

SentinelX AI is a production-quality cybersecurity platform providing autonomous security operations capabilities including real-time threat detection, incident management, vulnerability tracking, and AI-powered security analytics.

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS |
| **Backend** | FastAPI, Python 3.12, SQLAlchemy 2.0 |
| **Database** | PostgreSQL 17 (Supabase) |
| **AI** | Google Gemini API |
| **Real-time** | WebSocket, Supabase Realtime |
| **Deployment** | Vercel (FE), Render (BE), Docker |

## 🚀 Quick Start

### Prerequisites

- Node.js 22+
- Python 3.12+
- Git

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend runs at `http://localhost:8000`

### Docker (Full Stack)

```bash
cp .env.example .env
# Edit .env with your credentials
docker compose up --build
```

## 📁 Project Structure

```
sentinelx-ai/
├── frontend/          # React + Vite + Tailwind
├── backend/           # FastAPI + SQLAlchemy
├── database/          # Schema docs & seeds
├── docs/              # Architecture & API docs
├── infrastructure/    # Docker, Nginx, scripts
├── docker-compose.yml
└── .env.example
```

## 🔗 Connected Services

| Service | Purpose |
|---|---|
| Supabase | PostgreSQL database + Storage + Auth |
| Google Gemini | AI-powered threat analysis |
| Stitch MCP | UI design system management |

## 📄 License

MIT
