# Deploying to Vercel

Quick steps to deploy this project to Vercel (static site + Python serverless scan API):

1. Install the Vercel CLI (optional but recommended):

```bash
npm i -g vercel
```

2. From the project root (where `vercel.json` and `requirements.txt` live) deploy:

```bash
vercel login
vercel --prod
```

3. The API endpoint will be available at `/api/scan`.

Local testing:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python scanner.py
```

Notes:
- The serverless wrapper is at `api/scan.py` and calls `perform_scan` from `scanner.py`.
- Ensure `requirements.txt` lists all dependencies (Flask, requests, reportlab, etc.).
