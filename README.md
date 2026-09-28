# Birati Chess Academy™ – Parent Portal & Management System
No native modules: the database is a plain JSON file (DB_PATH), so it builds anywhere.

## Run locally
npm install → copy `.env.example` to `.env` and edit → `npm run dev` → http://localhost:3000

## Deploy on Render
- New → Web Service → connect your repo. Build Command: `npm install`. Start Command: `npm start`.
- Environment tab: add JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD (no .env file needed).
- IMPORTANT: Render's disk is wiped on every deploy/restart unless you attach a Persistent Disk
  (paid plans). Add a disk mounted at `/var/data` and set DB_PATH=/var/data/academy.json.
  Without it, all students are lost on redeploy.

## Using it
Admin: log in with ADMIN_EMAIL / ADMIN_PASSWORD (account created on first start).
Parents: Students → "+ Add & generate code" → send the BCA-XXXX-XXXX code to the parent.
Library: put PDFs in `books/` (commit them to your repo).
