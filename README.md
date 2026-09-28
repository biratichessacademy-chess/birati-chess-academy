# Birati Chess Academy™ – Parent Portal & Management System
Setup: `npm install` → copy `.env.example` to `.env` and edit → `npm start` → open http://localhost:3000
Admin: log in with ADMIN_EMAIL / ADMIN_PASSWORD from `.env` (account is created on first start).
Parents: Admin tab → "+ Add & generate code" → send the BCA-XXXX-XXXX code to the parent.
Library: drop PDFs into `books/`. Deploy behind HTTPS (Render, Railway, VPS + Nginx) and keep `academy.db` backed up.
