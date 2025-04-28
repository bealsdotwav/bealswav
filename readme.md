# Beals.wav

🎵 A Node.js + MongoDB + Zoho‑powered site for music catalog, beats, studio bookings & promotional services.

## Features
- User registration, email‑verification & login
- “Contact us” & “Book a session” forms (Zoho SMTP)
- Stripe checkout for beatstore
- Responsive design with CSP/CORS hardened

## Getting Started

### Prerequisites
- Node.js ≥ 16
- MongoDB connection URI
- Zoho SMTP credentials
- Stripe secret key

### Installation
```bash
git clone git@github.com:<your‑username>/bealswav.git
cd bealswav
npm install
```

### Configuration
1. Copy `.env.example` to `.env` and fill in your secrets:
   ```ini
   MONGODB_URI=your_mongo_uri
   STRIPE_SECRET_KEY=sk_xxx
   ZOHO_SMTP_USER=info@bealswav.com
   ZOHO_SMTP_PASS=your_zoho_app_password
   SENDER_EMAIL=info@bealswav.com
   ```
2. (Optional) Update `public/*.html` with your Google Analytics snippet in the `<head>`.

### Running Locally
```bash
npm start
```
Visit `http://localhost:4242` in your browser.

## Deployment
We recommend hosting the backend on Render:
1. Push code to GitHub
2. Create a Web Service on Render (Node.js, branch `main`)
3. Set environment variables in Render dashboard
4. Add custom domain and update DNS in Namecheap
5. Enable HTTPS (auto) and test

## .gitignore
Include a `.gitignore` at the repo root:
```
node_modules/
.env
.DS_Store
```

## License
This project is open source under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Feel free to open issues or submit pull requests. Ensure ESLint passes and tests (if any) are green.
