const crypto = require("crypto");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || "";
// Falls back to a random secret per boot so cookies from a previous
// deploy can't be replayed; that's fine since re-login is one password away.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const COOKIE_NAME = "jgb_auth";
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.disable("x-powered-by");

function sign(value) {
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
  return `${value}.${sig}`;
}

function isValidToken(token) {
  if (!token) return false;
  const sepIndex = token.lastIndexOf(".");
  if (sepIndex === -1) return false;
  const value = token.slice(0, sepIndex);
  const providedSig = token.slice(sepIndex + 1);
  const expectedSig = crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
  const a = Buffer.from(providedSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b) && value === "authed";
}

function renderLoginPage({ error } = {}) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JGB's Trade Compass — Sign in</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f4f1ea;
    --ink: #1f2318;
    --accent: #8a5a2b;
    --card: #ffffff;
    --border: #ddd6c8;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #171a13;
      --ink: #ece7d9;
      --accent: #d3924f;
      --card: #21251b;
      --border: #3a3f2d;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 24px;
  }
  form {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px 28px;
    width: 100%;
    max-width: 340px;
    box-shadow: 0 6px 24px rgba(0,0,0,0.08);
  }
  h1 {
    font-size: 1.15rem;
    margin: 0 0 4px;
  }
  p.sub {
    margin: 0 0 20px;
    font-size: 0.85rem;
    opacity: 0.7;
  }
  input[type="password"] {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--ink);
    margin-bottom: 14px;
  }
  button {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    background: var(--accent);
    color: #fff;
    cursor: pointer;
  }
  .error {
    color: #c0392b;
    font-size: 0.85rem;
    margin: -6px 0 14px;
  }
</style>
</head>
<body>
  <form method="POST" action="/login">
    <h1>JGB's Trade Compass</h1>
    <p class="sub">Enter the password to view.</p>
    ${error ? `<div class="error">${error}</div>` : ""}
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Enter</button>
  </form>
</body>
</html>`;
}

app.get("/login", (req, res) => {
  res.type("html").send(renderLoginPage());
});

app.post("/login", (req, res) => {
  const submitted = typeof req.body.password === "string" ? req.body.password : "";
  const a = Buffer.from(submitted);
  const b = Buffer.from(SITE_PASSWORD);
  const matches = a.length === b.length && crypto.timingSafeEqual(a, b) && SITE_PASSWORD.length > 0;
  if (matches) {
    res.cookie(COOKIE_NAME, sign("authed"), {
      httpOnly: true,
      sameSite: "lax",
      secure: req.protocol === "https",
      maxAge: COOKIE_MAX_AGE_MS,
    });
    return res.redirect("/");
  }
  res.status(401).type("html").send(renderLoginPage({ error: "Incorrect password." }));
});

app.get("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect("/login");
});

app.use((req, res, next) => {
  if (isValidToken(req.cookies[COOKIE_NAME])) return next();
  res.redirect("/login");
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`JGB's Trade Compass listening on port ${PORT}`);
});
