import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

/* =====================
   MIDDLEWARE
===================== */
app.use(cors({ origin: "*", methods: ["GET", "POST", "DELETE"] }));
app.use(express.json());

/* =====================
   FILES
===================== */
const USERS_FILE = "./users.json";
const OTP_FILE = "./otps.json";

/* =====================
   HELPERS
===================== */
const readJSON = (file) => {
  if (!fs.existsSync(file)) return [];
  const data = fs.readFileSync(file, "utf-8");
  return data ? JSON.parse(data) : [];
};

const writeJSON = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

// ✅ ALWAYS UNIQUE BGMI ID
const generateUniqueBGMIId = (users) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id;

  do {
    let code = "";
    for (let i = 0; i < 5; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    id = `BGMI-${code}`;
  } while (users.some(u => u.profile_id === id));

  return id;
};

/* =====================
   JWT AUTH
===================== */
const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

/* =====================
   SMTP (BREVO) - RENDER SAFE
===================== */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/* =====================
   SEND OTP - HYBRID MODE (BEST FOR BGMI) ✅
===================== */
app.post("/auth/send-otp", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    if (!email) return res.status(400).json({ error: "Email required" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otps = readJSON(OTP_FILE).filter(o => o.email !== email);
    otps.push({ email, otp, expires: Date.now() + 5 * 60 * 1000 });
    writeJSON(OTP_FILE, otps);

    // 🔥 HYBRID MODE - TRY EMAIL FIRST, FAIL = SCREEN OTP
    if (process.env.NODE_ENV === 'production') {
      try {
        // TRY Brevo SMTP
        await transporter.sendMail({
          from: `"BGMI Esports" <${process.env.FROM_EMAIL}>`,
          to: email,
          subject: "BGMI Tournament OTP",
          html: `<h2>BGMI Tournament Verification</h2><h1 style="font-size: 48px; color: #ff4444;">${otp}</h1><p>Valid for 5 minutes only</p>`,
        });
        console.log(`✅ REAL EMAIL sent to ${email}`);
        return res.json({ success: true, message: "Check your email for OTP!" });
      } catch (emailError) {
        // EMAIL FAIL → SCREEN OTP (RENDER SAFE)
        console.log(`❌ Email failed for ${email}, using SCREEN OTP: ${otp}`);
        return res.json({ 
          success: true, 
          otp: otp,
          message: `Email delivery failed! Use this OTP: <strong>${otp}</strong>`
        });
      }
    }

    // Local development - Real email
    await transporter.sendMail({
      from: `"BGMI Esports" <${process.env.FROM_EMAIL}>`,
      to: email,
      subject: "BGMI OTP Verification",
      html: `<h2>Your OTP</h2><h1>${otp}</h1><p>Valid for 5 minutes</p>`,
    });

    console.log(`✅ Local email sent to ${email}`);
    res.json({ success: true });
  } catch (err) {
    console.error("OTP ERROR:", err);
    res.status(500).json({ error: "OTP send failed" });
  }
});

/* =====================
   VERIFY OTP + REGISTER
===================== */
app.post("/auth/verify-otp", (req, res) => {
  const { name, email, password, code } = req.body;
  if (!name || !email || !password || !code)
    return res.status(400).json({ error: "Missing fields" });

  const otps = readJSON(OTP_FILE);
  const record = otps.find(
    o => o.email === email && o.otp === code && o.expires > Date.now()
  );
  if (!record)
    return res.status(400).json({ error: "Invalid or expired OTP" });

  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: "User already exists" });

  const user = {
    id: Date.now(),
    profile_id: generateUniqueBGMIId(users),
    name,
    email,
    password_plain: password,
    created_at: new Date().toISOString(),
  };

  users.push(user);
  writeJSON(USERS_FILE, users);
  writeJSON(OTP_FILE, otps.filter(o => o.email !== email));

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, user, token });
});

/* =====================
   LOGIN
===================== */
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  const users = readJSON(USERS_FILE);
  const user = users.find(
    u => u.email === email && u.password_plain === password
  );
  if (!user)
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, user, token });
});

/* =====================
   USER PROFILE
===================== */
app.get("/me", authMiddleware, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.userId);

  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({
    profile_id: user.profile_id,
    name: user.name,
    email: user.email,
    created_at: user.created_at,
  });
});

/* =====================
   ADMIN APIs
===================== */
app.get("/admin/users", (req, res) => {
  res.json(readJSON(USERS_FILE));
});

app.delete("/admin/users/:id", (req, res) => {
  const id = Number(req.params.id);
  const users = readJSON(USERS_FILE).filter(u => u.id !== id);
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

/* =====================
   START
===================== */
const server = app.listen(PORT, () => {
  console.log("✅ User server running on port", PORT);
});
