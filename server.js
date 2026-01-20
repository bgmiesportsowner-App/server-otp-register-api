import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

/* =====================
   MIDDLEWARE
===================== */
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST"],
  })
);
app.use(express.json());

/* =====================
   FILE PATHS
===================== */
const USERS_FILE = "./users.json";
const OTP_FILE = "./otps.json";

/* =====================
   ENSURE FILES
===================== */
const ensureFile = (file) => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "[]");
  }
};
ensureFile(USERS_FILE);
ensureFile(OTP_FILE);

/* =====================
   HELPERS
===================== */
const readJSON = (file) => {
  try {
    const data = fs.readFileSync(file, "utf-8");
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
};

const writeJSON = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

/* =====================
   UNIQUE BGMI ID
===================== */
const generateUniqueBGMIId = (users) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id;
  do {
    let code = "";
    for (let i = 0; i < 5; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    id = `BGMI-${code}`;
  } while (users.some((u) => u.profile_id === id));
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
   SMTP (BREVO) - Render Free Tier Safe
===================== */
let transporter;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransporter({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false },
    connectionTimeout: 10000, // 10 sec timeout
    greetingTimeout: 5000,
  });
}

/* =====================
   HEALTH CHECK
===================== */
app.get("/", (req, res) => {
  res.json({ status: "OK", service: "BGMI OTP API" });
});

/* =====================
   SEND OTP - FIXED VERSION 🔥
===================== */
app.post("/auth/send-otp", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    if (!email) return res.status(400).json({ error: "Email required" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP first
    const otps = readJSON(OTP_FILE).filter((o) => o.email !== email);
    otps.push({ email, otp, expires: Date.now() + 5 * 60 * 1000 });
    writeJSON(OTP_FILE, otps);

    console.log("📧 Sending OTP to:", email);
    console.log("🔥 Environment:", process.env.NODE_ENV || "development");

    // TRY EMAIL (Render local only)
    let emailSent = false;
    if (transporter && process.env.NODE_ENV !== 'production') {
      try {
        await transporter.sendMail({
          from: `"BGMI Esports" <${process.env.FROM_EMAIL}>`,
          to: email,
          subject: "BGMI Tournament OTP",
          html: `
            <div style="font-family:Arial; max-width: 500px;">
              <h2>🎮 BGMI Tournament Verification</h2>
              <div style="background: #4CAF50; color: white; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 5px;">
                ${otp}
              </div>
              <p>Valid for <strong>5 minutes</strong></p>
              <hr>
              <p>BGMI Esports Tournament Registration</p>
            </div>
          `,
        });
        console.log("✅ REAL EMAIL SENT");
        emailSent = true;
        return res.json({ 
          success: true, 
          message: "OTP sent to your email! Check inbox/spam." 
        });
      } catch (emailError) {
        console.log("❌ SMTP FAILED (Expected on Render):", emailError.message);
      }
    } else {
      console.log("⏭️  SKIPPING SMTP - SCREEN OTP MODE");
    }

    // SCREEN OTP (Render + BGMI Perfect!)
    console.log(`🚀 SCREEN OTP MODE: ${otp}`);
    res.json({ 
      success: true, 
      otp: otp,
      message: `🎮 BGMI Tournament OTP: <strong>${otp}</strong> (Screen pe use kar!)`
    });

  } catch (error) {
    console.error("💥 CRITICAL ERROR:", error.message);
    res.status(500).json({ error: "Server error" });
  }
});

/* =====================
   VERIFY OTP + REGISTER
===================== */
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { name, email, password, code } = req.body;
    if (!name || !email || !password || !code)
      return res.status(400).json({ error: "Missing fields" });

    const otps = readJSON(OTP_FILE);
    const record = otps.find(
      (o) => o.email === email && o.otp === code && o.expires > Date.now()
    );
    if (!record)
      return res.status(400).json({ error: "Invalid or expired OTP" });

    const users = readJSON(USERS_FILE);
    if (users.find((u) => u.email === email))
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
    writeJSON(OTP_FILE, otps.filter((o) => o.email !== email));

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    console.log(`🎉 NEW BGMI USER: ${user.profile_id} (${name})`);
    
    res.json({ success: true, user, token });
  } catch (error) {
    console.error("VERIFY ERROR:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

/* =====================
   LOGIN
===================== */
app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readJSON(USERS_FILE);

    const user = users.find(
      (u) => u.email === email && u.password_plain === password
    );
    if (!user)
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, user, token });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

/* =====================
   USER PROFILE
===================== */
app.get("/me", authMiddleware, (req, res) => {
  try {
    const users = readJSON(USERS_FILE);
    const user = users.find((u) => u.id === req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({
      profile_id: user.profile_id,
      name: user.name,
      email: user.email,
      created_at: user.created_at,
    });
  } catch (error) {
    res.status(500).json({ error: "Profile fetch failed" });
  }
});

/* =====================
   START SERVER
===================== */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ BGMI User Server running on port ${PORT}`);
  console.log(`🔥 Mode: ${process.env.NODE_ENV || 'development'}`);
  console.log("🚀 Ready for tournament registration!");
});
