import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret";

app.use(cors({ origin: "*" }));
app.use(express.json());

const USERS_FILE = "./users.json";
const OTP_FILE = "./otps.json";

const ensureFile = (file) => {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");
};
ensureFile(USERS_FILE);
ensureFile(OTP_FILE);

const readJSON = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8")) || [];
  } catch {
    return [];
  }
};

const writeJSON = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

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

const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });
  try {
    const token = auth.split(" ")[1];
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ✅ FIXED TRANSPORTER
let transporter;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({  // ← createTransport NOT createTransporter
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false },
    connectionTimeout: 5000,
    greetingTimeout: 3000,
  });
}

app.get("/", (req, res) => res.json({ status: "OK", service: "BGMI OTP API" }));

app.post("/auth/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Save OTP
    const otps = readJSON(OTP_FILE).filter((o) => o.email !== email);
    otps.push({ email: email.toLowerCase().trim(), otp, expires: Date.now() + 5 * 60 * 1000 });
    writeJSON(OTP_FILE, otps);

    console.log("📧 OTP for:", email, "OTP:", otp);

    // Screen OTP for Render (SMTP blocked)
    if (process.env.NODE_ENV === 'production') {
      console.log("🚀 RENDER MODE: SCREEN OTP");
      return res.json({
        success: true,
        otp,
        message: `🎮 BGMI Tournament OTP: ${otp}`
      });
    }

    // Try email locally
    if (transporter) {
      try {
        await transporter.sendMail({
          from: `"BGMI Esports" <${process.env.FROM_EMAIL || 'no-reply@bgmi.gg'}>`,
          to: email,
          subject: "BGMI Tournament OTP",
          html: `<h1 style="background:#4CAF50;color:white;padding:20px;text-align:center">${otp}</h1>`
        });
        console.log("✅ EMAIL SENT");
        return res.json({ success: true, message: "OTP sent to email!" });
      } catch (e) {
        console.log("❌ EMAIL FAILED:", e.message);
      }
    }

    // Fallback screen OTP
    res.json({ success: true, otp, message: `🎮 BGMI Tournament OTP: ${otp}` });

  } catch (error) {
    console.error("ERROR:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/verify-otp", (req, res) => {
  try {
    const { name, email, password, code } = req.body;
    if (!name || !email || !password || !code) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const otps = readJSON(OTP_FILE);
    const otpRecord = otps.find(o => 
      o.email === email.toLowerCase().trim() && 
      o.otp === code && 
      o.expires > Date.now()
    );

    if (!otpRecord) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email.toLowerCase().trim())) {
      return res.status(400).json({ error: "User already exists" });
    }

    const user = {
      id: Date.now(),
      profile_id: generateUniqueBGMIId(users),
      name,
      email: email.toLowerCase().trim(),
      password_plain: password,
      created_at: new Date().toISOString(),
    };

    users.push(user);
    writeJSON(USERS_FILE, users);
    writeJSON(OTP_FILE, otps.filter(o => o.email !== email));

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, user, token });
  } catch (error) {
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readJSON(USERS_FILE);
    const user = users.find(u => 
      u.email === email.toLowerCase().trim() && 
      u.password_plain === password
    );
    
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, user, token });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/me", authMiddleware, (req, res) => {
  try {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id == req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    res.json({
      profile_id: user.profile_id,
      name: user.name,
      email: user.email,
      created_at: user.created_at,
    });
  } catch (error) {
    res.status(500).json({ error: "Profile error" });
  }
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ BGMI Server: port ${PORT}`);
  console.log(`🔥 Mode: ${process.env.NODE_ENV || 'local'}`);
});
