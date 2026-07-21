const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();

// IMPORTANT: Render needs this
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

// =========================
// TEMP DATA
// =========================

const users = [];
const claims = [];
const rewardCodes = [];

// =========================
// ADMIN
// =========================

const ADMIN_EMAIL = "admin@mcfa.com";
const ADMIN_PASSWORD = "123456";

// =========================
// CODE GENERATOR
// =========================

function generateCode(prefix = "MCFA") {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let part = "";

    for (let i = 0; i < 5; i++) {
        part += chars[Math.floor(Math.random() * chars.length)];
    }

    return `${prefix}-${part}`;
}

// =========================
// ROUTES (PAGES)
// =========================

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "register.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/claim", (req, res) => res.sendFile(path.join(__dirname, "claim.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin-login.html")));
app.get("/admin/dashboard", (req, res) => res.sendFile(path.join(__dirname, "admin-dashboard.html")));

// =========================
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (users.find(u => u.email === email)) {
        return res.json({ success: false, message: "Email exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    users.push({ username, email, password: hashed });

    res.json({ success: true, message: "Registered" });
});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);

    if (!user) return res.json({ success: false });

    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.json({ success: false });

    res.json({ success: true, user });
});

// =========================
// ADMIN LOGIN
// =========================

app.post("/api/admin/login", (req, res) => {

    const { email, password } = req.body;

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        return res.json({ success: true });
    }

    return res.json({ success: false });
});

// =========================
// GENERATE CODES
// =========================

app.post("/api/admin/generate", (req, res) => {

    const { reward, amount } = req.body;

    const codes = [];

    for (let i = 0; i < amount; i++) {
        const code = generateCode();

        const newCode = {
            code,
            reward,
            used: false
        };

        rewardCodes.push(newCode);
        codes.push(newCode);
    }

    res.json({ success: true, codes });
});

// =========================
// CLAIM
// =========================

app.post("/api/claim", (req, res) => {

    const { reward, code, email } = req.body;

    const found = rewardCodes.find(c => c.code === code);

    if (!found) return res.json({ success: false, message: "Invalid code" });

    if (found.used) return res.json({ success: false, message: "Used" });

    if (found.reward !== reward) return res.json({ success: false, message: "Wrong reward" });

    found.used = true;

    claims.push({ email, reward, code, status: "Pending" });

    res.json({
        success: true,
        message: "Order confirmed (72 hours)"
    });
});

// =========================
// ADMIN CLAIMS
// =========================

app.get("/api/admin/claims", (req, res) => {
    res.json(claims);
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
                               
