const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const helmet = require("helmet");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

// =========================
// DATABASE
// =========================

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// =========================
// MIDDLEWARE
// =========================

app.use(helmet());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(__dirname));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 * 24
    }
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use(limiter);

// =========================
// EMAIL
// =========================

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// =========================
// MONGOOSE SCHEMAS
// =========================

const UserSchema = new mongoose.Schema({
    username: String,
    email: {
        type: String,
        unique: true
    },
    password: String,

    verified: {
        type: Boolean,
        default: false
    },

    verificationToken: String,

    resetToken: String,

    loginCount: {
        type: Number,
        default: 0
    },

    lastLogin: Date,

    createdAt: {
        type: Date,
        default: Date.now
    }
});

const RewardSchema = new mongoose.Schema({
    code: String,
    reward: String,
    used: {
        type: Boolean,
        default: false
    }
});

const ClaimSchema = new mongoose.Schema({
    email: String,
    reward: String,
    code: String,
    status: {
        type: String,
        default: "Pending"
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model("User", UserSchema);
const Reward = mongoose.model("Reward", RewardSchema);
const Claim = mongoose.model("Claim", ClaimSchema);

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
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {

    try {

        const { username, email, password } = req.body;

        const exists = await User.findOne({ email });

        if (exists) {
            return res.json({
                success: false,
                message: "Email already exists."
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        const token = crypto.randomBytes(32).toString("hex");

        const user = new User({
            username,
            email,
            password: hashed,
            verificationToken: token
        });

        await user.save();

        const verifyLink =
            `${process.env.BASE_URL}/verify/${token}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your MCFA Rewards account",
            html: `
            <h2>Welcome to MCFA Rewards</h2>
            <p>Click below to verify your email.</p>
            <a href="${verifyLink}">
                Verify Email
            </a>
            `
        });

        res.json({
            success: true,
            message: "Verification email sent."
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false,
            message: "Registration failed."
        });

    }

});

// =========================
// VERIFY EMAIL
// =========================

app.get("/verify/:token", async (req, res) => {

    const user = await User.findOne({
        verificationToken: req.params.token
    });

    if (!user) {
        return res.send("Invalid verification link.");
    }

    user.verified = true;
    user.verificationToken = null;

    await user.save();

    res.redirect("/");

});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {

            return res.json({
                success: false,
                message: "User not found."
            });

        }

        const match =
            await bcrypt.compare(password, user.password);

        if (!match) {

            return res.json({
                success: false,
                message: "Wrong password."
            });

        }

        if (!user.verified) {

            return res.json({
                success: false,
                message: "Verify your email first."
            });

        }

        user.loginCount += 1;
        user.lastLogin = new Date();

        await user.save();

        req.session.user = user._id;

        res.json({
            success: true,
            message: "Login successful.",
            user
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false,
            message: "Login failed."
        });

    }

});
// =========================
// RESEND VERIFICATION
// =========================

app.post("/api/resend-verification", async (req, res) => {

    try {

        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user)
            return res.json({
                success: false,
                message: "User not found."
            });

        if (user.verified)
            return res.json({
                success: false,
                message: "Already verified."
            });

        const token = crypto.randomBytes(32).toString("hex");

        user.verificationToken = token;

        await user.save();

        const verifyLink =
            `${process.env.BASE_URL}/verify/${token}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Verify your account",
            html: `
                <h2>Email Verification</h2>
                <a href="${verifyLink}">
                Verify Account
                </a>
            `
        });

        res.json({
            success: true,
            message: "Verification email sent."
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false
        });

    }

});

// =========================
// FORGOT PASSWORD
// =========================

app.post("/api/forgot-password", async (req, res) => {

    try {

        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user)
            return res.json({
                success: false,
                message: "Email not found."
            });

        const token =
            crypto.randomBytes(32).toString("hex");

        user.resetToken = token;

        user.resetExpires =
            Date.now() + (30 * 60 * 1000);

        await user.save();

        const link =
            `${process.env.BASE_URL}/reset-password/${token}`;

        await transporter.sendMail({

            from: process.env.EMAIL_USER,

            to: user.email,

            subject: "Reset Password",

            html: `
            <h2>Reset Password</h2>
            <a href="${link}">
            Reset Password
            </a>
            `

        });

        res.json({
            success: true,
            message: "Password reset email sent."
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false
        });

    }

});

// =========================
// RESET PASSWORD
// =========================

app.post("/api/reset-password/:token", async (req, res) => {

    try {

        const user = await User.findOne({
            resetToken: req.params.token
        });

        if (!user)
            return res.json({
                success: false,
                message: "Invalid token."
            });

        if (Date.now() > user.resetExpires)
            return res.json({
                success: false,
                message: "Token expired."
            });

        const hashed =
            await bcrypt.hash(req.body.password, 10);

        user.password = hashed;

        user.resetToken = null;
        user.resetExpires = null;

        await user.save();

        res.json({
            success: true,
            message: "Password updated."
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false
        });

    }

});
// =========================
// GENERATE CODES
// =========================

app.post("/api/admin/generate", async (req, res) => {

    try {

        const { reward, amount } = req.body;

        const codes = [];

        for (let i = 0; i < amount; i++) {

            const code = generateCode();

            const rewardCode = new Reward({
                code,
                reward,
                used: false
            });

            await rewardCode.save();

            codes.push(rewardCode);

        }

        res.json({
            success: true,
            codes
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false,
            message: "Failed to generate codes."
        });

    }

});

// =========================
// CLAIM REWARD
// =========================

app.post("/api/claim", async (req, res) => {

    try {

        const { reward, code, email } = req.body;

        const rewardCode = await Reward.findOne({
            code
        });

        if (!rewardCode)
            return res.json({
                success: false,
                message: "Invalid code."
            });

        if (rewardCode.used)
            return res.json({
                success: false,
                message: "Code already used."
            });

        if (rewardCode.reward !== reward)
            return res.json({
                success: false,
                message: "Wrong reward selected."
            });

        rewardCode.used = true;

        await rewardCode.save();

        const claim = new Claim({
            email,
            reward,
            code,
            status: "Pending"
        });

        await claim.save();

        res.json({
            success: true,
            message: "Your order has been confirmed. You will receive it within 72 hours."
        });

    } catch (err) {

        console.log(err);

        res.json({
            success: false,
            message: "Claim failed."
        });

    }

});

// =========================
// ADMIN CLAIMS
// =========================

app.get("/api/admin/claims", async (req, res) => {

    const claims = await Claim.find().sort({
        createdAt: -1
    });

    res.json(claims);

});

// =========================
// ADMIN USERS
// =========================

app.get("/api/admin/users", async (req, res) => {

    const users = await User.find().select("-password");

    res.json(users);

});

// =========================
// ADMIN STATS
// =========================

app.get("/api/admin/stats", async (req, res) => {

    const totalUsers = await User.countDocuments();

    const verifiedUsers = await User.countDocuments({
        verified: true
    });

    const unverifiedUsers = await User.countDocuments({
        verified: false
    });

    const totalClaims = await Claim.countDocuments();

    const totalCodes = await Reward.countDocuments();

    const usedCodes = await Reward.countDocuments({
        used: true
    });

    res.json({

        totalUsers,

        verifiedUsers,

        unverifiedUsers,

        totalClaims,

        totalCodes,

        usedCodes

    });

});

// =========================
// DELETE USER
// =========================

app.delete("/api/admin/user/:id", async (req, res) => {

    try {

        await User.findByIdAndDelete(req.params.id);

        res.json({
            success: true
        });

    } catch {

        res.json({
            success: false
        });

    }

});

// =========================
// SEARCH USER
// =========================

app.get("/api/admin/search", async (req, res) => {

    const keyword = req.query.email;

    const users = await User.find({

        email: {

            $regex: keyword,

            $options: "i"

        }

    }).select("-password");

    res.json(users);

});
// =========================
// LOGOUT
// =========================

app.get("/api/logout", (req, res) => {

    req.session.destroy(() => {
        res.json({
            success: true
        });
    });

});

// =========================
// LOGIN HISTORY
// =========================

app.get("/api/admin/login-history", async (req, res) => {

    try {

        const users = await User.find()
            .select("username email loginCount lastLogin createdAt verified");

        res.json(users);

    } catch (err) {

        res.json([]);

    }

});

// =========================
// ADMIN USER DETAILS
// =========================

app.get("/api/admin/user/:id", async (req, res) => {

    try {

        const user = await User.findById(req.params.id)
            .select("-password -verificationToken -resetToken");

        if (!user)
            return res.json({
                success: false
            });

        res.json({
            success: true,
            user
        });

    } catch {

        res.json({
            success: false
        });

    }

});

// =========================
// UPDATE CLAIM STATUS
// =========================

app.post("/api/admin/claim/update", async (req, res) => {

    try {

        const { id, status } = req.body;

        await Claim.findByIdAndUpdate(id, {
            status
        });

        res.json({
            success: true
        });

    } catch {

        res.json({
            success: false
        });

    }

});

// =========================
// DELETE CLAIM
// =========================

app.delete("/api/admin/claim/:id", async (req, res) => {

    try {

        await Claim.findByIdAndDelete(req.params.id);

        res.json({
            success: true
        });

    } catch {

        res.json({
            success: false
        });

    }

});

// =========================
// HEALTH CHECK
// =========================

app.get("/health", (req, res) => {

    res.json({
        status: "online",
        database: mongoose.connection.readyState === 1
            ? "connected"
            : "disconnected"
    });

});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {

    console.log("================================");
    console.log("MCFA Rewards Server Running");
    console.log("Port:", PORT);
    console.log("MongoDB:", mongoose.connection.readyState);
    console.log("================================");

});
