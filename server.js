import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import { connectDB, getCollection } from './db.js';
import { toNodeHandler } from "better-auth/node";
import { auth } from "./auth.js";
import { verifyToken } from './jwtMiddleware.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Mount Better Auth handler (must go before express.json middleware)
app.all("/api/auth/*", toNodeHandler(auth));

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Connect to Database and start server
let dbConnected = false;
connectDB().then(() => {
  dbConnected = true;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error("Database connection failed. Server not started.", err);
});

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ status: "ok", database: dbConnected });
});

// ==========================================
// AUTHENTICATION API ENDPOINTS
// ==========================================

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, image, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Name, email, and password are required" });
  }

  // Password Rules: min 6 chars, 1 uppercase, 1 lowercase
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 6 characters, and contain at least one uppercase letter and one lowercase letter."
    });
  }

  try {
    const usersCollection = getCollection('users');
    const existingUser = await usersCollection.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    // Call Better Auth to register
    await auth.api.signUpEmail({
      body: {
        email: email.toLowerCase(),
        password,
        name,
        image: image || "https://i.ibb.co/Vvpwk7R/default-avatar.png"
      }
    });

    // Fetch the newly created user (or update properties if needed)
    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    // Initialize custom fields if they don't exist
    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          role: user.role || 'user',
          isBlocked: user.isBlocked || false,
          isPremium: user.isPremium || false,
          createdAt: user.createdAt || new Date(),
          updatedAt: user.updatedAt || new Date()
        }
      }
    );

    const updatedUser = await usersCollection.findOne({ _id: user._id });

    // Generate JWT token
    const token = jwt.sign(
      { id: updatedUser._id.toString(), email: updatedUser.email, role: updatedUser.role || 'user' },
      process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
      { expiresIn: '7d' }
    );

    // Store JWT in HTTPOnly Cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // standard lax is best for cross-origin local cookies
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        id: updatedUser._id.toString(),
        name: updatedUser.name,
        email: updatedUser.email,
        image: updatedUser.image,
        role: updatedUser.role || 'user',
        isPremium: updatedUser.isPremium || false
      }
    });

  } catch (error) {
    console.error("Register Error:", error);
    return res.status(500).json({ success: false, message: error.message || "Registration failed" });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password are required" });
  }

  try {
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid email or password" });
    }

    if (user.isBlocked) {
      return res.status(403).json({ success: false, message: "Your account has been blocked by the administrator." });
    }

    // Call Better Auth to verify credentials
    await auth.api.signInEmail({
      body: {
        email: email.toLowerCase(),
        password,
      }
    });

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role || 'user' },
      process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
      { expiresIn: '7d' }
    );

    // Store JWT in HTTPOnly Cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      message: "Logged in successfully",
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role || 'user',
        isPremium: user.isPremium || false
      }
    });

  } catch (error) {
    console.error("Login Error:", error);
    return res.status(400).json({ success: false, message: "Invalid email or password" });
  }
});

// Google OAuth Login Sync Callback
app.post('/api/auth/google-callback', async (req, res) => {
  const { email, name, image } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required" });
  }

  try {
    const usersCollection = getCollection('users');
    let user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user) {
      // If Better Auth created the user, we find it. If not, let's create a record.
      const insertResult = await usersCollection.insertOne({
        name: name || "Google User",
        email: email.toLowerCase(),
        image: image || "https://i.ibb.co/Vvpwk7R/default-avatar.png",
        role: 'user',
        isBlocked: false,
        isPremium: false,
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      user = await usersCollection.findOne({ _id: insertResult.insertedId });
    }

    if (user.isBlocked) {
      return res.status(403).json({ success: false, message: "Your account is blocked by the administrator." });
    }

    // Generate custom JWT token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role || 'user' },
      process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
      { expiresIn: '7d' }
    );

    // Store JWT in HTTPOnly Cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      message: "Google Sign-in sync successful",
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role || 'user',
        isPremium: user.isPremium || false
      }
    });

  } catch (error) {
    console.error("Google Callback Error:", error);
    return res.status(500).json({ success: false, message: "Failed to sync Google user credentials" });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });
  return res.json({ success: true, message: "Logged out successfully" });
});

// Get Current Logged In User Profile (Protected)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    
    return res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role || 'user',
        isPremium: user.isPremium || false
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});
