import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import { connectDB, getCollection } from './db.js';
import { toNodeHandler } from "better-auth/node";
import { auth } from "./auth.js";
import { verifyToken, verifyAdmin, getOptionalUser } from './jwtMiddleware.js';
import Stripe from 'stripe';

dotenv.config();

const getUserIdQuery = (id) => {
  try {
    return { $or: [{ _id: id }, { _id: new ObjectId(id) }] };
  } catch (e) {
    return { _id: id };
  }
};

const MIN_WORD_COUNT = 400;

const countWords = (text) => {
  const trimmed = (text || '').trim();
  if (!trimmed) return 0;
  return trimmed.split(/\s+/).length;
};

// Normalize note fields for consistent client consumption
const normalizeNote = (note) => {
  if (!note) return note;
  const topics = note.importantTopics || note.ingredients || [];
  return {
    ...note,
    noteType: note.noteType || note.cuisineType || '',
    importantTopics: topics,
    importanttopics: topics,
    ingredients: topics,
  };
};

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://client-side-ochre.vercel.app',
  'https://client-side-salmakhandoker001-6644s-projects.vercel.app',
  process.env.FRONTEND_URL,
  process.env.CLIENT_URL,
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// Ensure Database is connected for all requests
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error("Database connection failed in middleware:", err);
    res.status(500).json({ success: false, message: "Database connection failed" });
  }
});

// Mount Better Auth handler (must go before express.json middleware)
app.all("/api/auth/*", (req, res, next) => {
  const customPaths = [
    '/api/auth/register',
    '/api/auth/login',
    '/api/auth/google-callback',
    '/api/auth/logout',
    '/api/auth/me',
    '/api/auth/stats',
    '/api/auth/profile'
  ];
  if (customPaths.includes(req.path)) {
    return next();
  }
  return toNodeHandler(auth)(req, res, next);
});

app.use(express.json());
app.use(cookieParser());

// Connect to Database and start server (only for local development)
let dbConnected = false;
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  connectDB().then(() => {
    dbConnected = true;
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  }).catch(err => {
    console.error("Database connection failed. Server not started.", err);
  });
} else {
  dbConnected = true;
}

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ status: "ok", database: dbConnected });
});

// ROOT ROUTE
app.get('/', (req, res) => {
  const frontendUrl = process.env.FRONTEND_URL || process.env.CLIENT_URL;
  if (frontendUrl) {
    return res.redirect(frontendUrl);
  }
  return res.json({ status: "ok", message: "Recipe Hub Server API is running" });
});

// cloude code

// Register - FIX: _id এর বদলে email দিয়ে updateOne করো
app.post('/api/auth/register', async (req, res) => {
  const { name, email, image, password, role } = req.body;

  try {
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    const usersCollection = getCollection("users");

    const existingUser = await usersCollection.findOne({
      email: email.toLowerCase()
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already registered"
      });
    }

    // Better Auth দিয়ে signup
    const signUpResult = await auth.api.signUpEmail({
      body: {
        name,
        email: email.toLowerCase(),
        password,
        image: image || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150"
      }
    });

    if (!signUpResult?.user) {
      return res.status(500).json({
        success: false,
        message: "Signup failed"
      });
    }

    const finalRole = "user";

    // ✅ FIX: _id এর বদলে email দিয়ে update করো
    // কারণ Better Auth string ID ব্যবহার করে, ObjectId না
    await usersCollection.updateOne(
      { email: email.toLowerCase() },
      {
        $set: {
          role: finalRole,
          isBlocked: false,
          isPremium: false,
          updatedAt: new Date()
        }
      }
    );

    // ✅ FIX: email দিয়ে user খোঁজো
    const user = await usersCollection.findOne({
      email: email.toLowerCase()
    });

    if (!user) {
      return res.status(500).json({
        success: false,
        message: "User created but not found in database"
      });
    }

    const token = jwt.sign(
      {
        id: user._id.toString(),
        email: user.email,
        role: user.role || "user",
        isPremium: user.isPremium || false,
        name: user.name
      },
      process.env.JWT_SECRET,
      { expiresIn: "10d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 10 * 24 * 60 * 60 * 1000
    });

    return res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role || "user",
        isPremium: user.isPremium || false
      }
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    // ✅ Better Auth এর specific error handle করো
    if (error?.body?.code === 'USER_ALREADY_EXISTS') {
      return res.status(400).json({
        success: false,
        message: "Email already registered"
      });
    }

    return res.status(500).json({
      success: false,
      message: error.message || "Registration failed"
    });
  }
});


// সাময়িক debug route - server.js এ add করো
app.get('/api/debug/users', async (req, res) => {
  const usersCollection = getCollection("users");
  const all = await usersCollection.find({}).toArray();
  console.log("ALL USERS:", JSON.stringify(all, null, 2));
  res.json({ count: all.length, users: all });
});

// Login - FIX: blocked check আগে করো, token এ isPremium ও name রাখো
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password required"
      });
    }

    const usersCollection = getCollection("users");

    // ✅ FIX: Better Auth call করার আগে blocked check করো
    const userCheck = await usersCollection.findOne({
      email: email.toLowerCase()
    });

    if (!userCheck) {
      return res.status(404).json({
        success: false,
        message: "No account found with this email"
      });
    }

    if (userCheck.isBlocked) {
      return res.status(403).json({
        success: false,
        message: "Your account has been blocked by the administrator."
      });
    }

    // ✅ এখন Better Auth দিয়ে password verify করো
    await auth.api.signInEmail({
      body: {
        email: email.toLowerCase(),
        password
      }
    });

    // Better Auth verify করলে এখন fresh user data নাও
    const user = await usersCollection.findOne({
      email: email.toLowerCase()
    });

    const token = jwt.sign(
      {
        id: user._id.toString(),
        email: user.email,
        role: user.role || "user",
        isPremium: user.isPremium || false,
        name: user.name
      },
      process.env.JWT_SECRET,
      { expiresIn: "10d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 10 * 24 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        image: user.image,
        role: user.role || "user",
        isPremium: user.isPremium || false
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    // ✅ Better Auth এর error clearly handle করো
    if (error?.statusCode === 401 || error?.body?.code === 'INVALID_EMAIL_OR_PASSWORD') {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
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
        image: image || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150",
        role: 'user',
        isBlocked: false,
        isPremium: false,
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      user = await usersCollection.findOne({ _id: insertResult.insertedId });
    } else {
      // If user exists (e.g. created by Better Auth), ensure default fields exist
      if (user.role === undefined || user.isBlocked === undefined || user.isPremium === undefined) {
        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              role: user.role || 'user',
              isBlocked: user.isBlocked ?? false,
              isPremium: user.isPremium ?? false,
              updatedAt: new Date()
            }
          }
        );
        user = await usersCollection.findOne({ _id: user._id });
      }
    }

    if (user.isBlocked) {
      return res.status(403).json({ success: false, message: "Your account is blocked by the administrator." });
    }

    // Generate custom JWT token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role || 'user' },
      process.env.JWT_SECRET || 'political-science-department_jwt_secret_token_key_2026_xoxo',
      { expiresIn: '10d' }
    );

    // Store JWT in HTTPOnly Cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 10 * 24 * 60 * 60 * 1000
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

// ==========================================
// noteS API ENDPOINTS
// ==========================================

// Create note (Protected, 2 note limit for normal users)
app.post('/api/notes', verifyToken, async (req, res) => {
  const {
    noteName,
    noteImage,
    category,
    cuisineType,
    noteType,
    difficultyLevel,
    preparationTime,
    ingredients,
    importantTopics,
    instructions,
    isPremium
  } = req.body;

  const resolvedNoteType = noteType || cuisineType;
  const resolvedTopics = importantTopics || ingredients;

  if (!noteName || !category || !resolvedNoteType || !difficultyLevel || !preparationTime || !resolvedTopics || !instructions) {
    return res.status(400).json({ success: false, message: "Required fields are missing" });
  }

  const wordCount = countWords(instructions);
  if (wordCount < MIN_WORD_COUNT) {
    return res.status(400).json({
      success: false,
      message: `Note content must be at least ${MIN_WORD_COUNT} words (currently ${wordCount}).`
    });
  }

  try {
    const notesCollection = getCollection('notes');
    
    // Check if the user has reached their limit (if not premium)
    if (!req.user.isPremium && req.user.role !== 'admin') {
      const count = await notesCollection.countDocuments({ authorEmail: req.user.email });
      if (count >= 2) {
        return res.status(403).json({
          success: false,
          message: "Limit reached: Standard members can only post up to 2 notes. Upgrade to Premium to post unlimited notes!"
        });
      }
    }

    const topicsArray = Array.isArray(resolvedTopics)
      ? resolvedTopics
      : resolvedTopics.split(',').map(i => i.trim()).filter(Boolean);

    const newnote = {
      noteName,
      noteImage: noteImage || "https://images.unsplash.com/photo-1481627834876-b7833e8f5570",
      category,
      noteType: resolvedNoteType,
      cuisineType: resolvedNoteType,
      difficultyLevel,
      preparationTime: parseInt(preparationTime, 10),
      importantTopics: topicsArray,
      ingredients: topicsArray,
      instructions,
      isPremium: !!isPremium,
      authorId: req.user.id,
      authorName: req.user.name,
      authorEmail: req.user.email,
      likesCount: 0,
      isFeatured: false,
      status: 'published',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await notesCollection.insertOne(newnote);
    return res.status(201).json({
      success: true,
      message: "note created successfully!",
      noteId: result.insertedId
    });

  } catch (error) {
    console.error("Create note Error:", error);
    return res.status(500).json({ success: false, message: "Failed to create note" });
  }
});

// Get All notes (Public, category filter via $in, pagination, search)
app.get('/api/notes', async (req, res) => {
  const { category, search, page = 1, limit = 6 } = req.query;
  
  const query = { status: 'published' };
  
  // Apply Search filter (case-insensitive on name)
  if (search) {
    query.noteName = { $regex: search, $options: 'i' };
  }

  // Apply Category filter using MongoDB $in
  if (category) {
    const categories = Array.isArray(category)
      ? category 
      : category.split(',').map(c => c.trim()).filter(Boolean);
    
    if (categories.length > 0) {
      query.category = { $in: categories };
    }
  }

  try {
    const notesCollection = getCollection('notes');
    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    const parsedLimit = parseInt(limit, 10);

    const totalnotes = await notesCollection.countDocuments(query);
    const notes = await notesCollection.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parsedLimit)
      .toArray();

    return res.json({
      success: true,
      data: notes.map(normalizeNote),
      pagination: {
        totalnotes,
        page: parseInt(page, 10),
        limit: parsedLimit,
        totalPages: Math.ceil(totalnotes / parsedLimit)
      }
    });

  } catch (error) {
    console.error("Get notes Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch notes" });
  }
});

// Get Featured notes
app.get('/api/notes/featured', async (req, res) => {
  try {
    const notesCollection = getCollection('notes');
    const featured = await notesCollection.find({ isFeatured: true, status: 'published' }).limit(6).toArray();
    return res.json({ success: true, data: featured.map(normalizeNote) });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch featured notes" });
  }
});

// Get Popular notes (Sorted by likes count)
app.get('/api/notes/popular', async (req, res) => {
  try {
    const notesCollection = getCollection('notes');
    const popular = await notesCollection.find({ status: 'published' })
      .sort({ likesCount: -1 })
      .limit(6)
      .toArray();
    return res.json({ success: true, data: popular.map(normalizeNote) });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch popular notes" });
  }
});

// Get Single note Details
app.get('/api/notes/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const notesCollection = getCollection('notes');
    const note = await notesCollection.findOne({ _id: new ObjectId(id) });
    if (!note) {
      return res.status(404).json({ success: false, message: "note not found" });
    }

    const user = await getOptionalUser(req);
    let hasAccess = false;

    if (user) {
      const isAuthor = note.authorEmail === user.email;
      const isAdmin = user.role === 'admin';

      const paymentsCollection = getCollection('payments');
      const purchase = await paymentsCollection.findOne({
        userId: user.id,
        noteId: new ObjectId(id),
        paymentStatus: 'paid'
      });

      hasAccess = isAuthor || isAdmin || !!purchase;
    }

    if (!hasAccess) {
      // Omit topics and instructions for locked/unpurchased notes
      const { ingredients, importantTopics, instructions, ...publicnote } = note;
      return res.json({ success: true, data: { ...normalizeNote(publicnote), isLocked: true } });
    }

    return res.json({ success: true, data: { ...normalizeNote(note), isLocked: false } });
  } catch (error) {
    console.error("Get Single note Error:", error);
    return res.status(400).json({ success: false, message: "Invalid note ID" });
  }
});

// Update note (Protected)
app.put('/api/notes/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  try {
    const notesCollection = getCollection('notes');
    const note = await notesCollection.findOne({ _id: new ObjectId(id) });
    
    if (!note) {
      return res.status(404).json({ success: false, message: "note not found" });
    }

    // Must be author or admin
    if (note.authorEmail !== req.user.email && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: "Forbidden: You are not authorized to edit this note" });
    }

    // Strip uneditable fields
    const { _id, authorId, authorEmail, authorName, likesCount, createdAt, ...allowedUpdates } = updates;
    allowedUpdates.updatedAt = new Date();
    
    if (allowedUpdates.preparationTime) {
      allowedUpdates.preparationTime = parseInt(allowedUpdates.preparationTime, 10);
    }

    // Sync field aliases
    if (allowedUpdates.noteType) {
      allowedUpdates.cuisineType = allowedUpdates.noteType;
    } else if (allowedUpdates.cuisineType) {
      allowedUpdates.noteType = allowedUpdates.cuisineType;
    }
    if (allowedUpdates.importantTopics) {
      allowedUpdates.ingredients = Array.isArray(allowedUpdates.importantTopics)
        ? allowedUpdates.importantTopics
        : allowedUpdates.importantTopics.split(',').map(i => i.trim());
    } else if (allowedUpdates.ingredients && !Array.isArray(allowedUpdates.ingredients)) {
      allowedUpdates.ingredients = allowedUpdates.ingredients.split(',').map(i => i.trim());
      allowedUpdates.importantTopics = allowedUpdates.ingredients;
    }

    if (allowedUpdates.instructions) {
      const wordCount = countWords(allowedUpdates.instructions);
      if (wordCount < MIN_WORD_COUNT) {
        return res.status(400).json({
          success: false,
          message: `Note content must be at least ${MIN_WORD_COUNT} words (currently ${wordCount}).`
        });
      }
    }

    if (allowedUpdates.isPremium !== undefined) {
      allowedUpdates.isPremium = !!allowedUpdates.isPremium;
    }

    await notesCollection.updateOne({ _id: new ObjectId(id) }, { $set: allowedUpdates });
    return res.json({ success: true, message: "note updated successfully" });

  } catch (error) {
    console.error("Update note Error:", error);
    return res.status(500).json({ success: false, message: "Failed to update note" });
  }
});

// Delete note (Protected)
app.delete('/api/notes/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const notesCollection = getCollection('notes');
    const note = await notesCollection.findOne({ _id: new ObjectId(id) });
    if (!note) {
      return res.status(404).json({ success: false, message: "note not found" });
    }

    // Must be author or admin
    if (note.authorEmail !== req.user.email && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: "Forbidden: You are not authorized to delete this note" });
    }

    await notesCollection.deleteOne({ _id: new ObjectId(id) });
    return res.json({ success: true, message: "note deleted successfully" });

  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to delete note" });
  }
});

// Like note (Protected)
app.post('/api/notes/:id/like', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const notesCollection = getCollection('notes');
    const result = await notesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { likesCount: 1 } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "note not found" });
    }
    
    // Optional: Increment total likes received by the note author
    const note = await notesCollection.findOne({ _id: new ObjectId(id) });
    if (note) {
      const usersCollection = getCollection('users');
      await usersCollection.updateOne(
        { email: note.authorEmail },
        { $inc: { totalLikesReceived: 1 } } // we can track this for user stats
      );
    }

    return res.json({ success: true, message: "Note liked!" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to like note" });
  }
});

// Report note (Protected)
app.post('/api/notes/:id/report', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  
  if (!reason || !['Spam', 'Offensive Content', 'Copyright Issue'].includes(reason)) {
    return res.status(400).json({ success: false, message: "Valid reason is required (Spam, Offensive Content, Copyright Issue)" });
  }

  try {
    const reportsCollection = getCollection('reports');
    const report = {
      noteId: new ObjectId(id),
      reporterEmail: req.user.email,
      reason,
      status: 'pending',
      createdAt: new Date()
    };
    await reportsCollection.insertOne(report);
    return res.json({ success: true, message: "Note reported successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to report note" });
  }
});


// FAVORITES API ENDPOINTS
// ==========================================

// Add note to Favorites (Protected)
app.post('/api/favorites', verifyToken, async (req, res) => {
  const { noteId } = req.body;
  if (!noteId) {
    return res.status(400).json({ success: false, message: "Note ID is required" });
  }

  try {
    const favoritesCollection = getCollection('favorites');
    
    // Check if already in favorites;
    const existing = await favoritesCollection.findOne({
      userId: req.user.id,
      noteId: new ObjectId(noteId)
    });

    if (existing) {
      return res.status(400).json({ success: false, message: "note is already in your favorites/impotant-list" });
    }

    const newFavorite = {
      userEmail: req.user.email,
      userId: req.user.id,
      noteId: new ObjectId(noteId),
      addedAt: new Date()
    };

    await favoritesCollection.insertOne(newFavorite);
    return res.status(201).json({ success: true, message: "Added to favorites" });

  } catch (error) {
    console.error("Add Favorite Error:", error);
    return res.status(500).json({ success: false, message: "Failed to add to favorites" });
  }
});

// Remove note from Favorites (Protected)
app.delete('/api/favorites/:noteId', verifyToken, async (req, res) => {
  const { noteId } = req.params;
  try {
    const favoritesCollection = getCollection('favorites');
    const result = await favoritesCollection.deleteOne({
      userId: req.user.id,
      noteId: new ObjectId(noteId)
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Favorite note not found" });
    }

    return res.json({ success: true, message: "Removed from favorites" });

  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to remove from favorites" });
  }
});

// List Favorite notes (Protected, joins with notes collection)
app.get('/api/favorites', verifyToken, async (req, res) => {
  try {
    const favoritesCollection = getCollection('favorites');
    const favorites = await favoritesCollection.aggregate([
      { $match: { userId: req.user.id } },
      {
        $lookup: {
          from: 'notes',
          localField: 'noteId',
          foreignField: '_id',
          as: 'noteDetails'
        }
      },
      { $unwind: '$noteDetails' },
      {
        $project: {
          _id: 1,
          addedAt: 1,
          noteId: '$noteDetails._id',
          noteName: '$noteDetails.noteName',
          noteImage: '$noteDetails.noteImage',
          category: '$noteDetails.category',
          cuisineType: '$noteDetails.cuisineType',
          difficultyLevel: '$noteDetails.difficultyLevel',
          preparationTime: '$noteDetails.preparationTime',
          authorName: '$noteDetails.authorName'
        }
      }
    ]).toArray();

    return res.json({ success: true, data: favorites });

  } catch (error) {
    console.error("Get Favorites Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch favorites" });
  }
});

// ==========================================
// PAYMENTS & STRIPE API ENDPOINTS
// ==========================================

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Create Checkout Session
app.post('/api/create-checkout-session', verifyToken, async (req, res) => {
  const { type, noteId } = req.body; // type can be 'premium' or 'note'
  
  if (!type || !['premium', 'note'].includes(type)) {
    return res.status(400).json({ success: false, message: "Valid purchase type is required (premium or note)" });
  }

  try {
    let line_items = [];
    let metadata = {
      userId: req.user.id,
      userEmail: req.user.email,
      type
    };

    if (type === 'premium') {
      line_items = [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'political-science-department Premium Membership Upgrade',
            description: 'Unlocks unlimited note submissions and premium badge on your profile.',
          },
          unit_amount: 999, // $9.99
        },
        quantity: 1,
      }];
    } else {
      if (!noteId) {
        return res.status(400).json({ success: false, message: "note ID is required for note purchase" });
      }
      
      const notesCollection = getCollection('notes');
      const note = await notesCollection.findOne({ _id: new ObjectId(noteId) });
      
      if (!note) {
        return res.status(404).json({ success: false, message: "note not found" });
      }

      line_items = [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `note Purchase: ${note.noteName}`,
            description: `Author: ${note.authorName} | Cuisine: ${note.cuisineType}`,
            images: [note.noteImage],
          },
          unit_amount: 499, // $4.99
        },
        quantity: 1,
      }];
      
      metadata.noteId = noteId;
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: `http://localhost:3000/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `http://localhost:3000/notes`,
      metadata
    });

    return res.json({ success: true, url: session.url });

  } catch (error) {
    console.error("Create Stripe Session Error:", error);
    return res.status(500).json({ success: false, message: "Failed to create checkout session" });
  }
});

// Verify Stripe Payment Session
app.post('/api/payments/verify', verifyToken, async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) {
    return res.status(400).json({ success: false, message: "Session ID is required" });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ success: false, message: "Payment was not completed successfully" });
    }

    const { type, userId, userEmail, noteId } = session.metadata;
    const paymentsCollection = getCollection('payments');
    
    // Check if this payment intent has already been saved
    const paymentIntent = session.payment_intent;
    const existingPayment = await paymentsCollection.findOne({ transactionId: paymentIntent });

    if (existingPayment) {
      return res.json({
        success: true,
        message: "Payment verified (already processed)",
        data: existingPayment
      });
    }

    // Record the payment in the DB
    const newPayment = {
      userEmail,
      userId,
      amount: session.amount_total / 100,
      noteId: noteId ? new ObjectId(noteId) : null,
      transactionId: paymentIntent,
      paymentStatus: 'paid',
      paidAt: new Date()
    };

    await paymentsCollection.insertOne(newPayment);

    // If type is premium, update user isPremium status
    if (type === 'premium') {
      const usersCollection = getCollection('users');
      await usersCollection.updateOne(
        { email: userEmail },
        { $set: { isPremium: true, updatedAt: new Date() } }
      );
    }

    return res.json({
      success: true,
      message: "Payment successfully verified and saved!",
      data: newPayment
    });

  } catch (error) {
    console.error("Verify Stripe Session Error:", error);
    return res.status(500).json({ success: false, message: "Failed to verify payment session" });
  }
});

// List Purchased notes for current user
app.get('/api/payments/purchased', verifyToken, async (req, res) => {
  try {
    const paymentsCollection = getCollection('payments');
    const purchases = await paymentsCollection.aggregate([
      { 
        $match: { 
          userId: req.user.id, 
          noteId: { $ne: null } 
        } 
      },
      {
        $lookup: {
          from: 'notes',
          localField: 'noteId',
          foreignField: '_id',
          as: 'noteDetails'
        }
      },
      { $unwind: '$noteDetails' },
      {
        $project: {
          _id: 1,
          paidAt: 1,
          amount: 1,
          transactionId: 1,
          noteId: '$noteDetails._id',
          noteName: '$noteDetails.noteName',
          noteImage: '$noteDetails.noteImage',
          category: '$noteDetails.category',
          cuisineType: '$noteDetails.cuisineType',
          difficultyLevel: '$noteDetails.difficultyLevel',
          preparationTime: '$noteDetails.preparationTime',
          authorName: '$noteDetails.authorName'
        }
      }
    ]).toArray();

    return res.json({ success: true, data: purchases });

  } catch (error) {
    console.error("Get Purchased notes Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch purchased notes" });
  }
});

// Auto-purchase note on view (Disabled: all notes require purchase)
app.post('/api/payments/auto-purchase', verifyToken, async (req, res) => {
  return res.status(400).json({ success: false, message: "Auto-purchase is disabled: all notes require explicit Stripe payment." });
});

// ==========================================
// ADMIN DASHBOARD API ENDPOINTS
// ==========================================

// Get Admin Overview Stats (Protected)
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const usersCollection = getCollection('users');
    const notesCollection = getCollection('notes');
    const reportsCollection = getCollection('reports');

    const totalUsers = await usersCollection.countDocuments();
    const totalnotes = await notesCollection.countDocuments();
    const totalPremiumMembers = await usersCollection.countDocuments({ isPremium: true });
    const totalReports = await reportsCollection.countDocuments();

    return res.json({
      success: true,
      data: {
        totalUsers,
        totalnotes,
        totalPremiumMembers,
        totalReports
      }
    });
  } catch (error) {
    console.error("Admin Stats Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch admin stats" });
  }
});

// Manage Users: View All Users (Protected)
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const usersCollection = getCollection('users');
    const users = await usersCollection.find().toArray();
    return res.json({ success: true, data: users });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch users" });
  }
});

// Manage Users: Block User (Protected)
app.put('/api/admin/users/:id/block', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const usersCollection = getCollection('users');
    
    // Prevent blocking oneself
    const query = getUserIdQuery(id);
    const userToBlock = await usersCollection.findOne(query);
    if (userToBlock && userToBlock.email === req.user.email) {
      return res.status(400).json({ success: false, message: "You cannot block yourself!" });
    }

    const result = await usersCollection.updateOne(
      query,
      { $set: { isBlocked: true, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Force sign-out of the user by deleting sessions
    const sessionsCollection = getCollection('sessions');
    await sessionsCollection.deleteMany({ userId: id });

    return res.json({ success: true, message: "User successfully blocked" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to block user" });
  }
});

// Manage Users: Unblock User (Protected)
app.put('/api/admin/users/:id/unblock', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const usersCollection = getCollection('users');
    const result = await usersCollection.updateOne(
      getUserIdQuery(id),
      { $set: { isBlocked: false, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, message: "User successfully unblocked" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to unblock user" });
  }
});

// Manage notes: View All notes (Protected)
app.get('/api/admin/notes', verifyAdmin, async (req, res) => {
  try {
    const notesCollection = getCollection('notes');
    const notes = await notesCollection.find().toArray();
    return res.json({ success: true, data: notes });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch notes" });
  }
});

// Manage notes: Toggle Feature note (Protected)
app.put('/api/admin/notes/:id/feature', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { isFeatured } = req.body;
  try {
    const notesCollection = getCollection('notes');
    const result = await notesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { isFeatured: !!isFeatured, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "note not found" });
    }

    return res.json({
      success: true,
      message: isFeatured ? "note added to featured section" : "note removed from featured section"
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to feature note" });
  }
});

// Manage notes: Delete note (Protected)
app.delete('/api/admin/notes/:id', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const notesCollection = getCollection('notes');
    const result = await notesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "note not found" });
    }

    // Clean up reports for this note
    const reportsCollection = getCollection('reports');
    await reportsCollection.deleteMany({ noteId: new ObjectId(id) });

    return res.json({ success: true, message: "note successfully deleted" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to delete note" });
  }
});

// note Reports: View All Reports (Protected)
app.get('/api/admin/reports', verifyAdmin, async (req, res) => {
  try {
    const reportsCollection = getCollection('reports');
    const reports = await reportsCollection.aggregate([
      {
        $lookup: {
          from: 'notes',
          localField: 'noteId',
          foreignField: '_id',
          as: 'noteDetails'
        }
      },
      { $unwind: '$noteDetails' },
      {
        $project: {
          _id: 1,
          noteId: 1,
          reporterEmail: 1,
          reason: 1,
          status: 1,
          createdAt: 1,
          noteName: '$noteDetails.noteName',
          noteAuthor: '$noteDetails.authorName',
          noteAuthorEmail: '$noteDetails.authorEmail'
        }
      }
    ]).toArray();

    return res.json({ success: true, data: reports });
  } catch (error) {
    console.error("Get Reports Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch reports" });
  }
});

// note Reports: Dismiss Report (Protected)
app.put('/api/admin/reports/:id/dismiss', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const reportsCollection = getCollection('reports');
    const result = await reportsCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Report not found" });
    }
    return res.json({ success: true, message: "Report successfully dismissed" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to dismiss report" });
  }
});

// Transactions: View All Payments (Protected)
app.get('/api/admin/transactions', verifyAdmin, async (req, res) => {
  try {
    const paymentsCollection = getCollection('payments');
    const transactions = await paymentsCollection.find().sort({ paidAt: -1 }).toArray();
    return res.json({ success: true, data: transactions });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch transactions" });
  }
});

// Update User Profile (Protected)
app.put('/api/auth/profile', verifyToken, async (req, res) => {
  const { name, image } = req.body;
  if (!name && !image) {
    return res.status(400).json({ success: false, message: "Please provide name or image to update" });
  }

  try {
    const usersCollection = getCollection('users');
    const updateDoc = { updatedAt: new Date() };
    if (name) updateDoc.name = name;
    if (image) updateDoc.image = image;

    const result = await usersCollection.updateOne(
      { email: req.user.email },
      { $set: updateDoc }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Return updated user
    const updatedUser = await usersCollection.findOne({ email: req.user.email });
    return res.json({
      success: true,
      message: "Profile updated successfully",
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
    console.error("Profile Update Error:", error);
    return res.status(500).json({ success: false, message: "Failed to update profile" });
  }
});

// Get Logged-in User Stats Overview
app.get('/api/auth/stats', verifyToken, async (req, res) => {
  try {
    const notesCollection = getCollection('notes');
    const favoritesCollection = getCollection('favorites');

    const totalnotes = await notesCollection.countDocuments({ authorEmail: req.user.email });
    const totalFavorites = await favoritesCollection.countDocuments({ userId: req.user.id });

    // Sum likesCount of all notes authored by the user
    const notes = await notesCollection.find({ authorEmail: req.user.email }).toArray();
    const totalLikesReceived = notes.reduce((sum, r) => sum + (r.likesCount || 0), 0);

    return res.json({
      success: true,
      data: {
        totalnotes,
        totalFavorites,
        totalLikesReceived
      }
    });
  } catch (error) {
    console.error("User Stats Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch user stats overview" });
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("Unhandled Server Error:", err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "An unexpected error occurred"
  });
});

export default app;





