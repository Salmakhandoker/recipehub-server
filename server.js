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

// ==========================================
// RECIPES API ENDPOINTS
// ==========================================

// Create Recipe (Protected, 2 recipe limit for normal users)
app.post('/api/recipes', verifyToken, async (req, res) => {
  const {
    recipeName,
    recipeImage,
    category,
    cuisineType,
    difficultyLevel,
    preparationTime,
    ingredients,
    instructions
  } = req.body;

  if (!recipeName || !category || !cuisineType || !difficultyLevel || !preparationTime || !ingredients || !instructions) {
    return res.status(400).json({ success: false, message: "Required fields are missing" });
  }

  try {
    const recipesCollection = getCollection('recipes');
    
    // Check if the user has reached their limit (if not premium)
    if (!req.user.isPremium && req.user.role !== 'admin') {
      const count = await recipesCollection.countDocuments({ authorEmail: req.user.email });
      if (count >= 2) {
        return res.status(403).json({
          success: false,
          message: "Limit reached: Standard members can only post up to 2 recipes. Upgrade to Premium to post unlimited recipes!"
        });
      }
    }

    const newRecipe = {
      recipeName,
      recipeImage: recipeImage || "https://images.unsplash.com/photo-1546069901-ba9599a7e63c",
      category,
      cuisineType,
      difficultyLevel,
      preparationTime: parseInt(preparationTime, 10),
      ingredients: Array.isArray(ingredients) ? ingredients : ingredients.split(',').map(i => i.trim()),
      instructions,
      authorId: req.user.id,
      authorName: req.user.name,
      authorEmail: req.user.email,
      likesCount: 0,
      isFeatured: false,
      status: 'published',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await recipesCollection.insertOne(newRecipe);
    return res.status(201).json({
      success: true,
      message: "Recipe created successfully!",
      recipeId: result.insertedId
    });

  } catch (error) {
    console.error("Create Recipe Error:", error);
    return res.status(500).json({ success: false, message: "Failed to create recipe" });
  }
});

// Get All Recipes (Public, category filter via $in, pagination, search)
app.get('/api/recipes', async (req, res) => {
  const { category, search, page = 1, limit = 6 } = req.query;
  
  const query = { status: 'published' };
  
  // Apply Search filter (case-insensitive on name)
  if (search) {
    query.recipeName = { $regex: search, $options: 'i' };
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
    const recipesCollection = getCollection('recipes');
    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    const parsedLimit = parseInt(limit, 10);

    const totalRecipes = await recipesCollection.countDocuments(query);
    const recipes = await recipesCollection.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parsedLimit)
      .toArray();

    return res.json({
      success: true,
      data: recipes,
      pagination: {
        totalRecipes,
        page: parseInt(page, 10),
        limit: parsedLimit,
        totalPages: Math.ceil(totalRecipes / parsedLimit)
      }
    });

  } catch (error) {
    console.error("Get Recipes Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch recipes" });
  }
});

// Get Featured Recipes
app.get('/api/recipes/featured', async (req, res) => {
  try {
    const recipesCollection = getCollection('recipes');
    const featured = await recipesCollection.find({ isFeatured: true, status: 'published' }).limit(6).toArray();
    return res.json({ success: true, data: featured });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch featured recipes" });
  }
});

// Get Popular Recipes (Sorted by likes count)
app.get('/api/recipes/popular', async (req, res) => {
  try {
    const recipesCollection = getCollection('recipes');
    const popular = await recipesCollection.find({ status: 'published' })
      .sort({ likesCount: -1 })
      .limit(6)
      .toArray();
    return res.json({ success: true, data: popular });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch popular recipes" });
  }
});

// Get Single Recipe Details
app.get('/api/recipes/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const recipesCollection = getCollection('recipes');
    const recipe = await recipesCollection.findOne({ _id: new ObjectId(id) });
    if (!recipe) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }
    return res.json({ success: true, data: recipe });
  } catch (error) {
    return res.status(400).json({ success: false, message: "Invalid Recipe ID" });
  }
});

// Update Recipe (Protected)
app.put('/api/recipes/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  try {
    const recipesCollection = getCollection('recipes');
    const recipe = await recipesCollection.findOne({ _id: new ObjectId(id) });
    
    if (!recipe) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }

    // Must be author or admin
    if (recipe.authorEmail !== req.user.email && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: "Forbidden: You are not authorized to edit this recipe" });
    }

    // Strip uneditable fields
    const { _id, authorId, authorEmail, authorName, likesCount, createdAt, ...allowedUpdates } = updates;
    allowedUpdates.updatedAt = new Date();
    
    if (allowedUpdates.preparationTime) {
      allowedUpdates.preparationTime = parseInt(allowedUpdates.preparationTime, 10);
    }
    if (allowedUpdates.ingredients && !Array.isArray(allowedUpdates.ingredients)) {
      allowedUpdates.ingredients = allowedUpdates.ingredients.split(',').map(i => i.trim());
    }

    await recipesCollection.updateOne({ _id: new ObjectId(id) }, { $set: allowedUpdates });
    return res.json({ success: true, message: "Recipe updated successfully" });

  } catch (error) {
    console.error("Update Recipe Error:", error);
    return res.status(500).json({ success: false, message: "Failed to update recipe" });
  }
});

// Delete Recipe (Protected)
app.delete('/api/recipes/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const recipesCollection = getCollection('recipes');
    const recipe = await recipesCollection.findOne({ _id: new ObjectId(id) });
    if (!recipe) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }

    // Must be author or admin
    if (recipe.authorEmail !== req.user.email && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: "Forbidden: You are not authorized to delete this recipe" });
    }

    await recipesCollection.deleteOne({ _id: new ObjectId(id) });
    return res.json({ success: true, message: "Recipe deleted successfully" });

  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to delete recipe" });
  }
});

// Like Recipe (Protected)
app.post('/api/recipes/:id/like', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const recipesCollection = getCollection('recipes');
    const result = await recipesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { likesCount: 1 } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }
    
    // Optional: Increment total likes received by the recipe author
    const recipe = await recipesCollection.findOne({ _id: new ObjectId(id) });
    if (recipe) {
      const usersCollection = getCollection('users');
      await usersCollection.updateOne(
        { email: recipe.authorEmail },
        { $inc: { totalLikesReceived: 1 } } // we can track this for user stats
      );
    }

    return res.json({ success: true, message: "Recipe liked!" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to like recipe" });
  }
});

// Report Recipe (Protected)
app.post('/api/recipes/:id/report', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  
  if (!reason || !['Spam', 'Offensive Content', 'Copyright Issue'].includes(reason)) {
    return res.status(400).json({ success: false, message: "Valid reason is required (Spam, Offensive Content, Copyright Issue)" });
  }

  try {
    const reportsCollection = getCollection('reports');
    const report = {
      recipeId: new ObjectId(id),
      reporterEmail: req.user.email,
      reason,
      status: 'pending',
      createdAt: new Date()
    };
    await reportsCollection.insertOne(report);
    return res.json({ success: true, message: "Recipe reported successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to report recipe" });
  }
});

