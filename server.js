import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import { connectDB, getCollection } from './db.js';
import { toNodeHandler } from "better-auth/node";
import { auth } from "./auth.js";
import { verifyToken, verifyAdmin } from './jwtMiddleware.js';
import Stripe from 'stripe';

dotenv.config();

const getUserIdQuery = (id) => {
  try {
    return { $or: [{ _id: id }, { _id: new ObjectId(id) }] };
  } catch (e) {
    return { _id: id };
  }
};

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

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

    const finalRole =
      role === "admin" || email.toLowerCase().includes("admin")
        ? "admin"
        : "user";

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

// chat-gpt code

// app.post('/api/auth/register', async (req, res) => {
//   const { name, email, image, password, role } = req.body;

//   try {
//     if (!name || !email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Name, email and password are required"
//       });
//     }

//     const usersCollection = getCollection("users");

//     // Check existing user
//     const existingUser = await usersCollection.findOne({
//       email: email.toLowerCase()
//     });

//     if (existingUser) {
//       return res.status(400).json({
//         success: false,
//         message: "Email already registered"
//       });
//     }

//     // Better Auth signup
//     const signUpResult = await auth.api.signUpEmail({
//       body: {
//         name,
//         email: email.toLowerCase(),
//         password,
//         image:
//           image ||
//           "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150"
//       }
//     });

//     if (!signUpResult?.user) {
//       return res.status(500).json({
//         success: false,
//         message: "Signup failed"
//       });
//     }

//     const userId = signUpResult.user.id;

//     const finalRole =
//       role === "admin" || email.toLowerCase().includes("admin")
//         ? "admin"
//         : "user";


//         console.log("Searching user...");

// const userByEmail = await usersCollection.findOne({
//   email: email.toLowerCase()
// });

// console.log("userByEmail =", userByEmail);

// const userById = await usersCollection.findOne({
//   _id: signUpResult.user.id
// });

// console.log("userById =", userById);
//     // Update Better Auth created user
//     await usersCollection.updateOne(
//       { _id: userId },
//       {
//         $set: {
//           role: finalRole,
//           isBlocked: false,
//           isPremium: false,
//           updatedAt: new Date()
//         }
//       }
//     );

//     const user = await usersCollection.findOne({
//       _id: userId
//     });

//     if (!user) {
//       return res.status(500).json({
//         success: false,
//         message: "User created but not found in database"
//       });
//     }

//     const token = jwt.sign(
//       {
//         id: user._id.toString(),
//         email: user.email,
//         role: user.role
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: "10d" }
//     );

//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: false,
//       sameSite: "lax",
//       maxAge: 10 * 24 * 60 * 60 * 1000
//     });

//     return res.status(201).json({
//       success: true,
//       token,
//       user
//     });
//   } catch (error) {
//     console.error("REGISTER ERROR:", error);

//     return res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// });

// Register
// app.post('/api/auth/register', async (req, res) => {
//   const { name, email, image, password, role } = req.body;
//   if (!name || !email || !password) {
//     return res.status(400).json({ success: false, message: "Name, email, and password are required" });
//   }

  // Password Rules: min 6 chars, 1 uppercase, 1 lowercase
//   const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
//   if (!passwordRegex.test(password)) {
//     return res.status(400).json({
//       success: false,
//       message: "Password must be at least 6 characters, and contain at least one uppercase letter and one lowercase letter."
//     });
//   }

//   try {
//     const usersCollection = getCollection('users');
//     const existingUser = await usersCollection.findOne({ email: email.toLowerCase() });
//     if (existingUser) {
//       return res.status(400).json({ success: false, message: "Email already registered" });
//     }

//     // Call Better Auth to register
//     const signUpResult = await auth.api.signUpEmail({
//       body: {
//         email: email.toLowerCase(),
//         password,
//         name,
//         image: image || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150"
//       }
//     });

//     if (!signUpResult || !signUpResult.user) {
//       return res.status(500).json({ success: false, message: "Authentication provider failed to register user." });
//     }

//     const userId = signUpResult.user.id;
//     const userObjectId = new ObjectId(userId);

//     // Determine the role: default to 'user', allow setting 'admin'
//     const finalRole = (role === 'admin' || email.toLowerCase().includes('admin')) ? 'admin' : 'user';

//     // Initialize custom fields if they don't exist
//     await usersCollection.updateOne(
//       { _id: userObjectId },
//       {
//         $set: {
//           role: finalRole,
//           isBlocked: signUpResult.user.isBlocked || false,
//           isPremium: signUpResult.user.isPremium || false,
//           createdAt: signUpResult.user.createdAt || new Date(),
//           updatedAt: signUpResult.user.updatedAt || new Date()
//         }
//       }
//     );

//     const updatedUser = await usersCollection.findOne({ _id: userObjectId });
// console.log("signUpResult =", signUpResult);

// const checkUser = await usersCollection.findOne({
//   email: email.toLowerCase()
// });

// console.log("checkUser =", checkUser);
    // Generate JWT token
  //  console.log("updatedUser =", updatedUser);
  //   const token = jwt.sign(

  //     { id: updatedUser._id.toString(), email: updatedUser.email, role: updatedUser.role || 'user' },
  //     process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
  //     { expiresIn: '10d' }
      
  //   );
  // ✅ Replace your current try block with this:
// try {
//   const usersCollection = getCollection('users');
//   const existingUser = await usersCollection.findOne({ email: email.toLowerCase() });
//   if (existingUser) {
//     return res.status(400).json({ success: false, message: "Email already registered" });
//   }

  // Wrap Better Auth separately so we can handle its specific errors
//   let signUpResult;
//   try {
//     signUpResult = await auth.api.signUpEmail({
//       body: {
//         email: email.toLowerCase(),
//         password,
//         name,
//         image: image || "https://api.dicebear.com/7.x/initials/svg?seed=User"
//       }
//     });
//   } catch (authError) {
//     // Better Auth throws structured APIError objects
//     const code = authError?.body?.code || '';
//     if (code === 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL') {
//       return res.status(400).json({ success: false, message: "Email already registered" });
//     }
//     if (authError?.body?.message?.toLowerCase().includes('password')) {
//       return res.status(400).json({ success: false, message: "Password must be at least 8 characters with uppercase and lowercase letters." });
//     }
//     return res.status(500).json({ success: false, message: authError?.body?.message || "Registration failed" });
//   }

//   if (!signUpResult?.user) {
//     return res.status(500).json({ success: false, message: "Authentication provider failed." });
//   }

//   const userId = signUpResult.user.id;
//   const userObjectId = new ObjectId(userId);

//   const finalRole = (role === 'admin' || email.toLowerCase().includes('admin')) ? 'admin' : 'user';

//   await usersCollection.updateOne(
//     { _id: userObjectId },
//     {
//       $set: {
//         role: finalRole,
//         isBlocked: false,
//         isPremium: false,
//         createdAt: signUpResult.user.createdAt || new Date(),
//         updatedAt: new Date()
//       }
//     }
//   );

//   const updatedUser = await usersCollection.findOne({ _id: userObjectId });

//   if (!updatedUser) {
//     return res.status(500).json({ success: false, message: "User created but could not be retrieved." });
//   }

//   const token = jwt.sign(
//     { id: updatedUser._id.toString(), email: updatedUser.email, role: updatedUser.role || 'user' },
//     process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
//     { expiresIn: '10d' }
//   );

//   res.cookie('token', token, {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === 'production',
//     sameSite: 'lax',
//     maxAge: 10 * 24 * 60 * 60 * 1000
//   });

//   return res.status(201).json({
//     success: true,
//     message: "Registration successful",
//     token,
//     user: {
//       id: updatedUser._id.toString(),
//       name: updatedUser.name,
//       email: updatedUser.email,
//       image: updatedUser.image,
//       role: updatedUser.role || 'user',
//       isPremium: updatedUser.isPremium || false
//     }
//   });

// } catch (error) {
//   console.error("Register Error:", error);
//   return res.status(500).json({ success: false, message: error.message || "Registration failed" });
// }

    // Store JWT in HTTPOnly Cookie
//     res.cookie('token', token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === 'production',
//       sameSite: 'lax', // standard lax is best for cross-origin local cookies
//       maxAge: 10 * 24 * 60 * 60 * 1000 // 10 days
//     });

//     return res.status(201).json({
//       success: true,
//       message: "Registration successful",
//       token,
//       user: {
//         id: updatedUser._id.toString(),
//         name: updatedUser.name,
//         email: updatedUser.email,
//         image: updatedUser.image,
//         role: updatedUser.role || 'user',
//         isPremium: updatedUser.isPremium || false
//       }
//     });
//     console.log("signUpResult =", signUpResult);
// console.log("userId =", signUpResult?.user?.id);

//   } catch (error) {
//     console.error("Register Error:", error);
//     return res.status(500).json({ success: false, message: error.message || "Registration failed" });
//   }
// });

// Login
// app.post('/api/auth/login', async (req, res) => {
//   const { email, password } = req.body;
//   if (!email || !password) {
//     return res.status(400).json({ success: false, message: "Email and password are required" });
//   }

//   try {
//     const usersCollection = getCollection('users');
//     const user = await usersCollection.findOne({ email: email.toLowerCase() });

//     if (!user) {
//       return res.status(400).json({ success: false, message: "Invalid email or password" });
//     }

//     if (user.isBlocked) {
//       return res.status(403).json({ success: false, message: "Your account has been blocked by the administrator." });
//     }

    // Call Better Auth to verify credentials
    // await auth.api.signInEmail({
    //   body: {
    //     email: email.toLowerCase(),
    //     password,
    //   }
    // });

    // Generate JWT token
    // const token = jwt.sign(
    //   { id: user._id.toString(), email: user.email, role: user.role || 'user' },
    //   process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
    //   { expiresIn: '7d' }
    // );

    // Store JWT in HTTPOnly Cookie
//     res.cookie('token', token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === 'production',
//       sameSite: 'lax',
//       maxAge: 10 * 24 * 60 * 60 * 1000
//     });

//     return res.json({
//       success: true,
//       message: "Logged in successfully",
//       token,
//       user: {
//         id: user._id.toString(),
//         name: user.name,
//         email: user.email,
//         image: user.image,
//         role: user.role || 'user',
//         isPremium: user.isPremium || false
//       }
//     });

//   } catch (error) {
//     console.error("Login Error:", error);
//     return res.status(400).json({ success: false, message: "Invalid email or password" });
//   }
// });


// chatgpt login code


// app.post('/api/auth/login', async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Email and password required"
//       });
//     }

    // Verify password through Better Auth
//     await auth.api.signInEmail({
//       body: {
//         email: email.toLowerCase(),
//         password
//       }
//     });

//     const usersCollection = getCollection("users");

//     const user = await usersCollection.findOne({
//       email: email.toLowerCase()
//     });

//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: "User not found"
//       });
//     }

//     const token = jwt.sign(
//       {
//         id: user._id.toString(),
//         email: user.email,
//         role: user.role || "user"
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: "10d" }
//     );

//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: false,
//       sameSite: "lax",
//       maxAge: 10 * 24 * 60 * 60 * 1000
//     });

//     return res.json({
//       success: true,
//       token,
//       user
//     });
//   } catch (error) {
//     console.error("LOGIN ERROR:", error);

//     return res.status(400).json({
//       success: false,
//       message: "Invalid email or password"
//     });
//   }
// });
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
    }

    if (user.isBlocked) {
      return res.status(403).json({ success: false, message: "Your account is blocked by the administrator." });
    }

    // Generate custom JWT token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role || 'user' },
      process.env.JWT_SECRET || 'recipehub_jwt_secret_token_key_2026_xoxo',
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


// FAVORITES API ENDPOINTS
// ==========================================

// Add Recipe to Favorites (Protected)
app.post('/api/favorites', verifyToken, async (req, res) => {
  const { recipeId } = req.body;
  if (!recipeId) {
    return res.status(400).json({ success: false, message: "Recipe ID is required" });
  }

  try {
    const favoritesCollection = getCollection('favorites');
    
    // Check if already in favorites;
    const existing = await favoritesCollection.findOne({
      userId: req.user.id,
      recipeId: new ObjectId(recipeId)
    });

    if (existing) {
      return res.status(400).json({ success: false, message: "Recipe is already in your favorites" });
    }

    const newFavorite = {
      userEmail: req.user.email,
      userId: req.user.id,
      recipeId: new ObjectId(recipeId),
      addedAt: new Date()
    };

    await favoritesCollection.insertOne(newFavorite);
    return res.status(201).json({ success: true, message: "Added to favorites" });

  } catch (error) {
    console.error("Add Favorite Error:", error);
    return res.status(500).json({ success: false, message: "Failed to add to favorites" });
  }
});

// Remove Recipe from Favorites (Protected)
app.delete('/api/favorites/:recipeId', verifyToken, async (req, res) => {
  const { recipeId } = req.params;
  try {
    const favoritesCollection = getCollection('favorites');
    const result = await favoritesCollection.deleteOne({
      userId: req.user.id,
      recipeId: new ObjectId(recipeId)
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Favorite recipe not found" });
    }

    return res.json({ success: true, message: "Removed from favorites" });

  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to remove from favorites" });
  }
});

// List Favorite Recipes (Protected, joins with recipes collection)
app.get('/api/favorites', verifyToken, async (req, res) => {
  try {
    const favoritesCollection = getCollection('favorites');
    const favorites = await favoritesCollection.aggregate([
      { $match: { userId: req.user.id } },
      {
        $lookup: {
          from: 'recipes',
          localField: 'recipeId',
          foreignField: '_id',
          as: 'recipeDetails'
        }
      },
      { $unwind: '$recipeDetails' },
      {
        $project: {
          _id: 1,
          addedAt: 1,
          recipeId: '$recipeDetails._id',
          recipeName: '$recipeDetails.recipeName',
          recipeImage: '$recipeDetails.recipeImage',
          category: '$recipeDetails.category',
          cuisineType: '$recipeDetails.cuisineType',
          difficultyLevel: '$recipeDetails.difficultyLevel',
          preparationTime: '$recipeDetails.preparationTime',
          authorName: '$recipeDetails.authorName'
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
  const { type, recipeId } = req.body; // type can be 'premium' or 'recipe'
  
  if (!type || !['premium', 'recipe'].includes(type)) {
    return res.status(400).json({ success: false, message: "Valid purchase type is required (premium or recipe)" });
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
            name: 'RecipeHub Premium Membership Upgrade',
            description: 'Unlocks unlimited recipe submissions and premium badge on your profile.',
          },
          unit_amount: 999, // $9.99
        },
        quantity: 1,
      }];
    } else {
      if (!recipeId) {
        return res.status(400).json({ success: false, message: "Recipe ID is required for recipe purchase" });
      }
      
      const recipesCollection = getCollection('recipes');
      const recipe = await recipesCollection.findOne({ _id: new ObjectId(recipeId) });
      
      if (!recipe) {
        return res.status(404).json({ success: false, message: "Recipe not found" });
      }

      line_items = [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `Recipe Purchase: ${recipe.recipeName}`,
            description: `Author: ${recipe.authorName} | Cuisine: ${recipe.cuisineType}`,
            images: [recipe.recipeImage],
          },
          unit_amount: 499, // $4.99
        },
        quantity: 1,
      }];
      
      metadata.recipeId = recipeId;
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: `http://localhost:3000/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `http://localhost:3000/recipes`,
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

    const { type, userId, userEmail, recipeId } = session.metadata;
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
      recipeId: recipeId ? new ObjectId(recipeId) : null,
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

// List Purchased Recipes for current user
app.get('/api/payments/purchased', verifyToken, async (req, res) => {
  try {
    const paymentsCollection = getCollection('payments');
    const purchases = await paymentsCollection.aggregate([
      { 
        $match: { 
          userId: req.user.id, 
          recipeId: { $ne: null } 
        } 
      },
      {
        $lookup: {
          from: 'recipes',
          localField: 'recipeId',
          foreignField: '_id',
          as: 'recipeDetails'
        }
      },
      { $unwind: '$recipeDetails' },
      {
        $project: {
          _id: 1,
          paidAt: 1,
          amount: 1,
          transactionId: 1,
          recipeId: '$recipeDetails._id',
          recipeName: '$recipeDetails.recipeName',
          recipeImage: '$recipeDetails.recipeImage',
          category: '$recipeDetails.category',
          cuisineType: '$recipeDetails.cuisineType',
          difficultyLevel: '$recipeDetails.difficultyLevel',
          preparationTime: '$recipeDetails.preparationTime',
          authorName: '$recipeDetails.authorName'
        }
      }
    ]).toArray();

    return res.json({ success: true, data: purchases });

  } catch (error) {
    console.error("Get Purchased Recipes Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch purchased recipes" });
  }
});

// Auto-purchase recipe on view
app.post('/api/payments/auto-purchase', verifyToken, async (req, res) => {
  const { recipeId } = req.body;
  if (!recipeId) {
    return res.status(400).json({ success: false, message: "Recipe ID is required" });
  }

  try {
    const paymentsCollection = getCollection('payments');
    
    // Check if already purchased
    const existing = await paymentsCollection.findOne({
      userId: req.user.id,
      recipeId: new ObjectId(recipeId)
    });

    if (!existing) {
      const newPurchase = {
        userEmail: req.user.email,
        userId: req.user.id,
        amount: 0, // Free auto-purchase on view
        recipeId: new ObjectId(recipeId),
        transactionId: `auto-${req.user.id}-${recipeId}`,
        paymentStatus: 'paid',
        paidAt: new Date()
      };
      await paymentsCollection.insertOne(newPurchase);
    }

    return res.json({ success: true, message: "Recipe added to purchased list" });
  } catch (error) {
    console.error("Auto purchase error:", error);
    return res.status(500).json({ success: false, message: "Failed to record auto-purchase" });
  }
});

// ==========================================
// ADMIN DASHBOARD API ENDPOINTS
// ==========================================

// Get Admin Overview Stats (Protected)
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const usersCollection = getCollection('users');
    const recipesCollection = getCollection('recipes');
    const reportsCollection = getCollection('reports');

    const totalUsers = await usersCollection.countDocuments();
    const totalRecipes = await recipesCollection.countDocuments();
    const totalPremiumMembers = await usersCollection.countDocuments({ isPremium: true });
    const totalReports = await reportsCollection.countDocuments();

    return res.json({
      success: true,
      data: {
        totalUsers,
        totalRecipes,
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

// Manage Recipes: View All Recipes (Protected)
app.get('/api/admin/recipes', verifyAdmin, async (req, res) => {
  try {
    const recipesCollection = getCollection('recipes');
    const recipes = await recipesCollection.find().toArray();
    return res.json({ success: true, data: recipes });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to fetch recipes" });
  }
});

// Manage Recipes: Toggle Feature Recipe (Protected)
app.put('/api/admin/recipes/:id/feature', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { isFeatured } = req.body;
  try {
    const recipesCollection = getCollection('recipes');
    const result = await recipesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { isFeatured: !!isFeatured, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }

    return res.json({
      success: true,
      message: isFeatured ? "Recipe added to featured section" : "Recipe removed from featured section"
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to feature recipe" });
  }
});

// Manage Recipes: Delete Recipe (Protected)
app.delete('/api/admin/recipes/:id', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const recipesCollection = getCollection('recipes');
    const result = await recipesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Recipe not found" });
    }

    // Clean up reports for this recipe
    const reportsCollection = getCollection('reports');
    await reportsCollection.deleteMany({ recipeId: new ObjectId(id) });

    return res.json({ success: true, message: "Recipe successfully deleted" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to delete recipe" });
  }
});

// Recipe Reports: View All Reports (Protected)
app.get('/api/admin/reports', verifyAdmin, async (req, res) => {
  try {
    const reportsCollection = getCollection('reports');
    const reports = await reportsCollection.aggregate([
      {
        $lookup: {
          from: 'recipes',
          localField: 'recipeId',
          foreignField: '_id',
          as: 'recipeDetails'
        }
      },
      { $unwind: '$recipeDetails' },
      {
        $project: {
          _id: 1,
          recipeId: 1,
          reporterEmail: 1,
          reason: 1,
          status: 1,
          createdAt: 1,
          recipeName: '$recipeDetails.recipeName',
          recipeAuthor: '$recipeDetails.authorName',
          recipeAuthorEmail: '$recipeDetails.authorEmail'
        }
      }
    ]).toArray();

    return res.json({ success: true, data: reports });
  } catch (error) {
    console.error("Get Reports Error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch reports" });
  }
});

// Recipe Reports: Dismiss Report (Protected)
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
    const recipesCollection = getCollection('recipes');
    const favoritesCollection = getCollection('favorites');

    const totalRecipes = await recipesCollection.countDocuments({ authorEmail: req.user.email });
    const totalFavorites = await favoritesCollection.countDocuments({ userId: req.user.id });

    // Sum likesCount of all recipes authored by the user
    const recipes = await recipesCollection.find({ authorEmail: req.user.email }).toArray();
    const totalLikesReceived = recipes.reduce((sum, r) => sum + (r.likesCount || 0), 0);

    return res.json({
      success: true,
      data: {
        totalRecipes,
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





