import jwt from 'jsonwebtoken';
import { getCollection } from './db.js';

export async function verifyToken(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);

  if (!token) {
    return res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'political-science_jwt_secret_token_key_2026_xoxo');
    
    // Check if user is blocked in the database
    const usersCollection = getCollection('users');
    
    // Better Auth saves users with standard email or ID. Let's find by email.
    const user = await usersCollection.findOne({ email: decoded.email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.isBlocked) {
      return res.status(403).json({ success: false, message: "Forbidden: User is blocked by admin" });
    }

    req.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role || 'user',
      isPremium: user.isPremium || false,
      image: user.image
    };

    next();
  } catch (error) {
    console.error("JWT verification failed:", error);
    return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
  }
}

export function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: "Forbidden: Admin access only" });
    }
    next();
  });
}

export async function getOptionalUser(req) {
  const token = req.cookies?.token || (req.headers?.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'political-science_jwt_secret_token_key_2026_xoxo');
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne({ email: decoded.email });
    
    if (!user || user.isBlocked) {
      return null;
    }

    return {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role || 'user',
      isPremium: user.isPremium || false,
      image: user.image
    };
  } catch (error) {
    return null;
  }
}

