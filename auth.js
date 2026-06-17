import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client } from "./db.js";
import dotenv from 'dotenv';

dotenv.config();

const db = client.db(process.env.AUTH_DB_NAME || 'new-database');

export const auth = betterAuth({
  database: mongodbAdapter(db, {
    client,
    collectionNames: {
      user: "users",
      session: "sessions",
      account: "accounts",
    },
  }),
  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
  },
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "dummy-id",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "dummy-secret",
    }
  }
});
