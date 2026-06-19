import dns from "node:dns" ;
dns.setServers (["1.1.1.1", "1.0.0.1"]);
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client } from "./db.js";
import dotenv from 'dotenv';
import { Server } from "node:http";

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
  trustedOrigins: [
    "http://localhost:3000",
    "http://127.0.0.1:3000"
  ],
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
