import dns from "node:dns" ;
dns.setServers (["1.1.1.1", "1.0.0.1"]);
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client } from "./db.js";
import dotenv from 'dotenv';
import { Server } from "node:http";

dotenv.config();

const db = client.db(process.env.AUTH_DB_NAME || 'political-science-department');

export const auth = betterAuth({
  database: mongodbAdapter(db, {
    client,
    usePlural: true,
  }),
  trustedOrigins: [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
      "https://client-side-8jv1xvjww-salmakhandoker001-6644s-projects.vercel.app", // ← তোমার frontend URL
    process.env.CLIENT_URL
  ].filter(Boolean),
  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
  },
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID ,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }
  }
});
