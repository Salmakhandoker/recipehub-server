import { connectDB, getCollection, client } from './db.js';

async function run() {
  try {
    const db = await connectDB();
    console.log("Connected successfully!");
    
    const collections = await db.listCollections().toArray();
    console.log("Collections:", collections.map(c => c.name));
    
    const recipesColl = getCollection('recipes');
    const sampleRecipes = await recipesColl.find({}).limit(2).toArray();
    console.log("Sample Recipes:", JSON.stringify(sampleRecipes, null, 2));

    const usersColl = getCollection('users');
    const sampleUsers = await usersColl.find({}).limit(2).toArray();
    console.log("Sample Users:", JSON.stringify(sampleUsers, null, 2));

    const paymentsColl = getCollection('payments');
    const samplePayments = await paymentsColl.find({}).limit(2).toArray();
    console.log("Sample Payments:", JSON.stringify(samplePayments, null, 2));
    
  } catch (err) {
    console.error("Error inspecting database:", err);
  } finally {
    await client.close();
  }
}

run();
