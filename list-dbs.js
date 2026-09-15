import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGO_DB_URI;

if (!uri) {
  console.error("MONGO_DB_URI is not defined in the environment variables!");
  process.exit(1);
}

const client = new MongoClient(uri);

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB successfully!");
    
    // List all databases
    const adminDb = client.db().admin();
    const dbsInfo = await adminDb.listDatabases();
    
    console.log("\nDatabases on the cluster:");
    for (const dbInfo of dbsInfo.databases) {
      console.log(`- Database: ${dbInfo.name} (Size: ${dbInfo.sizeOnDisk} bytes)`);
      const tempDb = client.db(dbInfo.name);
      const collections = await tempDb.listCollections().toArray();
      for (const coll of collections) {
        const count = await tempDb.collection(coll.name).countDocuments({});
        console.log(`    * Collection: ${coll.name} (${count} documents)`);
      }
    }
  } catch (err) {
    console.error("Error listing databases:", err);
  } finally {
    await client.close();
  }
}

run();
