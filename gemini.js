import dotenv from 'dotenv';
dotenv.config();

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const MODELS = ['gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-3.5-flash-lite'];

/**
 * Helper to call Gemini API with multi-model fallback & retry
 */
async function callGemini(contents, systemInstruction = null) {
  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is not configured on the server.');
  }

  const payload = {
    contents: contents,
  };

  if (systemInstruction) {
    payload.systemInstruction = {
      parts: [{ text: systemInstruction }]
    };
  }

  let lastError = null;

  for (const model of MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        });

        if (response.ok) {
          const data = await response.json();
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            return text;
          }
        }

        const errorData = await response.json().catch(() => ({}));
        const errorMsg = errorData?.error?.message || response.statusText;

        // If high demand 503 or 429, try next model or retry
        if (response.status === 503 || response.status === 429) {
          console.warn(`Model ${model} spike (${response.status}): ${errorMsg}. Trying fallback...`);
          break; // break to try next model
        }

        throw new Error(`Gemini API error (${response.status}): ${errorMsg}`);
      } catch (err) {
        lastError = err;
        if (err.message.includes('503') || err.message.includes('429')) {
          break; // try next model
        }
        if (attempt < 2) {
          await new Promise(res => setTimeout(res, 1000));
        }
      }
    }
  }

  throw lastError || new Error('All Gemini model endpoints are currently unreachable.');
}

/**
 * Clean markdown code block if model wraps JSON in ```json ... ```
 */
function extractJSON(text) {
  try {
    return JSON.parse(text);
  } catch (e) {
    // Attempt markdown regex extraction
    const match = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (match && match[1]) {
      try {
        return JSON.parse(match[1]);
      } catch (err) {
        // Continue to fallback
      }
    }
    // Attempt to locate first { or [ and last } or ]
    const firstBrace = text.indexOf('{');
    const firstBracket = text.indexOf('[');
    let startIdx = -1;
    let endIdx = -1;

    if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) {
      startIdx = firstBracket;
      endIdx = text.lastIndexOf(']');
    } else if (firstBrace !== -1) {
      startIdx = firstBrace;
      endIdx = text.lastIndexOf('}');
    }

    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
      const slice = text.substring(startIdx, endIdx + 1);
      return JSON.parse(slice);
    }
    throw new Error('Failed to parse JSON response from Gemini: ' + text.substring(0, 100));
  }
}

/**
 * Feature 1: AI Recipe Generator & Smart Auto-Fill
 * Creates structured recipe from a user prompt or idea
 */
export async function generateRecipeWithAI({ prompt, cuisine, category, dietaryPreference }) {
  const systemInstruction = `You are a world-class professional chef and culinary developer on RecipeHub.
You generate creative, delicious, kitchen-tested recipes formatted strictly as JSON.
Never include conversational filler outside the JSON. Return only the JSON object.`;

  const userPrompt = `Create a complete, detailed recipe based on the following request:
- User Idea / Ingredients: "${prompt || 'Surprise delicious meal'}"
- Cuisine Preference: "${cuisine || 'Any'}"
- Category: "${category || 'Main Course'}"
- Dietary Preference: "${dietaryPreference || 'None'}"

You must return a valid JSON object with EXACTLY these fields:
{
  "recipeName": "A catchy, appealing name for the dish",
  "category": "One of: Main Course, Dessert, Breakfast, Appetizer, Salad, Beverage, Soup, Side Dish",
  "cuisineType": "e.g. Italian, Mexican, Asian, American, Mediterranean, French, Indian, Thai, etc.",
  "difficultyLevel": "Easy, Medium, or Hard",
  "preparationTime": 30,
  "ingredients": [
    "2 boneless, skinless chicken breasts (sliced)",
    "2 tbsp extra virgin olive oil",
    "3 cloves garlic (minced)"
  ],
  "instructions": "Step 1: Prep the ingredients...\\n\\nStep 2: Heat olive oil in a large skillet over medium-high heat...\\n\\nStep 3: ... (provide 4-7 detailed, sequential cooking steps with temperatures and timings)",
  "chefTips": "A professional chef tip on achieving best flavor or texture"
}`;

  const contents = [
    {
      role: 'user',
      parts: [{ text: userPrompt }]
    }
  ];

  const rawText = await callGemini(contents, systemInstruction);
  return extractJSON(rawText);
}

/**
 * Feature 2: Interactive AI Sous-Chef on Recipe Details
 * Context-aware cooking assistant for a specific recipe
 */
export async function askSousChef({ recipe, question, conversationHistory = [] }) {
  const systemInstruction = `You are the friendly, expert AI Sous-Chef on RecipeHub.
You are actively helping a cook who is looking at this specific recipe:
- Dish: "${recipe.recipeName || 'Dish'}"
- Category: "${recipe.category || 'General'}"
- Cuisine: "${recipe.cuisineType || 'International'}"
- Prep Time: ${recipe.preparationTime || 30} minutes
- Difficulty: ${recipe.difficultyLevel || 'Medium'}
- Ingredients:
${Array.isArray(recipe.ingredients) ? recipe.ingredients.map(i => `  * ${i}`).join('\n') : recipe.ingredients}

- Cooking Instructions:
${recipe.instructions || 'N/A'}

Your mission:
- Answer the user's cooking question clearly, practically, and encouragingly.
- Specialize in:
  1. Ingredient substitutions (e.g. what to use if an ingredient is missing or needs to be vegan/gluten-free/dairy-free)
  2. Scaling servings and measurements accurately
  3. Clarifying cooking temperatures, doneness, and techniques
  4. Drink & side dish pairings
- Keep answers concise, helpful, and formatted with clean bullet points or short paragraphs.`;

  const contents = [];

  // Append recent history (up to last 6 turns)
  if (Array.isArray(conversationHistory)) {
    for (const msg of conversationHistory.slice(-6)) {
      contents.push({
        role: msg.role === 'user' ? 'user' : 'model',
        parts: [{ text: msg.content }]
      });
    }
  }

  // Current question
  contents.push({
    role: 'user',
    parts: [{ text: question }]
  });

  const responseText = await callGemini(contents, systemInstruction);
  return {
    answer: responseText
  };
}

/**
 * Feature 3: AI Pantry Chef ("What's In My Fridge?")
 * Suggests tailored recipes based on available ingredients
 */
export async function generatePantryRecipes({ ingredients, mealType, maxTime, dietaryPreference }) {
  const systemInstruction = `You are the AI Pantry Chef on RecipeHub.
You help home cooks transform whatever ingredients they have in their fridge and pantry into delicious, restaurant-worthy meals with minimal waste.
Never return conversational filler outside JSON. Return only a JSON array of recipe objects.`;

  const userPrompt = `Given these ingredients available in the user's kitchen:
${Array.isArray(ingredients) ? ingredients.join(', ') : ingredients}

Preferences:
- Meal Type: "${mealType || 'Any'}"
- Maximum Cooking Time: "${maxTime ? maxTime + ' minutes' : 'Any'}"
- Dietary Preference: "${dietaryPreference || 'None'}"

Generate 2 to 3 creative, distinct recipes that make maximum use of the provided ingredients.
Assume basic pantry staples are available (water, salt, black pepper, cooking oil, basic spices).

Return a JSON array of objects with EXACTLY this structure:
[
  {
    "id": "recipe-1",
    "recipeName": "Catchy Recipe Name",
    "tagline": "Brief mouthwatering description in one sentence",
    "category": "Main Course",
    "cuisineType": "Italian",
    "difficultyLevel": "Easy",
    "preparationTime": 25,
    "matchedIngredients": ["Ingredient from user list", "Another matching ingredient"],
    "additionalPantryItems": ["Salt", "Olive oil", "Black pepper"],
    "ingredients": [
      "1 cup of ...",
      "2 tablespoons of ..."
    ],
    "instructions": "Step 1: ...\\n\\nStep 2: ...\\n\\nStep 3: ...",
    "whyItWorks": "Short culinary explanation of why this flavor combo excels"
  }
]`;

  const contents = [
    {
      role: 'user',
      parts: [{ text: userPrompt }]
    }
  ];

  const rawText = await callGemini(contents, systemInstruction);
  const result = extractJSON(rawText);
  return Array.isArray(result) ? result : [result];
}
