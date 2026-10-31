import { GoogleGenAI } from '@google/genai';

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

export async function runJob(userId) {
  return ai.models.generateContent({
    model: 'gemini-flash',
    contents: userId,
  });
}

export async function ask(prompt) {
  return ai.models.generateContent({
    model: 'gemini-flash',
    contents: prompt,
  });
}
