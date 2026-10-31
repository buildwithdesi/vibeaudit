'use client';

export function Leak() {
  const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY || 'sk-AAAAAAAAAAAAAAAAAAAAAAAA';
  return key;
}
