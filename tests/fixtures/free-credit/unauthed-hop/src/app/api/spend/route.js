import { runJob } from '@/lib/gemini';

export async function POST() {
  return runJob();
}
