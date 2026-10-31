export async function POST() {
  await fetch('https://api.openai.com/v1/chat/completions', { headers: { Authorization: 'Bearer sk-AAAAAAAAAAAAAAAAAAAAAAAA' } });
  return new Response('ok');
}
