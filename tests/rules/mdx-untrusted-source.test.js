import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { mdxUntrustedSource } from '../../src/rules/mdx-untrusted-source.js';

function makeFile(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}

describe('mdx-untrusted-source', () => {
  it('flags next-mdx-remote serialize() fed by a Supabase read', () => {
    const file = makeFile(
      'src/lib/blog.ts',
      `import { serialize } from 'next-mdx-remote/serialize';\n` +
        `export async function getPost(slug) {\n` +
        `  const { data } = await supabase.from('posts').select('content').eq('slug', slug).single();\n` +
        `  return serialize(data.content);\n` +
        `}\n`,
    );
    const findings = mdxUntrustedSource.check(file);
    assert.equal(findings.length, 1, 'Should flag one finding');
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].message, /remote code execution/);
    assert.equal(findings[0].line, 4);
  });

  it('flags <MDXRemote source={...}> JSX fed by a fetch() call', () => {
    const file = makeFile(
      'src/app/blog/[slug]/page.tsx',
      `import { MDXRemote } from 'next-mdx-remote/rsc';\n` +
        `export default async function Page({ params }) {\n` +
        `  const post = await (await fetch(\`https://api.example.com/posts/\${params.slug}\`)).json();\n` +
        `  return <MDXRemote source={post.content} />;\n` +
        `}\n`,
    );
    const findings = mdxUntrustedSource.check(file);
    assert.equal(findings.length, 1, 'Should flag the JSX MDXRemote usage');
    assert.match(findings[0].evidence, /MDXRemote/);
  });

  it('does not flag a static local MDX pipeline (no DB/request/fetch signal)', () => {
    const file = makeFile(
      'src/lib/posts.ts',
      `import fs from 'fs';\n` +
        `import { MDXRemote } from 'next-mdx-remote/rsc';\n` +
        `export function readPost(slug) {\n` +
        `  const content = fs.readFileSync(\`./content/posts/\${slug}.mdx\`, 'utf8');\n` +
        `  return <MDXRemote source={content} />;\n` +
        `}\n`,
    );
    const findings = mdxUntrustedSource.check(file);
    assert.equal(findings.length, 0, 'A locally-authored MDX file with no DB/network signal should not trip this');
  });

  it('does not flag files that never mention MDX', () => {
    const file = makeFile(
      'src/lib/users.ts',
      `export async function getUser(id) {\n` +
        `  return supabase.from('users').select('*').eq('id', id).single();\n` +
        `}\n`,
    );
    const findings = mdxUntrustedSource.check(file);
    assert.equal(findings.length, 0, 'Should skip files with no MDX signal at all');
  });

  it('skips test files', () => {
    const file = makeFile(
      'tests/blog.test.ts',
      `import { serialize } from 'next-mdx-remote/serialize';\n` +
        `test('x', () => serialize(supabase.from('posts').select().single().content));\n`,
    );
    const findings = mdxUntrustedSource.check(file);
    assert.equal(findings.length, 0, 'Should skip test files');
  });
});
