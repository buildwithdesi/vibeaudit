/**
 * Rule: known-vulnerable-versions
 * Flags a short, dated list of runtime and package versions that vendors have publicly
 * declared unsafe: the October 2026 Node.js and Next.js security releases, the poisoned
 * LiteLLM builds, and the certifi bundle that still trusts the eMudhra issuers. OSV
 * catches CVEs once they are indexed; this rule catches the window before that, and the
 * "my computer is fine, the Dockerfile says node:20" case.
 *
 * Every entry carries a `since` date and a `source`. The list is meant to be pruned:
 * when an entry is older than a few release cycles, OSV covers it and it should go.
 * Dependency ranges (`^16.0.0`) are judged by their minimum; the lockfile is judged
 * by the resolved version, so a lock with 16.4.1 clears a range that starts lower.
 */

/** @typedef {import('./types.js').Rule} Rule */
/** @typedef {import('./types.js').Finding} Finding */

const PKG_JSON = /(?:^|\/)package\.json$/;
const PKG_LOCK = /(?:^|\/)package-lock\.json$/;
const DOCKERFILE = /(?:^|\/)(?:Dockerfile|.*\.dockerfile)$/i;
const NVMRC = /(?:^|\/)\.(?:nvmrc|node-version)$/;
const PY_REQ = /(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/;

const ADVISORY_DATE = '2026-10-21';

/**
 * Minimum safe version per major line. A major that is absent from `lines` has no fixed
 * release (end of life); it is reported as `eol`.
 */
const NPM = {
  next: {
    lines: { 15: '15.5.28', 16: '16.4.1' },
    why: 'Next.js shipped fixes on Oct 14 2026 for two critical remote-code-execution bugs and a server-action denial of service.',
    source: 'Next.js / Vercel security advisories, 2026-10-14',
  },
  sharp: {
    lines: { 0: '0.35.5' },
    why: 'The Next.js SVG image RCE mitigation names sharp 0.35.5 or newer.',
    source: 'Next.js / Vercel security advisories, 2026-10-14',
  },
};
const NODE = {
  lines: { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' },
  why: 'Node.js shipped fixes on Oct 21 2026 for a Brotli decoder RCE and TLS hostname-check bypasses. Node 20 and older get no fix.',
  source: 'nodejs.org security release, 2026-10-21',
};
const PYTHON = {
  litellm: {
    bad: ['1.107.0', '1.82.7', '1.82.8'],
    why: 'These LiteLLM builds were published with credential-stealing code. If one was ever installed, rotate every key on that machine.',
    source: 'PyPI quarantine notices, 2026-03-24 and 2026-10-21',
  },
  certifi: {
    lines: { 2026: '2026.10.19' },
    why: 'Older certifi bundles still trust the eMudhra intermediates whose private keys were recovered.',
    source: 'discuss.python.org eMudhra notice, 2026-10-20',
  },
};

function parseVersion(s) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || ''));
  return m ? m.slice(1).map(Number) : null;
}
function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
/** First concrete version in an npm range: "^16.1.0" -> [16,1,0]; ">=20" -> [20,0,0]; "latest" -> null. */
function rangeFloor(range) {
  const m = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(String(range || ''));
  if (!m) return null;
  return [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)];
}
/** @returns {{status:'ok'|'update'|'eol', min?:string}} */
function judge(v, lines) {
  if (!v) return { status: 'ok' };
  const min = lines[v[0]];
  if (!min) {
    // Older than every line we know: no fix exists. Newer than every line: unknown, not our call.
    const oldest = Math.min(...Object.keys(lines).map(Number));
    return v[0] < oldest ? { status: 'eol' } : { status: 'ok' };
  }
  return cmp(v, parseVersion(min)) < 0 ? { status: 'update', min } : { status: 'ok' };
}
function lineOf(file, needle) {
  const idx = file.lines.findIndex((l) => l.includes(needle));
  return { line: idx >= 0 ? idx + 1 : 1, evidence: idx >= 0 ? file.lines[idx].trim().slice(0, 120) : undefined };
}
function finding(file, needle, severity, message, fix) {
  const at = lineOf(file, needle);
  return {
    ruleId: 'known-vulnerable-versions',
    ruleName: 'Known Vulnerable Versions',
    severity,
    message,
    file: file.relativePath,
    line: at.line,
    evidence: at.evidence,
    fix: `${fix} Advisory list dated ${ADVISORY_DATE}; confirm the current safe version on the vendor page before you rely on it.`,
    cweId: 'CWE-1104',
    owaspCategory: 'A06:2021',
  };
}

function checkNpmDeps(file, deps, resolvedFromLock) {
  const out = [];
  for (const [name, spec] of Object.entries(NPM)) {
    const range = deps[name];
    if (typeof range !== 'string') continue;
    const locked = resolvedFromLock?.[name];
    const v = locked ? parseVersion(locked) : rangeFloor(range);
    const j = judge(v, spec.lines);
    if (j.status === 'ok') continue;
    const where = locked ? `locked at ${locked}` : `declared as "${range}"`;
    const msg = j.status === 'eol'
      ? `"${name}" is ${where}, a major line with no security fix for the ${ADVISORY_DATE} advisories. ${spec.why}`
      : `"${name}" is ${where}, below the fixed version ${j.min}. ${spec.why}`;
    out.push(finding(file, `"${name}"`, 'critical', msg, `Run \`npm install ${name}@${j.min || Object.values(spec.lines).at(-1)} --ignore-scripts\`, run your build, and redeploy. Source: ${spec.source}.`));
  }
  return out;
}

/** @type {Rule} */
export const knownVulnerableVersions = {
  id: 'known-vulnerable-versions',
  name: 'Known Vulnerable Versions',
  severity: 'critical',
  description: 'Flags runtime and package versions that vendors have publicly declared unsafe (Oct 2026 Node.js and Next.js releases, poisoned LiteLLM builds, pre-eMudhra certifi), including Docker and .nvmrc pins that differ from the machine running the scan.',

  check(file) {
    const p = file.relativePath;

    if (PKG_LOCK.test(p)) {
      let lock;
      try { lock = JSON.parse(file.content); } catch { return []; }
      const pk = lock?.packages || {};
      const resolved = {};
      for (const name of Object.keys(NPM)) {
        const v = pk[`node_modules/${name}`]?.version;
        if (typeof v === 'string') resolved[name] = v;
      }
      if (!Object.keys(resolved).length) return [];
      // Treat the lock as the source of truth; pass every resolved package as if declared.
      const declared = Object.fromEntries(Object.keys(resolved).map((n) => [n, resolved[n]]));
      return checkNpmDeps(file, declared, resolved);
    }

    if (PKG_JSON.test(p)) {
      let pkg;
      try { pkg = JSON.parse(file.content); } catch { return []; }
      const out = [];
      const deps = { ...(pkg.optionalDependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.dependencies || {}) };
      out.push(...checkNpmDeps(file, deps, null));
      const engine = pkg.engines?.node;
      if (typeof engine === 'string') {
        const j = judge(rangeFloor(engine), NODE.lines);
        if (j.status !== 'ok') {
          out.push(finding(file, '"node"', 'warning',
            j.status === 'eol'
              ? `"engines.node" allows "${engine}", a Node line with no security fix for the ${ADVISORY_DATE} advisories. ${NODE.why}`
              : `"engines.node" allows "${engine}", below the fixed version ${j.min}. ${NODE.why}`,
            `Set "engines": { "node": ">=24.22.1" } (or the fixed version of your line) and match it in your host's runtime setting. Source: ${NODE.source}.`));
        }
      }
      return out;
    }

    if (NVMRC.test(p)) {
      const raw = file.content.trim().split('\n')[0].trim();
      const v = rangeFloor(raw);
      const j = judge(v, NODE.lines);
      if (j.status === 'ok') return [];
      return [finding(file, raw, 'warning',
        j.status === 'eol'
          ? `This file pins Node "${raw}", a line with no security fix for the ${ADVISORY_DATE} advisories. ${NODE.why}`
          : `This file pins Node "${raw}", below the fixed version ${j.min}. ${NODE.why}`,
        `Change it to ${j.min || '24.22.1'} and reinstall with your version manager. Source: ${NODE.source}.`)];
    }

    if (DOCKERFILE.test(p)) {
      const out = [];
      for (const line of file.lines) {
        const m = /^\s*FROM\s+(?:[\w./-]+\/)?node:(\d+(?:\.\d+){0,2})/i.exec(line);
        if (!m) continue;
        const parts = m[1].split('.');
        if (parts.length < 3) {
          // A floating tag like node:24 pulls the newest 24.x at build time; a stale local cache
          // still rebuilds old. Only flag majors with no fix at all.
          const j = judge([Number(parts[0]), 0, 0], NODE.lines);
          if (j.status !== 'eol') continue;
          out.push(finding(file, line.trim(), 'warning', `Dockerfile uses "node:${m[1]}", a Node line with no security fix for the ${ADVISORY_DATE} advisories. ${NODE.why}`, `Use FROM node:24 (or a fixed version of your line), rebuild without cache, and redeploy. Source: ${NODE.source}.`));
          continue;
        }
        const j = judge(parseVersion(m[1]), NODE.lines);
        if (j.status === 'ok') continue;
        out.push(finding(file, line.trim(), 'warning',
          j.status === 'eol'
            ? `Dockerfile pins "node:${m[1]}", a Node line with no security fix for the ${ADVISORY_DATE} advisories. ${NODE.why}`
            : `Dockerfile pins "node:${m[1]}", below the fixed version ${j.min}. ${NODE.why}`,
          `Change the FROM line to node:${j.min || '24.22.1'}, rebuild without cache, and redeploy. The machine running this scan may already be patched; the container is what ships. Source: ${NODE.source}.`));
      }
      return out;
    }

    if (PY_REQ.test(p)) {
      const out = [];
      for (const line of file.lines) {
        const l = line.trim();
        if (!l || l.startsWith('#')) continue;
        // Exact pins only. A ">=" range is handled below as a loose pin.
        const lite = /^["']?litellm["']?\s*(?:==|~=|=(?!=))\s*["']?(\d+\.\d+\.\d+)/i.exec(l);
        if (lite) {
          const v = lite[1];
          if (PYTHON.litellm.bad.includes(v)) {
            out.push(finding(file, l, 'critical', `litellm is pinned to ${v}, a build published with credential-stealing code. ${PYTHON.litellm.why}`, `Pin litellm==1.106.2 (the last safe release before 1.107.0), reinstall in a clean environment, and rotate every key that machine could read. Source: ${PYTHON.litellm.source}.`));
          }
          continue;
        }
        if (/^["']?litellm["']?\s*(?:>=\s*[\d.]+\s*)?,?\s*<\s*2/i.test(l) || /^["']?litellm["']?\s*$/i.test(l) || /^["']?litellm["']?\s*>=/i.test(l)) {
          out.push(finding(file, l, 'warning', `litellm is unpinned or range-pinned ("${l}"), so a fresh install can pull 1.107.0, a build published with credential-stealing code.`, `Pin litellm==1.106.2 exactly until a newer release is confirmed clean on the vendor page. Source: ${PYTHON.litellm.source}.`));
          continue;
        }
        const cert = /^["']?certifi["']?\s*(?:==|~=|=)\s*["']?(\d{4}\.\d{1,2}\.\d{1,2})/i.exec(l);
        if (cert) {
          const v = cert[1].split('.').map(Number);
          const min = PYTHON.certifi.lines[2026].split('.').map(Number);
          if (v[0] < 2026 || cmp(v, min) < 0) {
            out.push(finding(file, l, 'warning', `certifi is pinned to ${cert[1]}, below ${PYTHON.certifi.lines[2026]}. ${PYTHON.certifi.why}`, `Pin certifi>=${PYTHON.certifi.lines[2026]} and reinstall. Source: ${PYTHON.certifi.source}.`));
          }
        }
      }
      return out;
    }

    return [];
  },
};
