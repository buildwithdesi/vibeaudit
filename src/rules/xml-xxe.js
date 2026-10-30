/**
 * Rule: xml-xxe
 * Detects XML parsing with external entities enabled (XXE attacks).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

// Only parser construction that actually resolves external entities is flagged.
// An import alone is not a vulnerability, and xml2js, sax, node-expat and
// fast-xml-parser do not resolve external entities by default.
const XXE_PATTERNS = [
  // libxmljs with noent
  { pattern: /parseXml\s*\([\s\S]{0,200}noent\s*:\s*true/gi, label: 'XML parser with external entities enabled (noent: true)' },
  // DOMParser on server with user input
  { pattern: /new\s+DOMParser\s*\(\s*\)[\s\S]{0,200}(?:req\.|request\.|body\.|input)/gi, label: 'DOMParser with user-provided XML' },
];

// Java JAXP factories resolve DTDs and external entities unless hardened.
const JAVA_FACTORY = /\b(?:DocumentBuilderFactory|SAXParserFactory)\s*\.\s*newInstance\s*\(|\bXMLInputFactory\s*\.\s*new(?:Instance|Factory)\s*\(/g;
const JAVA_LABEL = 'Java XML parser factory created without disabling DTDs or external entities';

const TRUE = String.raw`(?:true|Boolean\.TRUE)`;
const FALSE = String.raw`(?:false|Boolean\.FALSE)`;

/**
 * Blank out comments with spaces so indexes still line up with the original.
 * "http://" inside feature URIs survives: a line comment has no colon before it.
 */
function codeOnly(content) {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, lead) => lead + ' '.repeat(m.length - lead.length));
}

/** A feature argument: a string literal naming it, or a constant whose value names it. */
function featureArg(code, name) {
  const consts = [...code.matchAll(new RegExp(String.raw`\b(\w+)\s*=\s*"[^"]*${name}"`, 'g'))].map((m) => m[1]);
  return `(?:"[^"]*${name}"${consts.length ? `|${consts.join('|')}` : ''})`;
}

/**
 * True when this factory variable gets a call that actually blocks XXE: the
 * setting named AND set to its safe value. Naming a setting is not enough.
 */
function isHardened(code, variable) {
  const call = (method, arg, value) =>
    new RegExp(String.raw`\b${variable}\s*\.\s*${method}\s*\(\s*${arg}\s*,\s*${value}\s*\)`).test(code);

  if (call('setFeature', featureArg(code, 'disallow-doctype-decl'), TRUE)) return true;
  if (call('setFeature', featureArg(code, 'external-general-entities'), FALSE)
    && call('setFeature', featureArg(code, 'external-parameter-entities'), FALSE)) return true;
  if (call('setProperty', String.raw`(?:XMLInputFactory\.)?(?:SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES)`, FALSE)) return true;
  if (call('set(?:Property|Attribute)', String.raw`(?:XMLConstants\.)?ACCESS_EXTERNAL_DTD`, '""')) return true;
  return false;
}

/** Each factory is judged on its own, so one hardened parser cannot cover another. */
function unhardenedJavaFactories(content) {
  const code = codeOnly(content);
  const indexes = [];
  JAVA_FACTORY.lastIndex = 0;
  let match;
  while ((match = JAVA_FACTORY.exec(code)) !== null) {
    const before = code.slice(Math.max(0, match.index - 120), match.index);
    const variable = before.match(/\b(\w+)\s*=\s*$/)?.[1];
    if (variable && isHardened(code, variable)) continue;
    indexes.push(match.index);
  }
  return indexes;
}

/** @type {Rule} */
export const xmlXxe = {
  id: 'xml-xxe',
  name: 'XML External Entity (XXE)',
  severity: 'critical',
  description: 'Detects XML parsing configurations vulnerable to XXE attacks.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:xml|parseXml|DOMParser|DocumentBuilder|xml2js|expat|sax)/i.test(file.content)) return [];

    const hits = [];
    for (const { pattern, label } of XXE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) hits.push({ index: match.index, label });
    }
    for (const index of unhardenedJavaFactories(file.content)) hits.push({ index, label: JAVA_LABEL });

    const findings = [];

    for (const { index, label } of hits) {
      const lineNum = file.content.slice(0, index).split('\n').length;
      const line = file.lines[lineNum - 1]?.trim();
      if (line?.startsWith('//') || line?.startsWith('*')) continue;

      findings.push({
        ruleId: 'xml-xxe',
        ruleName: 'XML External Entity (XXE)',
        severity: 'critical',
        message: `${label}.`,
        file: file.relativePath,
        line: lineNum,
        evidence: line?.slice(0, 120),
        fix: 'Disable external entity processing: for libxmljs use noent: false. For Java factories set the feature "http://apache.org/xml/features/disallow-doctype-decl" to true (or turn off external-general-entities and external-parameter-entities; for XMLInputFactory set SUPPORT_DTD and IS_SUPPORTING_EXTERNAL_ENTITIES to false). Avoid parsing untrusted XML when possible — use JSON instead.',
      });
    }

    return findings;
  },
};
