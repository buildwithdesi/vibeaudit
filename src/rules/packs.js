/**
 * Named rule packs. `--pack free-credit` runs only these ids.
 * The ids stay in the default registry too, so a full scan and the morning
 * scan include them without a second pass.
 */

export const FREE_CREDIT_PACK = [
  'fca-01',
  'fca-02',
  'fca-03',
  'fca-04',
  'fca-05',
  'fca-06',
  'fca-07',
  'fca-08',
  'fca-09',
  'fca-10',
  'fca-11',
];

/** @type {Record<string, string[]>} */
export const RULE_PACKS = {
  'free-credit': FREE_CREDIT_PACK,
};

/** @param {string} name */
export function ruleIdsForPack(name) {
  const ids = RULE_PACKS[name];
  if (!ids) {
    const known = Object.keys(RULE_PACKS).sort().join(', ') || '(none)';
    throw new Error(`Unknown pack "${name}". Known packs: ${known}`);
  }
  return [...ids];
}
