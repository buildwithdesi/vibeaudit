/**
 * Rule: no-error-monitoring
 * Flags a WEB APP project (Next/React/Express/etc.) whose dependencies include no error
 * monitoring / alerting service. Production errors then fail silently — you find out
 * your app is broken when a user tells you, not when it happens.
 *
 * INFO severity, and scoped to web frameworks so CLIs and libraries (which don't need
 * an error monitor) are never flagged — including this scanner itself.
 */

/** @typedef {import('./types.js').Rule} Rule */

const PKG_JSON = /(?:^|\/)package\.json$/;

// Web frameworks — projects that serve users and therefore want error monitoring.
const WEB_FRAMEWORK = /^(?:next|react|react-dom|express|fastify|koa|@remix-run\/|vue|nuxt|svelte|@sveltejs\/|hono|@nestjs\/|@angular\/)/i;

// Known error-monitoring / alerting packages.
const MONITORING = /^(?:@sentry\/|rollbar|bugsnag|@bugsnag\/|@datadog\/|newrelic|@newrelic\/|honeybadger|@honeybadger-io\/|elastic-apm|@opentelemetry\/|logrocket|@highlight-run\/)/i;

/** @type {Rule} */
export const noErrorMonitoring = {
  id: 'no-error-monitoring',
  name: 'No Error Monitoring',
  severity: 'info',
  description: 'Flags web app projects with no error monitoring/alerting dependency (Sentry, Rollbar, Bugsnag, Datadog) — production errors fail silently.',

  check(file) {
    if (!PKG_JSON.test(file.relativePath)) return [];

    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return [];
    }

    const names = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    if (!names.some((n) => WEB_FRAMEWORK.test(n))) return []; // CLIs/libraries don't need it
    if (names.some((n) => MONITORING.test(n))) return []; // already monitored

    return [
      {
        ruleId: 'no-error-monitoring',
        ruleName: 'No Error Monitoring',
        severity: 'info',
        message:
          "No error monitoring/alerting dependency found (Sentry, Rollbar, Bugsnag, Datadog…). Production errors will fail silently — you won't know the app is broken until a user tells you.",
        file: file.relativePath,
        line: 1,
        fix: 'Add an error monitor: @sentry/nextjs (or @sentry/node), Rollbar, or Bugsnag — wire it to capture unhandled errors and alert you. If your host already provides this, treat this as informational.',
      },
    ];
  },
};
