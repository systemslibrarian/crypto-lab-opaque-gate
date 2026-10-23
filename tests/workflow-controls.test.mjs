import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/deploy.yml', import.meta.url), 'utf8');

function job(name) {
  const start = workflow.indexOf(`  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const remainder = workflow.slice(start + 1);
  const next = remainder.search(/^  [a-z][a-z0-9-]*:\n/m);
  return next === -1 ? workflow.slice(start) : workflow.slice(start, start + 1 + next);
}

test('repository code runs with read-only contents permission', () => {
  const preJobs = workflow.slice(0, workflow.indexOf('jobs:\n'));
  assert.match(preJobs, /permissions:\n  contents: read/);
  assert.doesNotMatch(preJobs, /(?:pages|id-token|pull-requests|actions): write/);

  for (const name of ['quality', 'browser']) {
    assert.doesNotMatch(job(name), /(?:contents|pages|id-token|pull-requests|actions): write/);
  }
});

test('every referenced action is pinned to an immutable commit', () => {
  const uses = [...workflow.matchAll(/uses:\s+([^\s#]+)/g)].map(match => match[1]);
  assert.ok(uses.length > 0, 'workflow must reference at least one action');
  for (const reference of uses) {
    assert.match(reference, /@[0-9a-f]{40}$/, `${reference} is not pinned to a full commit`);
  }
});

test('quality gate uses clean installs, audit, and supported Node releases', () => {
  const quality = job('quality');
  assert.match(quality, /node-version: \[22, 24, 26\]/);
  assert.match(quality, /run: npm ci/);
  assert.match(quality, /run: npm audit --audit-level=high/);
  assert.match(quality, /run: npm test/);
  assert.match(quality, /run: npm run test:workflow/);
  assert.match(quality, /run: npm run build/);
  assert.doesNotMatch(quality, /npm install(?:\s|$)/);
});

test('pull requests run browser gates without publishing a Pages artifact', () => {
  const browser = job('browser');
  assert.match(browser, /needs: quality/);
  assert.match(browser, /run: npm run test:a11y/);
  assert.match(
    browser,
    /name: Package the tested site for Pages\n        if: github\.event_name != 'pull_request'/
  );
});

test('deployment authority exists only in the no-checkout deploy job', () => {
  const deploy = job('deploy');
  assert.match(deploy, /if: github\.event_name != 'pull_request'/);
  assert.match(deploy, /needs: browser/);
  assert.match(deploy, /permissions:\n      pages: write\n      id-token: write/);
  assert.doesNotMatch(deploy, /actions\/checkout|npm (?:ci|install)|run: npm/);
});

test('main deployments are never cancelled by a newer run', () => {
  assert.match(workflow, /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}/);
});

test('Dependabot automation is gated, version-limited, and fail-closed', () => {
  const merge = job('dependabot-auto-merge');
  assert.match(merge, /needs: \[quality, browser\]/);
  assert.doesNotMatch(merge, /actions\/checkout|npm (?:ci|install)|npm run/);
  assert.match(merge, /update-type == 'version-update:semver-minor'/);
  assert.match(merge, /update-type == 'version-update:semver-patch'/);
  assert.match(merge, /Leave major updates for human review/);
  assert.match(merge, /Reject an unrecognized Dependabot update type/);
  assert.match(merge, /gh workflow run deploy\.yml/);
  assert.match(merge, /::error::gate passed/);
  assert.match(merge, /::error::merge landed, but the required deploy workflow did not dispatch/);
  assert.match(merge, /exit 1/);
  assert.doesNotMatch(merge, /\|\|\s*(?:echo|true)|exit 0\s*#.*failed/);
});
