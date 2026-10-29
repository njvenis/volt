import assert from 'node:assert/strict';
import {build} from '../ui/node_modules/esbuild/lib/main.js';
import {createRequire} from 'node:module';
import {readFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const [actualSummaryPath, normalizedSummaryPath, normalizedPagePath] = process.argv.slice(2);
if (!normalizedPagePath && actualSummaryPath !== '--summary-only') throw new Error('usage: node tool.mjs actual-summary normalized-summary normalized-page');
const output = join(tmpdir(), `g7-preservation-parser-${process.pid}.cjs`);
await build({entryPoints:['ui/src/preservation-api.ts'],bundle:true,platform:'node',format:'cjs',outfile:output,logLevel:'silent'});
const parser=createRequire(import.meta.url)(output);
await unlink(output);
if (actualSummaryPath === '--summary-only') {
  const summary=JSON.parse(await readFile(normalizedSummaryPath,'utf8'));
  assert.deepEqual(parser.parseSummary(structuredClone(summary),summary.scope),summary);
  console.log(JSON.stringify({actual_summary_accepted:true}));
  process.exit(0);
}
const actual=JSON.parse(await readFile(actualSummaryPath,'utf8'));
assert.throws(()=>parser.parseSummary(structuredClone(actual),actual.scope),error=>error?.code==='invalid_response');
const summary=JSON.parse(await readFile(normalizedSummaryPath,'utf8'));
assert.deepEqual(parser.parseSummary(structuredClone(summary),summary.scope),summary);
const page=JSON.parse(await readFile(normalizedPagePath,'utf8'));
assert.deepEqual(parser.parsePage(structuredClone(page),summary.snapshot_id,page.class_id),page);
console.log(JSON.stringify({actual_summary_rejected:true,utc_normalized_summary_accepted:true,
  actual_record_page_accepted:true,summary_snapshot_id:summary.snapshot_id}));
