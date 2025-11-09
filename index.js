import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pkg from 'pg';
import crypto from 'crypto';
import multer from 'multer';
import { parse as csvParse } from 'csv-parse/sync';
import { Parser as Json2Csv } from 'json2csv';

const { Pool } = pkg;
const app = express();
app.use(cors());
app.use(express.json({ limit: '32kb' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/iotdb' });

const readLimiter = rateLimit({ windowMs: 60_000, max: 120 });
const writeLimiter = rateLimit({ windowMs: 60_000, max: 60 });

async function getChannel(id) {
  const r = await pool.query('select * from channels where id=$1', [id]);
  return r.rows[0];
}

async function checkApiKey(key, scope) {
  const r = await pool.query('select channel_id, scope from api_keys where key=$1', [key]);
  const row = r.rows[0];
  if (!row) return null;
  if (row.scope === 'readwrite') return row.channel_id;
  if (row.scope === scope) return row.channel_id;
  return null;
}

// Health
app.get('/health', (_req, res) => res.json({ ok: true }));

// Channels
app.post('/api/channels', async (req, res) => {
  const { name, description, allowedFields = [], minWrite = 15, minRead = 5, maxFields = 8 } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const r = await pool.query(
    'insert into channels(name, description, allowed_fields, min_write_interval_seconds, min_read_interval_seconds, max_fields) values ($1,$2,$3,$4,$5,$6) returning *',
    [name, description, allowedFields, minWrite, minRead, maxFields]
  );
  res.json(r.rows[0]);
});

app.get('/api/channels/:id', async (req, res) => {
  const r = await pool.query('select * from channels where id=$1', [req.params.id]);
  res.json(r.rows[0] || null);
});

app.post('/api/channels/:id/keys', async (req, res) => {
  const { scope = 'readwrite' } = req.body || {};
  const key = crypto.randomBytes(24).toString('hex');
  await pool.query('insert into api_keys(key, channel_id, scope) values ($1,$2,$3)', [key, req.params.id, scope]);
  res.json({ key, scope, channelId: req.params.id });
});

// Readings
app.post('/api/readings', writeLimiter, async (req, res) => {
  try {
    const apiKey = (req.header('x-api-key') || '').trim();
    const channelId = await checkApiKey(apiKey, 'write');
    if (!channelId) return res.status(401).json({ error: 'invalid key' });
    const channel = await getChannel(channelId);
    const fields = req.body || {};
    const keys = Object.keys(fields);
    if (!keys.length || keys.length > channel.max_fields) return res.status(400).json({ error: 'invalid fields' });
    if (channel.allowed_fields.length && !keys.every(k => channel.allowed_fields.includes(k))) return res.status(400).json({ error: 'field not allowed' });

    const last = await pool.query('select ts from readings where channel_id=$1 order by ts desc limit 1', [channelId]);
    const minGap = channel.min_write_interval_seconds;
    if (last.rows[0]) {
      const delta = (Date.now() - new Date(last.rows[0].ts).getTime()) / 1000;
      if (delta < minGap) return res.status(429).set('Retry-After', String(Math.ceil(minGap - delta))).json({ error: 'rate_limited' });
    }

    await pool.query('insert into readings(channel_id, fields, source) values ($1,$2,$3)', [channelId, fields, req.header('x-device-id') || null]);

    // evaluate workflows asynchronously (no await)
    evaluateWorkflows(channelId, fields).catch(() => {});

    res.status(202).set('X-Min-Poll-Interval', String(channel.min_read_interval_seconds)).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get('/api/readings/latest', readLimiter, async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'read');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const channel = await getChannel(channelId);
  const r = await pool.query('select ts, fields from readings where channel_id=$1 order by ts desc limit 1', [channelId]);
  const row = r.rows[0] || null;
  const etag = row ? `W/"${new Date(row.ts).getTime()}"` : 'W/"empty"';
  if (req.headers['if-none-match'] === etag) return res.status(304).end();
  res
    .set('ETag', etag)
    .set('Last-Modified', row ? new Date(row.ts).toUTCString() : new Date(0).toUTCString())
    .set('Cache-Control', `private, max-age=${channel.min_read_interval_seconds}`)
    .set('X-Min-Poll-Interval', String(channel.min_read_interval_seconds))
    .json(row);
});

app.get('/api/readings', readLimiter, async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'read');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const limit = Math.min(parseInt(String(req.query.limit || 100), 10), 500);
  const since = req.query.since ? new Date(String(req.query.since)) : null;
  const args = [channelId];
  let sql = 'select ts, fields from readings where channel_id=$1';
  if (since) { args.push(since); sql += ` and ts >= $${args.length}`; }
  sql += ' order by ts desc limit ' + limit;
  const r = await pool.query(sql, args);
  res.json(r.rows);
});

// Charts
app.get('/api/charts/series', readLimiter, async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'read');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const field = String(req.query.field || 'temperature');
  const limit = Math.min(parseInt(String(req.query.limit || 100), 10), 1000);
  const since = req.query.since ? new Date(String(req.query.since)) : null;
  const args = [channelId, field];
  let sql = "select ts, (fields->>$2)::numeric as value from readings where channel_id=$1 and fields ? $2";
  if (since) { args.push(since); sql += ` and ts >= $${args.length}`; }
  sql += ' order by ts desc limit ' + limit;
  const r = await pool.query(sql, args);
  res.set('X-Min-Poll-Interval', '5').json(r.rows.reverse());
});

// CSV export
app.get('/api/export/csv', readLimiter, async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'read');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const limit = Math.min(parseInt(String(req.query.limit || 1000), 10), 5000);
  const r = await pool.query('select ts, fields from readings where channel_id=$1 order by ts desc limit ' + limit, [channelId]);
  const rows = r.rows.map(x => ({ ts: x.ts, ...x.fields }));
  const csv = new Json2Csv().parse(rows);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="readings.csv"');
  res.send(csv);
});

// CSV import
const upload = multer();
app.post('/api/import/csv', writeLimiter, upload.single('file'), async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'write');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const text = req.file?.buffer.toString('utf8') || '';
  const records = csvParse(text, { columns: true, skip_empty_lines: true });
  const client = await pool.connect();
  try {
    await client.query('begin');
    for (const r of records) {
      const { ts, ...fields } = r;
      await client.query('insert into readings(channel_id, ts, fields) values ($1,$2,$3)', [channelId, ts ? new Date(ts) : new Date(), fields]);
    }
    await client.query('commit');
    res.json({ ok: true, count: records.length });
  } catch (e) {
    await client.query('rollback');
    res.status(400).json({ error: String(e.message || e) });
  } finally { client.release(); }
});

// Workflows
app.post('/api/workflows', async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'write');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const { name, enabled = true, rule, action } = req.body || {};
  const r = await pool.query('insert into workflows(channel_id, name, enabled, rule, action) values ($1,$2,$3,$4,$5) returning *', [channelId, name, enabled, rule, action]);
  res.json(r.rows[0]);
});

app.get('/api/workflows', async (req, res) => {
  const apiKey = (req.header('x-api-key') || '').trim();
  const channelId = await checkApiKey(apiKey, 'read');
  if (!channelId) return res.status(401).json({ error: 'invalid key' });
  const r = await pool.query('select * from workflows where channel_id=$1', [channelId]);
  res.json(r.rows);
});

async function evaluateWorkflows(channelId, fields) {
  const r = await pool.query('select * from workflows where channel_id=$1 and enabled', [channelId]);
  for (const wf of r.rows) {
    const rule = wf.rule || {}; const act = wf.action || {};
    const v = Number(fields?.[rule.field]);
    if (Number.isNaN(v)) continue;
    const pass = (rule.op === '>') ? v > rule.value : (rule.op === '>=') ? v >= rule.value : (rule.op === '<') ? v < rule.value : (rule.op === '<=') ? v <= rule.value : (rule.op === '==') ? v == rule.value : false;
    if (!pass) continue;
    if (act.type === 'webhook' && act.url) {
      fetch(act.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId, fields, ts: Date.now(), workflowId: wf.id }) }).catch(()=>{});
    }
  }
}

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`API listening on :${port}`));


