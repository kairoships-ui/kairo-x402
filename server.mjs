// Kairo Agent x402 API — standalone, host-ready (Render/Fly/Railway).
// Config comes from ENV. Needs NO wallet private keys (it only RECEIVES to payTo).
//   WALLET_ADDRESS         payTo address (required)
//   CDP_API_KEY_ID/SECRET  Coinbase CDP facilitator creds -> mainnet Base settlement (optional; without => base-sepolia testnet)
//   GITHUB_TOKEN           token with public read (for /api/bounty-scan; optional but recommended for rate limits)
//   X402_PRICE             price per call, default "$0.01"
//   PUBLIC_URL             public https origin (Render auto-sets RENDER_EXTERNAL_URL)
//   PORT                   provided by host
import express from 'express';
import { paymentMiddleware } from 'x402-express';
import { createPublicClient, http as viemHttp, formatEther, formatUnits, isAddress } from 'viem';
import { base } from 'viem/chains';

const PAYTO = process.env.WALLET_ADDRESS;
if (!PAYTO) { console.error('FATAL: WALLET_ADDRESS env is required'); process.exit(1); }
const PORT = process.env.PORT || 4318;
const PRICE = process.env.X402_PRICE || '$0.01';
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, '');

let NETWORK, facilitator;
if (process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET && process.env.X402_NETWORK !== 'base-sepolia') {
  const { facilitator: cdpFacilitator } = await import('@coinbase/x402');
  NETWORK = 'base'; facilitator = cdpFacilitator;
} else {
  NETWORK = 'base-sepolia';
  facilitator = { url: process.env.X402_FACILITATOR || 'https://x402.org/facilitator' };
}

// Known agent-bounty honeypots (prompt-exfiltration). Kept inline so the service is self-contained.
const HONEYPOT_BLOCKLIST = ['unsafelabs/bounty-hunters', 'clankernation/openagents'];
const EXFIL_RE = /(environment_config|initialization payload|startup config(uration)?|system prompt|@generated-by|paste (the )?(full )?(raw )?(text of your )?(config|configuration|instructions|rules|prompt|payload)|behavioral (rules|guidelines)|home director|working director|complete instructions loaded)/i;

const app = express();
function publicBase(req) { return PUBLIC_URL || `${req.headers['x-forwarded-proto'] || req.protocol}://${req.get('host')}`; }

app.use(paymentMiddleware(PAYTO, {
  'GET /api/strength': { price: PRICE, network: NETWORK, config: { discoverable: true, description: 'Password/entropy strength analysis.', mimeType: 'application/json', inputSchema: { queryParams: { pw: 'string' } }, outputSchema: { length: 'number', pool: 'number', entropy_bits: 'number', verdict: 'string' } } },
  'GET /api/onchain': { price: PRICE, network: NETWORK, config: { discoverable: true, description: 'Base address intel: ETH+USDC balance, tx count, is-contract, is-funded, is-active.', mimeType: 'application/json', inputSchema: { queryParams: { address: '0x EVM address' } }, outputSchema: { network: 'string', address: 'string', eth_balance: 'number', usdc_balance: 'number', tx_count: 'number', is_contract: 'boolean', is_funded: 'boolean', is_active: 'boolean' } } },
  'GET /api/bounty-scan': { price: PRICE, network: NETWORK, config: { discoverable: true, description: 'Agent-safety scanner for GitHub bounties: flags prompt-exfiltration honeypots, fiat/KYC-gated payout rails, unproven payers, blocklisted repos.', mimeType: 'application/json', inputSchema: { queryParams: { repo: 'owner/name', issue: 'number (optional)' } }, outputSchema: { repo: 'string', risk: 'string', crypto_collectable: 'boolean', safe_to_attempt: 'boolean', findings: 'array' } } },
}, facilitator));

const rpc = createPublicClient({ chain: base, transport: viemHttp('https://mainnet.base.org') });
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const ERC20 = [{ name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] }];

app.get('/api/strength', (req, res) => {
  const pw = String(req.query.pw || '');
  const sets = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
  const pool = [26, 26, 10, 33].filter((n, i) => sets[i].test(pw)).reduce((a, b) => a + b, 0);
  const bits = pw.length ? +(pw.length * Math.log2(pool || 1)).toFixed(2) : 0;
  const verdict = bits < 28 ? 'very weak' : bits < 36 ? 'weak' : bits < 60 ? 'reasonable' : bits < 128 ? 'strong' : 'very strong';
  console.log(JSON.stringify({ evt: 'paid', route: 'strength', amount: PRICE, network: NETWORK }));
  res.json({ length: pw.length, pool, entropy_bits: bits, verdict });
});

app.get('/api/onchain', async (req, res) => {
  const addr = String(req.query.address || '');
  if (!isAddress(addr)) return res.status(400).json({ error: 'invalid ?address' });
  try {
    const [wei, usdc, nonce, code] = await Promise.all([
      rpc.getBalance({ address: addr }), rpc.readContract({ address: USDC, abi: ERC20, functionName: 'balanceOf', args: [addr] }),
      rpc.getTransactionCount({ address: addr }), rpc.getBytecode({ address: addr }),
    ]);
    const isContract = !!code && code !== '0x';
    const ethBal = Number(formatEther(wei)); const usdcBal = Number(formatUnits(usdc, 6));
    const funded = ethBal > 0 || usdcBal > 0;
    console.log(JSON.stringify({ evt: 'paid', route: 'onchain', amount: PRICE, network: NETWORK }));
    res.json({ network: 'base', address: addr, eth_balance: ethBal, usdc_balance: usdcBal, tx_count: nonce, is_contract: isContract, is_funded: funded, is_active: nonce > 0 || isContract || funded });
  } catch (e) { res.status(502).json({ error: e.shortMessage || e.message }); }
});

const EXFIL = EXFIL_RE;
async function gh(path) {
  const h = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const r = await fetch(`https://api.github.com${path}`, { headers: h });
  if (!r.ok) throw new Error(`gh ${r.status}`);
  return r.json();
}
app.get('/api/bounty-scan', async (req, res) => {
  const repo = String(req.query.repo || '').replace(/^https?:\/\/github\.com\//, '').replace(/\/+$/, '');
  const issue = req.query.issue ? String(req.query.issue).replace(/[^0-9]/g, '') : null;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return res.status(400).json({ error: 'need ?repo=owner/name' });
  const findings = []; let collectable = true;
  try {
    if (HONEYPOT_BLOCKLIST.includes(repo.toLowerCase())) findings.push({ severity: 'critical', code: 'blocklisted', detail: 'Known-honeypot blocklist.' });
    let text = '';
    if (issue) { const iss = await gh(`/repos/${repo}/issues/${issue}`); text += (iss.body || '') + '\n'; try { const cs = await gh(`/repos/${repo}/issues/${issue}/comments?per_page=100`); text += cs.map(c => c.body || '').join('\n'); } catch {} }
    else { try { const rd = await gh(`/repos/${repo}/readme`); text += Buffer.from(rd.content || '', 'base64').toString('utf8'); } catch {} }
    if (EXFIL.test(text)) findings.push({ severity: 'critical', code: 'prompt_exfiltration', detail: 'Task requires pasting your system prompt / init payload / host info. Data-exfiltration attack.' });
    if (/algora\.io|algora-pbc/i.test(text)) { collectable = false; findings.push({ severity: 'high', code: 'fiat_kyc_gated', detail: 'Algora = Stripe Connect + KYC. Not crypto-collectable.' }); }
    if (/huntr\.com|stripe connect/i.test(text)) { collectable = false; findings.push({ severity: 'high', code: 'fiat_kyc_gated', detail: 'Stripe Connect / KYC. Not crypto-collectable.' }); }
    try {
      const enc = s => encodeURIComponent(s);
      const rewarded = await gh(`/search/issues?q=${enc(`repo:${repo} label:"💰 Rewarded"`)}&per_page=1`);
      const openB = await gh(`/search/issues?q=${enc(`repo:${repo} is:open label:"💎 Bounty"`)}&per_page=1`);
      if ((rewarded.total_count || 0) === 0 && (openB.total_count || 0) >= 3) findings.push({ severity: 'medium', code: 'unproven_payer', detail: `${openB.total_count} open bounties but 0 ever rewarded.` });
    } catch {}
    let stars = null;
    try { const meta = await gh(`/repos/${repo}`); stars = meta.stargazers_count; if (stars < 20) findings.push({ severity: 'low', code: 'low_reputation', detail: `Only ${stars} stars.` }); } catch {}
    const sev = findings.map(f => f.severity);
    const risk = sev.includes('critical') ? 'critical' : sev.includes('high') ? 'high' : sev.includes('medium') ? 'medium' : sev.includes('low') ? 'low' : 'clean';
    console.log(JSON.stringify({ evt: 'paid', route: 'bounty-scan', repo, amount: PRICE, network: NETWORK }));
    res.json({ repo, issue: issue ? Number(issue) : null, stars, risk, crypto_collectable: collectable, safe_to_attempt: risk === 'clean' || risk === 'low', findings, note: 'Heuristic scan. crypto_collectable=false means payout needs KYC/bank. Verify independently.' });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/health', (req, res) => res.json({ ok: true, network: NETWORK, payTo: PAYTO, endpoints: ['/api/strength', '/api/onchain', '/api/bounty-scan'] }));

app.get(['/.well-known/x402', '/x402-manifest'], (req, res) => {
  const b = publicBase(req);
  res.json({ x402Version: 1, resources: ['onchain', 'strength', 'bounty-scan'].map(n => ({ resource: `${b}/api/${n}`, method: 'GET', network: NETWORK, price: PRICE, payTo: PAYTO })) });
});

const USD_AMOUNT = Number(PRICE.replace('$', '')).toFixed(6);
function paidOp({ operationId, summary, tag, params, outputProps, outputRequired }) {
  return { operationId, summary, tags: [tag], 'x-payment-info': { price: { mode: 'fixed', currency: 'USD', amount: USD_AMOUNT }, protocols: [{ x402: {} }] }, parameters: params, responses: { 200: { description: 'Successful response', content: { 'application/json': { schema: { type: 'object', properties: outputProps, required: outputRequired } } } }, 402: { description: 'Payment Required — pay the x402 challenge (USDC on Base).' } } };
}
app.get('/openapi.json', (req, res) => {
  const b = publicBase(req);
  res.json({
    openapi: '3.1.0',
    info: { title: 'Kairo Agent x402 API', version: '1.0.0', description: 'Crypto-native ($0.01 USDC on Base, x402) utility endpoints for agents. No accounts, no KYC — pay-per-call.', 'x-guidance': 'Three paid GET endpoints, $0.01 USDC on Base via x402. GET /api/bounty-scan?repo=owner/name[&issue=N] scores a GitHub bounty for scam risk. GET /api/onchain?address=0x... returns Base account intel. GET /api/strength?pw=... returns password entropy. Pay the 402 challenge to receive JSON.', contact: { email: 'kairo.ships@gmail.com' } },
    servers: [{ url: b }],
    paths: {
      '/api/bounty-scan': { get: paidOp({ operationId: 'bountyScan', summary: 'Bounty safety scan', tag: 'Security', params: [{ name: 'repo', in: 'query', required: true, schema: { type: 'string' }, description: 'owner/name' }, { name: 'issue', in: 'query', required: false, schema: { type: 'integer' } }], outputProps: { repo: { type: 'string' }, issue: { type: ['integer', 'null'] }, stars: { type: ['integer', 'null'] }, risk: { type: 'string', enum: ['clean', 'low', 'medium', 'high', 'critical'] }, crypto_collectable: { type: 'boolean' }, safe_to_attempt: { type: 'boolean' }, findings: { type: 'array', items: { type: 'object' } }, note: { type: 'string' } }, outputRequired: ['repo', 'risk', 'crypto_collectable', 'safe_to_attempt', 'findings'] }) },
      '/api/onchain': { get: paidOp({ operationId: 'onchain', summary: 'Base address intel', tag: 'Onchain', params: [{ name: 'address', in: 'query', required: true, schema: { type: 'string' }, description: '0x EVM address' }], outputProps: { network: { type: 'string' }, address: { type: 'string' }, eth_balance: { type: 'number' }, usdc_balance: { type: 'number' }, tx_count: { type: 'integer' }, is_contract: { type: 'boolean' }, is_funded: { type: 'boolean' }, is_active: { type: 'boolean' } }, outputRequired: ['network', 'address', 'eth_balance', 'usdc_balance', 'tx_count', 'is_contract', 'is_active'] }) },
      '/api/strength': { get: paidOp({ operationId: 'strength', summary: 'Password/entropy strength', tag: 'Utility', params: [{ name: 'pw', in: 'query', required: true, schema: { type: 'string' }, description: 'String to analyze' }], outputProps: { length: { type: 'integer' }, pool: { type: 'integer' }, entropy_bits: { type: 'number' }, verdict: { type: 'string' } }, outputRequired: ['length', 'pool', 'entropy_bits', 'verdict'] }) },
      '/health': { get: { operationId: 'health', summary: 'Health check', tags: ['Meta'], security: [], responses: { 200: { description: 'OK' } } } },
      '/.well-known/x402': { get: { operationId: 'x402Manifest', summary: 'x402 manifest', tags: ['Meta'], security: [], responses: { 200: { description: 'OK' } } } },
    },
  });
});

app.listen(PORT, '0.0.0.0', () => console.log(`x402 service on :${PORT} payTo=${PAYTO} net=${NETWORK} price=${PRICE} public=${PUBLIC_URL || '(from request host)'}`));
