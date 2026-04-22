import * as crypto from 'crypto';

const SHEET_ID = '12LcaLcrGPTebS_Ikr5wIK_v7h0-iVDOUEdwT7jy59qU';

function base64url(str) {
  return Buffer.from(str).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function getAccessToken(credentials) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim  = base64url(JSON.stringify({
    iss: credentials.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }));
  const sigInput = `${header}.${claim}`;
  const privateKey = crypto.createPrivateKey(credentials.private_key);
  const signature  = crypto.sign('sha256', Buffer.from(sigInput), privateKey);
  const jwt = `${sigInput}.${signature.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')}`;
  const res  = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Token error: ' + JSON.stringify(data));
  return data.access_token;
}

async function getSheetData(token, tab) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(tab + '!A1:ZZ')}`;
  const res  = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  const data = await res.json();
  return data.values || [];
}

export async function onRequest(context) {
  const url   = new URL(context.request.url);
  const email = (url.searchParams.get('email') || '').toLowerCase().trim();

  if (!email) {
    return new Response(JSON.stringify({ error: 'Email required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const credentials = JSON.parse(context.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessToken(credentials);

    const scanRows     = await getSheetData(token, 'Scan Data');
    const scanHeaders  = scanRows[0] || [];
    const scanEmailIdx = scanHeaders.findIndex(h => h?.toLowerCase().trim() === 'email');
    const scanData     = scanRows.slice(1)
      .filter(r => r[scanEmailIdx]?.toLowerCase().trim() === email)
      .map(r => { const obj = {}; scanHeaders.forEach((h, i) => { obj[h] = r[i] || ''; }); return obj; });

    const strRows      = await getSheetData(token, 'Strength Data');
    const strHeaders   = strRows[0] || [];
    const strEmailIdx  = strHeaders.findIndex(h => h?.toLowerCase().trim() === 'email');
    const strengthData = strRows.slice(1)
      .filter(r => r[strEmailIdx]?.toLowerCase().trim() === email)
      .map(r => { const obj = {}; strHeaders.forEach((h, i) => { obj[h] = r[i] || ''; }); return obj; });

    return new Response(JSON.stringify({ scanData, strengthData }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });

  } catch (err) {
    console.error('Error:', err);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
