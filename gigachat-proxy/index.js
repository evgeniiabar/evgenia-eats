// Прокси GigaChat для Evgenia Eats (Yandex Cloud Functions, Node.js).
// Браузер не может ходить в GigaChat напрямую: нет CORS и сертификат Минцифры.
// Вход:  POST, заголовок x-giga-key (ключ авторизации), тело {image: base64 JPEG, prompt, model}
// Выход: {text} или {error}
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');

// Russian Trusted Root CA (Минцифры), действует до 27.02.2032
const RU_ROOT = `-----BEGIN CERTIFICATE-----
MIIFwjCCA6qgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwcDELMAkGA1UEBhMCUlUx
PzA9BgNVBAoMNlRoZSBNaW5pc3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFu
ZCBDb21tdW5pY2F0aW9uczEgMB4GA1UEAwwXUnVzc2lhbiBUcnVzdGVkIFJvb3Qg
Q0EwHhcNMjIwMzAxMjEwNDE1WhcNMzIwMjI3MjEwNDE1WjBwMQswCQYDVQQGEwJS
VTE/MD0GA1UECgw2VGhlIE1pbmlzdHJ5IG9mIERpZ2l0YWwgRGV2ZWxvcG1lbnQg
YW5kIENvbW11bmljYXRpb25zMSAwHgYDVQQDDBdSdXNzaWFuIFRydXN0ZWQgUm9v
dCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMfFOZ8pUAL3+r2n
qqE0Zp52selXsKGFYoG0GM5bwz1bSFtCt+AZQMhkWQheI3poZAToYJu69pHLKS6Q
XBiwBC1cvzYmUYKMYZC7jE5YhEU2bSL0mX7NaMxMDmH2/NwuOVRj8OImVa5s1F4U
zn4Kv3PFlDBjjSjXKVY9kmjUBsXQrIHeaqmUIsPIlNWUnimXS0I0abExqkbdrXbX
YwCOXhOO2pDUx3ckmJlCMUGacUTnylyQW2VsJIyIGA8V0xzdaeUXg0VZ6ZmNUr5Y
Ber/EAOLPb8NYpsAhJe2mXjMB/J9HNsoFMBFJ0lLOT/+dQvjbdRZoOT8eqJpWnVD
U+QL/qEZnz57N88OWM3rabJkRNdU/Z7x5SFIM9FrqtN8xewsiBWBI0K6XFuOBOTD
4V08o4TzJ8+Ccq5XlCUW2L48pZNCYuBDfBh7FxkB7qDgGDiaftEkZZfApRg2E+M9
G8wkNKTPLDc4wH0FDTijhgxR3Y4PiS1HL2Zhw7bD3CbslmEGgfnnZojNkJtcLeBH
BLa52/dSwNU4WWLubaYSiAmA9IUMX1/RpfpxOxd4Ykmhz97oFbUaDJFipIggx5sX
ePAlkTdWnv+RWBxlJwMQ25oEHmRguNYf4Zr/Rxr9cS93Y+mdXIZaBEE0KS2iLRqa
OiWBki9IMQU4phqPOBAaG7A+eP8PAgMBAAGjZjBkMB0GA1UdDgQWBBTh0YHlzlpf
BKrS6badZrHF+qwshzAfBgNVHSMEGDAWgBTh0YHlzlpfBKrS6badZrHF+qwshzAS
BgNVHRMBAf8ECDAGAQH/AgEEMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF
AAOCAgEAALIY1wkilt/urfEVM5vKzr6utOeDWCUczmWX/RX4ljpRdgF+5fAIS4vH
tmXkqpSCOVeWUrJV9QvZn6L227ZwuE15cWi8DCDal3Ue90WgAJJZMfTshN4OI8cq
W9E4EG9wglbEtMnObHlms8F3CHmrw3k6KmUkWGoa+/ENmcVl68u/cMRl1JbW2bM+
/3A+SAg2c6iPDlehczKx2oa95QW0SkPPWGuNA/CE8CpyANIhu9XFrj3RQ3EqeRcS
AQQod1RNuHpfETLU/A2gMmvn/w/sx7TB3W5BPs6rprOA37tutPq9u6FTZOcG1Oqj
C/B7yTqgI7rbyvox7DEXoX7rIiEqyNNUguTk/u3SZ4VXE2kmxdmSh3TQvybfbnXV
4JbCZVaqiZraqc7oZMnRoWrXRG3ztbnbes/9qhRGI7PqXqeKJBztxRTEVj8ONs1d
WN5szTwaPIvhkhO3CO5ErU2rVdUr89wKpNXbBODFKRtgxUT70YpmJ46VVaqdAhOZ
D9EUUn4YaeLaS8AjSF/h7UkjOibNc4qVDiPP+rkehFWM66PVnP1Msh93tc+taIfC
EYVMxjh8zNbFuoc7fzvvrFILLe7ifvEIUqSVIC/AzplM/Jxw7buXFeGP1qVCBEHq
391d/9RAfaZ12zkwFsl+IKwE/OZxW8AHa9i1p4GO0YSNuczzEm4=
-----END CERTIFICATE-----`;

const CA = [...tls.rootCertificates, RU_ROOT];
const OAUTH_URL = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth';
const API_URL = 'https://gigachat.devices.sberbank.ru/api/v1';
const SCOPE = 'GIGACHAT_API_PERS';
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, x-giga-key',
};

// Токен живёт 30 минут, держим его между вызовами, пока функция "тёплая"
const tokens = {};

function request(url, headers, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'POST', headers, ca: CA, timeout: 60000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (e) {}
        if (res.statusCode >= 300 || !json) {
          reject(new Error('GigaChat ' + res.statusCode + ': ' + ((json && json.message) || text.slice(0, 200))));
        } else resolve(json);
      });
    });
    req.on('timeout', () => req.destroy(new Error('GigaChat не ответил за 60 секунд')));
    req.on('error', reject);
    req.end(body);
  });
}

async function getToken(key) {
  const cached = tokens[key];
  if (cached && cached.expires > Date.now() + 60000) return cached.token;
  const data = await request(OAUTH_URL, {
    Authorization: 'Basic ' + key,
    RqUID: crypto.randomUUID(),
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  }, 'scope=' + SCOPE);
  tokens[key] = { token: data.access_token, expires: data.expires_at };
  return data.access_token;
}

function uploadImage(token, image) {
  const boundary = '----evg' + crypto.randomBytes(12).toString('hex');
  const body = Buffer.concat([
    Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name="purpose"\r\n\r\ngeneral\r\n'
      + '--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="food.jpg"\r\nContent-Type: image/jpeg\r\n\r\n'),
    image,
    Buffer.from('\r\n--' + boundary + '--\r\n'),
  ]);
  return request(API_URL + '/files', {
    Authorization: 'Bearer ' + token,
    'Content-Type': 'multipart/form-data; boundary=' + boundary,
    'Content-Length': body.length,
    Accept: 'application/json',
  }, body);
}

function reply(statusCode, obj) {
  return { statusCode, headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8' }, body: JSON.stringify(obj) };
}

module.exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST') return reply(405, { error: 'Только POST' });
  try {
    const headers = {};
    for (const k in event.headers || {}) headers[k.toLowerCase()] = event.headers[k];
    const key = headers['x-giga-key'];
    if (!key) return reply(401, { error: 'Нет ключа GigaChat' });
    const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : event.body;
    const { image, prompt, model } = JSON.parse(raw || '{}');
    if (!image || !prompt) return reply(400, { error: 'Нужны image и prompt' });

    const token = await getToken(key);
    const auth = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', Accept: 'application/json' };
    const file = await uploadImage(token, Buffer.from(image, 'base64'));
    try {
      const data = await request(API_URL + '/chat/completions', auth, JSON.stringify({
        model: model || 'GigaChat-2-Max',
        messages: [{ role: 'user', content: prompt, attachments: [file.id] }],
        temperature: 0.1,
        stream: false,
      }));
      return reply(200, { text: data.choices[0].message.content });
    } finally {
      // Фото в хранилище GigaChat не оставляем
      await request(API_URL + '/files/' + file.id + '/delete', auth, '').catch(() => {});
    }
  } catch (err) {
    return reply(502, { error: err.message });
  }
};
