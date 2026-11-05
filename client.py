#!/usr/bin/env python3
"""PhoneLink client — stdlib puro, sem instalacao, sem token no texto.
Uso:  PL_REPO=OWNER/REPO PL_KEY=<hex> python3 pl.py "input tap 300 400"
      PL_REPO=... PL_KEY=... PL_ID=123 python3 pl.py --read

O PAT fica cifrado em token.enc no proprio repo: o client busca e decifra.
"""
import os, sys, json, base64, secrets, hashlib, hmac, time, urllib.request

REPO = os.environ['PL_REPO']; KEY = bytes.fromhex(os.environ['PL_KEY'])
API = 'https://api.github.com/repos/' + REPO
RAW = 'https://raw.githubusercontent.com/' + REPO + '/main/'

def fetch(url):
    r = urllib.request.Request(url, headers={'User-Agent': 'phonelink', 'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(r, timeout=40) as x:
        return x.read().decode('utf-8', 'replace')

def decrypt(blob):
    raw = base64.b64decode(blob.strip()[4:])
    n, tag, ct = raw[:16], raw[16:32], raw[32:]
    mk = hashlib.sha256(KEY + b'mac').digest()
    if not hmac.compare_digest(tag, hmac.new(mk, n + ct, hashlib.sha256).digest()[:16]):
        raise ValueError('MAC invalido — payload rejeitado')
    ek = hashlib.sha256(KEY + b'enc').digest(); ks = b''; i = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(ek + n + i.to_bytes(4, 'big')).digest(); i += 1
    return bytes(a ^ b for a, b in zip(ct, ks)).decode('utf-8', 'replace')

def encrypt(s):
    ek = hashlib.sha256(KEY + b'enc').digest(); mk = hashlib.sha256(KEY + b'mac').digest()
    n = secrets.token_bytes(16); d = s.encode(); ks = b''; i = 0
    while len(ks) < len(d):
        ks += hashlib.sha256(ek + n + i.to_bytes(4, 'big')).digest(); i += 1
    ct = bytes(a ^ b for a, b in zip(d, ks))
    return 'PL1.' + base64.b64encode(n + hmac.new(mk, n + ct, hashlib.sha256).digest()[:16] + ct).decode()

TOKEN = decrypt(fetch(RAW + 'token.enc?t=%d' % time.time_ns()))
H = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json',
     'User-Agent': 'phonelink', 'X-GitHub-Api-Version': '2022-11-28',
     'Cache-Control': 'no-cache', 'Content-Type': 'application/json'}

def call(method, url, body=None):
    d = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=d, method=method, headers=H)
    with urllib.request.urlopen(r, timeout=40) as x:
        return json.loads(x.read() or b'{}')

def parts(ident):
    cs = call('GET', API + '/issues/%s/comments?per_page=100&t=%d' % (ident, time.time_ns()))
    return [c['body'] for c in cs if c.get('body', '').startswith('PL1.')]

def send(cmd):
    iss = call('POST', API + '/issues', {'title': 'pl', 'body': encrypt(cmd), 'labels': ['pl']})
    n = iss['number']; print('ID=' + str(n), flush=True)
    for _ in range(90):
        time.sleep(1)
        p = parts(n)
        if p:
            print(''.join(decrypt(b) for b in p), flush=True)
            return
    print('(sem resposta ainda; use PL_ID=%d python3 pl.py --read)' % n)

def read(ident):
    p = parts(ident)
    print(''.join(decrypt(b) for b in p) if p else '(sem resposta)')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--read':
        read(os.environ.get('PL_ID', ''))
    else:
        send(' '.join(sys.argv[1:]) if len(sys.argv) > 1 else '!ping')
