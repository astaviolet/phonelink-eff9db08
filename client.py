#!/usr/bin/env python3
"""PhoneLink client — stdlib puro. Uso:
PL_REPO=OWNER/REPO PL_TOKEN=ghp_... PL_KEY=<hex> python3 pl.py "input tap 300 400"
PL_REPO=... PL_TOKEN=... PL_KEY=... PL_ID=ID1 python3 pl.py --read
"""
import os, sys, json, base64, secrets, hashlib, hmac, time, urllib.request, urllib.error

REPO = os.environ['PL_REPO']; TOKEN = os.environ['PL_TOKEN']; KEY = bytes.fromhex(os.environ['PL_KEY'])
API = 'https://api.github.com/repos/' + REPO
RAW = 'https://raw.githubusercontent.com/' + REPO + '/main/'
H = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json',
     'User-Agent': 'phonelink', 'X-GitHub-Api-Version': '2022-11-28',
     'Content-Type': 'application/json'}

def call(method, url, body=None):
    d = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=d, method=method, headers=H)
    with urllib.request.urlopen(r, timeout=40) as x:
        return json.loads(x.read() or b'{}')

def encrypt(s):
    ek = hashlib.sha256(KEY + b'enc').digest(); mk = hashlib.sha256(KEY + b'mac').digest()
    n = secrets.token_bytes(16); d = s.encode(); ks = b''; i = 0
    while len(ks) < len(d):
        ks += hashlib.sha256(ek + n + i.to_bytes(4,'big')).digest(); i += 1
    ct = bytes(a ^ b for a,b in zip(d, ks))
    return 'PL1.' + base64.b64encode(n + hmac.new(mk, n + ct, hashlib.sha256').digest()[:16] + ct).decode()

def decrypt(blob):
    if not blob.startswith('PL1.'): raise ValueError('payload nao cifrado')
    raw = base64.b64decode(blob[4:]); n, tag, ct = raw[:16], raw[16:32], raw[32:]
    mk = hashlib.sha256(KEY + b'mac').digest()
    if not hmac.compare_digest(tag, hmac.new(mk, n + ct, hashlib.sha256').digest()[:16]):
        raise ValueError('MAC invalido — comando rejeitado')
    ek = hashlib.sha256(KEY + b'enc').digest(); ks = b''; i = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(ek + n + i.to_bytes(4,'big')).digest(); i += 1
    return bytes(a ^ b for a,b in zip(ct, ks)).decode('utf-8', 'replace')

def send(cmd, ident=None):
    ident = ident or ('c' + str(int(time.time()*1000)))
    iss = call('POST', API + '/issues', {'title': 'pl', 'body': encrypt(cmd), 'labels': ['pl']})
    n = iss['number']
    print('ID=' + str(n))
    for _ in range(120):
        time.sleep(1)
        cs = call('GET', API + '/issues/%d/comments?per_page=100' % n)
        parts = [c['body'] for c in cs if c.get('body','').startswith('PL1.')]
        if parts:
            out = ''.join(decrypt(p) for p in parts)
            print(out)
            return
    print('(sem resposta ainda; use PL_ID=%d python3 pl.py --read)' % n)

def read(ident):
    cs = call('GET', API + '/issues/%s/comments?per_page=100' % ident)
    parts = [c['body'] for c in cs if c.get('body','').startswith('PL1.')]
    print(''.join(decrypt(p) for p in parts) if parts else '(sem resposta)')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--read':
        read(os.environ.get('PL_ID',''))
    else:
        send(' '.join(sys.argv[1:]) if len(sys.argv) > 1 else '!ping')
