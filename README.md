# PhoneLink relay — repo publico, conteudo CIFRADO

Barramento entre um celular Android (Shizuku) e agentes de IA. Issues/comentarios sao **cifrados ponta a ponta** (`PL1.` + nonce + HMAC-SHA256 + SHA-256-CTR). Sem a chave ninguem le nem injeta comandos. O token NAO esta neste repo. GitHub Actions (gratis em repo publico) usa apenas `GITHUB_TOKEN`, que nunca expira, para anti-spam e limpeza. Sem tunel, sem servidor, sem Cloudflare, sem cota diaria, sem 4 KB, sem URL que expira.
