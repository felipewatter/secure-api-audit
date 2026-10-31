# Secure API Audit

[![CI](https://github.com/felipewatter/secure-api-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/secure-api-audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/felipewatter/secure-api-audit)](https://github.com/felipewatter/secure-api-audit/releases)

Ferramenta CLI em TypeScript/Node.js para **verificações HTTP não destrutivas e observacionais** de endpoints REST e GraphQL. O comportamento padrão evita acessar redes internas e não segue redirecionamentos.

## Novidades da v1.1.0

- Inspeção de HTTPS, HSTS e X-Content-Type-Options.
- Comparação entre resposta sem credenciais e resposta com bearer token, quando fornecido.
- Verificação de CORS com uma origem de teste; alertas para wildcard, reflexão arbitrária e Vary ausente.
- Cache-Control em respostas autenticadas e identificação de redirects (não seguidos).
- Regras de segurança de destino, bloqueio de SSRF, timeout e requisições limitadas.
- Modo opcional extra (chamado --aggressive por compatibilidade): somente OPTIONS e GET de caminho aleatório. **Não faz fuzzing destrutivo nem invasivo**.
- Relatórios textuais/JSON e códigos de saída adequados para CI.

**Importante:** um endpoint acessível sem autenticação pode ser intencionalmente público. O resultado é apresentado como observação que requer avaliação contextual, não como prova de falha. O modo observacional não garante ausência de vulnerabilidades.

## Instalação

Node.js 22 ou 24; npm.

    git clone https://github.com/felipewatter/secure-api-audit.git
    cd secure-api-audit
    npm install
    npm run build
    node dist/bin/index.js --help

Execução após instalação global a partir do repositório compilado:

    npm install -g .

O pacote **não foi publicado no registro npm**; não use npx assumindo publicação.

## Exemplos

Auditar serviço HTTPS autorizado:

    node dist/bin/index.js --url=https://api.example.com/health

Usar token por variável de ambiente (recomendado):

    export SECURE_API_AUDIT_TOKEN='valor-do-token'
    node dist/bin/index.js --url https://api.example.com/private --format json

No Windows PowerShell use: $env:SECURE_API_AUDIT_TOKEN='valor-do-token'.

Para integração em CI:

    node dist/bin/index.js --url https://api.example.com --fail-on high --format json

Para testes em laboratório local autorizado:

    node dist/bin/index.js --url http://127.0.0.1:3000/ --allow-http --allow-private

Verificações adicionais seguras:

    node dist/bin/index.js --url https://api.example.com --aggressive

## Opções

| Opção | Padrão | Significado |
|---|---|---|
| --url | Obrigatório | URL absoluta exata a auditar |
| --token-env NOME | SECURE_API_AUDIT_TOKEN | Nome de variável que contém token bearer |
| --token VALOR | — | Opção legada; não recomendada pela exposição no shell |
| --allow-http | Desativado | Autoriza HTTP não criptografado |
| --allow-private | Desativado | Autoriza IPs e nomes locais |
| --aggressive | Desativado | Adiciona OPTIONS preflight e GET a caminho aleatório |
| --timeout MS | 8000 | Limite de tempo entre 100 e 30000 ms |
| --format text/json | text | Formato dos resultados |
| --fail-on none/medium/high | high | Limiar de código de saída |
| --help / --version | — | Ajuda e versão |

Códigos: **0** sem findings no limiar, **1** findings no limiar ou acima, **2** erro operacional. Retornar 0 não equivale a declarar que uma API é segura.

## Práticas e escopo

Faça auditorias apenas em ativos próprios ou autorizados. A ferramenta realiza GET e OPTIONS e não executa POST, PATCH, DELETE, payload fuzzing mutável ou exploração de vulnerabilidades.

As verificações se limitam a indícios nos cabeçalhos e códigos HTTP. Não há suporte a autorização por objeto, GraphQL introspection, SQLi, XSS, testes de CSRF nem verificação automática de privacidade. Um CORS permissivo sozinho não comprova acesso a dados sensíveis. O resultado de cada teste exige análise contextual.

A proteção por IP/DNS é uma camada adicional, não substitui firewall de egress. IPv6 público exige --allow-private nesta versão porque a política de endereços IPv6 ainda não foi implementada. URL com query é permitida para o teste, mas o relatório omite os parâmetros.

## Qualidade

    npm run typecheck
    npm test
    npm pack --dry-run

O CI valida Node.js 22/24 em Ubuntu, Windows e macOS com testes unitários e HTTP local controlado, sem sondar serviços reais externos.

MIT. Consulte SECURITY.md e CHANGELOG.md.
