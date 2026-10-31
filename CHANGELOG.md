# Changelog

## 1.1.0 — 2026-10-31

- Corrigida avaliação de autenticação com uma requisição anônima mesmo quando um token é fornecido.
- Adicionadas verificações de CORS com origem arbitrária, TLS/HSTS e cabeçalhos defensivos.
- Bloqueio de SSRF por IP/hostname especial, conferência DNS no ponto de conexão e redirecionamentos sem seguimento.
- Modo --aggressive limitado a probes não destrutivos GET e OPTIONS.
- CLI completa com formatos JSON/texto, timeout, critérios de falha e códigos 0/1/2.
- Compatibilidade com --token legada, preferência por variáveis de ambiente.
- 16 testes automatizados e CI multiplataforma, documentação e modelo de limites.

## 1.0.0 — 2025-07-07

- Versão inicial da CLI com verificações demonstrativas.
