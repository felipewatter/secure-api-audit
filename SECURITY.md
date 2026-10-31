# Segurança e divulgação de vulnerabilidades

Reporte falhas de maneira privada via GitHub Security Advisories (quando habilitado). Não envie tokens, credenciais ou resultados contendo informações privadas por issues públicas.

Esta ferramenta faz **requisições HTTP e HTTPS reais** contra endpoints escolhidos pelo operador. Execute apenas contra serviços sob sua responsabilidade ou para os quais recebeu autorização.

Proteções: HTTPS obrigatório por padrão; bloqueio de IPs especiais e internos e hostnames locais; conferência do endereço DNS no ponto de conexão; resolução de DNS sem aceitar múltiplos endereços proibidos; bloqueio de redirecionamentos; métodos GET/OPTIONS, sem envio de corpos; timeout; não leitura de corpos HTTP. HTTP e endereços privados só são permitidos com flags de opt-in explícitas.

**Limitações:** a lista de redes privadas/reservadas não é uma política completa de egress; IPv6 é negado por padrão; outras formas de bypass dependem da infraestrutura. Implemente um firewall/regras de saída no ambiente de execução. Não execute com NODE_TLS_REJECT_UNAUTHORIZED=0. Não há scanners mutáveis, fuzz de payloads, exploração, autenticação GraphQL introspectiva, varredura de portas, validação RBAC por objeto ou certificação de conformidade.

Tokens são enviados exclusivamente ao destino explicitamente configurado (sem seguir redirecionamentos). Preferir --token-env e variável SECURE_API_AUDIT_TOKEN; --token é aceito por compatibilidade, mas pode vazar no histórico do terminal e listagem de processos. As mensagens de erro e relatórios não devem conter secrets.

O serviço acessado pode registrar as requisições de auditoria. Não é adequado para produção sem janela ou aprovação do responsável.
