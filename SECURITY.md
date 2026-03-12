# Política de Segurança

- Use o ParamStrike apenas em alvos com autorização explícita. Pentest não autorizado é ilegal.
- Tokens de terceiros:
  - Defina `HF_TOKEN` apenas em ambientes confiáveis; não faça commit de tokens.
  - O bootstrap grava o modelo em `unsloth_local/`; proteja esse diretório se o modelo for privado.
- Reporte vulnerabilidades no repositório abrindo uma issue com título `[security]`.
- Dependências:
  - Compile com rustls (padrão). Se alterar para OpenSSL, mantenha o ambiente atualizado.
  - Recomenda-se rodar `cargo audit` periodicamente.
