# Contribuindo

Obrigado por contribuir com o ParamStrike! Segue um guia rápido.

## Processo
1. Abra uma issue descrevendo a mudança/bug.
2. Faça fork e crie uma branch: `feature/...` ou `fix/...`.
3. Rode checagens locais:
   - `cargo fmt`
   - `cargo clippy`
   - `cargo test`
4. Se alterar CLI/comportamento, atualize README/CHANGELOG.
5. Abra o PR com:
   - Resumo curto
   - Passos de teste executados
   - Screens/logs relevantes (se aplicável)

## Estilo de código
- Rust 2021.
- Prefira early-return para fluxos de erro.
- Comentários curtos apenas onde o código não é autoexplicativo.
- Evite dependências novas sem discutir em issue.

## Segurança
- Não inclua tokens ou credenciais em commits.
- Para LLM bootstrap, lembre-se de que `HF_TOKEN` é opcional; não hardcode.

## Commits
- Use mensagens claras: `Add: ...`, `Fix: ...`, `Change: ...`.
- Agrupe mudanças relacionadas; evite commits gigantes mistos.

## Testes opcionais
- `cargo audit` (se disponível).
- Rodar um fluxo manual: `cargo run -- -l sample_urls.txt -p --unsloth` (se tiver ambiente LLM).
