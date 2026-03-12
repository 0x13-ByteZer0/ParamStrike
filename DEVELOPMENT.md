# Desenvolvimento Local

## Pré-requisitos
- Rust 1.70+ (instale com rustup)
- Git
- (Opcional para LLM) Python 3 + pip ou Windows para usar bootstrap do llama-server
- Ferramentas externas opcionais: subfinder, katana, urlfinder, anew, pinchtab service, dalfox, nuclei

## Setup
```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
cargo build --release
```
Binário: `target/release/paramstrike`.

## Comandos úteis
- Build debug: `cargo build`
- Build release: `cargo build --release`
- Testes: `cargo test`
- Formatação: `cargo fmt`
- Lints: `cargo clippy`
- Auditoria: `cargo install cargo-audit && cargo audit`

## Fuzzing Nuclei
- Flags: `--nuclei`, `--nuclei-templates`, `--nuclei-rate`, `--nuclei-output`.
- Templates: usa `$NUCLEI_TEMPLATES`, `~/nuclei-templates` ou `./nuclei-templates`.
- Se nuclei não estiver no PATH, a etapa é ignorada com aviso.

## LLM / Unsloth
- Servidor esperado: OpenAI-compatible (`/v1/chat/completions`).
- Para bootstrap automático: use `--unsloth-bootstrap` + (opcional) `--hf-token <TOKEN>` ou `HF_TOKEN`.
- Linux/macOS: requer `python3` e `pip` no PATH para rodar `python -m llama_cpp.server`.
- Windows: bootstrap baixa `llama-server.exe`.

## Estrutura
```
src/main.rs   # Toda a lógica
Cargo.toml
docs (.md)    # README, ARCHITECTURE, etc.
```

## Fluxo de desenvolvimento
1) Branch: `feature/...` ou `fix/...`
2) Codar + `cargo fmt && cargo clippy && cargo test`
3) Se mexer em CLI/fluxos, atualize README/CHANGELOG.
4) PR com resumo breve.

## Troubleshooting rápido
- `cargo: command not found`: `source $HOME/.cargo/env` ou reinstale rustup.
- Erro de TLS em downloads: verifique proxy/certificados; rustls é usado.
- 401 ao baixar modelo HF: defina `HF_TOKEN` ou `--hf-token`.
- LLM não sobe: cheque se porta 8001 está livre e se `python3 -m llama_cpp.server` existe.
