# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) e versões conforme SemVer.

## [Unreleased] - 2026-03-11
### Added
- 🤖 Integração Unsloth/llama-server com preflight de modelo.
- 🚀 `--unsloth-bootstrap` baixa o modelo Qwen3.5-8B-Instruct-GGUF e sobe servidor local (llama_cpp.server em Linux/macOS; binário em Windows).
- 🔑 Suporte a token HuggingFace (`--hf-token` ou env `HF_TOKEN`) para baixar modelos privados.
- 🗂️ Relatórios CSV de achados/falhas com `--report-prefix`.
- 🧭 Flags pinchtab (`--pinchtab-start`, `--pinchtab-scope`, `--pinchtab-scope-file`, `--pinchtab-host`) para coletar URLs com parâmetros.
- 🔦 Fuzzing de URLs filtradas com Nuclei (`--nuclei`, templates e rate configuráveis).

### Changed
- 🛡️ Validação de achados agora padrão via Unsloth; Ollama foi removido da CLI.
- 📦 Dependências principais: reqwest (blocking) + rustls, rayon para paralelismo, indicatif para progresso.
- 🔁 Verificação de atualização consulta releases do GitHub (não mais arquivos locais).
- 🧪 Exploração ativa inclui IDOR (deltas configurados) além de SQLi/XSS.

### Fixed
- ✅ Fallback quando `anew` não está instalado: deduplicação em Rust.
- ✅ Bootstrap agora funciona em plataformas não-Windows via python + llama_cpp.server.

---

## [1.1.0] - 2024-03-10
### Added
- ✨ Sistema de versionamento semântico.
- 🔧 `-up/--update` para atualizar via git pull + build.
- 📊 `-status` categoriza URLs por código HTTP.
- 🔍 Integração com subfinder (flag `-all`) para domínio único.

### Fixed
- ✅ Deduplicação de URLs com `anew` antes da categorização.

---

## [1.0.0] - 2024-03-10
### Added
- 🚀 Versão inicial com filtragem de parâmetros, modos padrão / domínio / batch, filtros de extensão e saída colorida.

---

## Futuro
- Exportação JSON/CSV avançada.
- Integrações adicionais de recon.
- Dashboard / API quando o núcleo estiver estável.
