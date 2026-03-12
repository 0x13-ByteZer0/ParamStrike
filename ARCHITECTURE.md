# Arquitetura do ParamStrike

## Visão geral
Monólito em `src/main.rs` (~1.3k linhas) orientado a pipeline:
1) Parse de argumentos e configuração (verbose, status, explore, unsloth, pinchtab).
2) Coleta de URLs (arquivo, subfinder/katana/urlfinder, pinchtab opcional).
3) Filtragem: remove extensões estáticas e exige query string.
4) (Opcional) Verificação de status HTTP em paralelo.
5) (Opcional) Exploração ativa SQLi/XSS/IDOR em paralelo.
6) (Opcional) Validação via Unsloth/llama-server e exportação CSV.

## Componentes principais
- **CLI & Config**: parsing manual de flags; constantes para cores, modelos e limites.
- **Coleta**:
  - Arquivo ou stdin via `-l`.
  - Domínio único `-d`: subfinder → katana → urlfinder.
  - Batch `-f`: katana + urlfinder.
  - Pinchtab (`coletar_urls_pinchtab`) via API HTTP, com dedup e limite de seeds.
- **Filtragem** (`filtrar_urls`):
  - BufReader para contagem/iteração.
  - `EXTENSOES_REMOVER` para ignorar ruído.
  - Barra de progresso (indicatif).
  - Dedup final com HashSet.
  - Saída via `anew` ou fallback em Rust.
- **Status HTTP** (`verificar_status_http`):
  - reqwest blocking com timeout; paralelismo com Rayon; arquivos por código HTTP.
- **Exploração ativa** (`explorar_vulnerabilidades`):
  - SQLi/XSS payloads fixos; IDOR com deltas.
  - Percent-encoding completo na injeção.
  - Baseline de resposta para diffs de tamanho (IDOR).
  - Resultados guardados em `Achado`.
- **Validação LLM** (`validar_com_unsloth`):
  - Chamada OpenAI-compatible `/v1/chat/completions`.
  - Prompt em PT-BR; extrai classificação e payloads extras.
  - Relatórios CSV com achados e falhas.
- **Bootstrap LLM** (`bootstrap_unsloth`):
  - Baixa modelo recomendado (Qwen3.5-8B Instruct Q4_K_M).
  - Windows: `llama-server.exe`; Linux/macOS: `python -m llama_cpp.server`.
  - Suporte a token HuggingFace (`--hf-token` / `HF_TOKEN`).

## Fluxos
### Modo padrão (-l)
arquivo → filtragem → (status?) → (explore?) → (unsloth?) → saída/CSV

### Modo domínio (-d)
subfinder → katana/urlfinder → filtragem → demais passos iguais ao padrão

### Bootstrap Unsloth
preflight /v1/models → se falhar e `--unsloth-bootstrap`:
  - baixa modelo (autenticado se token)
  - inicia servidor local
  - re-test /v1/models

## Dependências-chave
- reqwest (blocking, rustls), rayon, percent-encoding, indicatif, serde_json.
- Ferramentas externas opcionais: subfinder, katana, urlfinder, pinchtab service, anew.
- LLM opcional: llama-server/llama_cpp.server com modelo GGUF.

## Decisões de design
- **Simples primeiro**: monólito único facilita distribuição.
- **Paralelismo controlado**: uso de Rayon para CPU/I/O bound.
- **Fallbacks resilientes**: dedup sem `anew`, bootstrap LLM multiplataforma, avisos sem abortar pipeline.
- **Rustls**: evitar OpenSSL em ambientes mínimos.

## Pontos de extensão
- Novos payloads de exploração → constantes `SQLI_PAYLOADS`, `XSS_PAYLOADS`, `IDOR_DELTAS`.
- Novos filtros → `EXTENSOES_REMOVER` ou lógica em `filtrar_urls`.
- Outro validador LLM → adaptar `validar_com_unsloth` para outro endpoint compatível.
- Saídas extras → adicionar writer em `filtrar_urls` ou `salvar_relatorios`.
