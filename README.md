# ParamStrike

Uma ferramenta rápida em Rust para filtrar URLs, testar parâmetros (SQLi/XSS/IDOR) e validar achados com modelos locais via llama-server/Unsloth.

---

## Sumário
Sobre • Features • Instalação • Uso • Exemplos • FAQ • Contribuir

---

## Sobre
ParamStrike lê listas de URLs, remove ruído (extensões estáticas), verifica status HTTP, faz provas de conceito básicas de SQLi/XSS/IDOR e, opcionalmente, valida os achados com um LLM local exposto em modo OpenAI-compatible (llama-server/Unsloth). Há modos para um domínio, batch de subdomínios e coleta com pinchtab.

---

## Features
- ⚡ Paralelismo com Rayon (filtragem e exploração).
- 🔍 Modos: arquivo (`-l`), domínio único (`-d` com subfinder/katana/urlfinder) e batch (`-f`).
- 🧹 Filtro de extensões irrelevantes (imagens, mídia, fontes, binários, map etc).
- ✅ Status HTTP categorizado (2xx/3xx/4xx/5xx/sem resposta).
- 🧪 Exploração ativa: SQLi, XSS refletido, IDOR com deltas.
- 🤖 Validação de achados via Unsloth/llama-server (`--unsloth`).
- 🛠️ Bootstrap automático do modelo/servidor (`--unsloth-bootstrap`) com suporte a token HuggingFace (`--hf-token` ou `HF_TOKEN`).
- 🗂️ Relatórios CSV de achados/falhas (`--report-prefix`).
- 🌈 Saída colorida e barra de progresso (indicatif).
- 🔁 Auto-update opcional (`-up`).

---

## Instalação
Pré-requisitos:
- Rust 1.70+
- Git
- (Opcional) Python 3 + pip **ou** Windows para usar o bootstrap do llama-server

Passos:
```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
cargo build --release
```
Binário: `target/release/paramstrike` (ou `.exe` no Windows).

LLM opcional (bootstrap):
- Tenha `python3` + `pip` no PATH (Linux/macOS) **ou** deixe o bootstrap baixar `llama-server.exe` (Windows).
- Para modelos privados do HuggingFace, defina `HF_TOKEN` ou use `--hf-token <token>`.

---

## Uso rápido
Sintaxe:
```bash
paramstrike [OPÇÕES]
```

Principais flags:
| Flag | Descrição |
| --- | --- |
| `-l <arquivo>` | Arquivo de entrada com URLs (modo padrão) |
| `-o <arquivo>` | Saída (padrão: `urls_parametros.txt`) |
| `-d <domínio>` | Domínio único (subfinder + katana + urlfinder) |
| `-f <arquivo>` | Lista de subdomínios (batch) |
| `-v/--verbose` | Verbose |
| `-status` | Checa status HTTP e separa por código |
| `-p/--explore` | Testes SQLi/XSS/IDOR |
| `--unsloth` | Valida achados com LLM (OpenAI-compatible) |
| `--unsloth-model <m>` | Alias/modelo no llama-server (padrão `unsloth/Qwen3.5-8B-Instruct-GGUF`) |
| `--unsloth-host <url>` | Host do servidor (padrão `http://127.0.0.1:8001`) |
| `--unsloth-bootstrap` | Baixa o modelo recomendado e sobe o servidor local |
| `--hf-token <t>` | Token HuggingFace (ou use env `HF_TOKEN`) |
| `--report-prefix <p>` | Gera `<p>_achados.csv` e `<p>_falhas.csv` |
| `--pinchtab-start <url>` | Seed inicial para coleta com pinchtab |
| `--pinchtab-scope <dom>` / `--pinchtab-scope-file <arq>` | Restringe seeds pinchtab |
| `-up/--update` | Atualiza via git pull + cargo build |

---

## Exemplos
Filtrar URLs:
```bash
paramstrike -l urls.txt -o parametros.txt
```
Status + verbose:
```bash
paramstrike -l urls.txt -status -v
```
Explorar (SQLi/XSS/IDOR) e validar com LLM bootstrap:
```bash
paramstrike -l urls.txt -p --unsloth --unsloth-bootstrap --report-prefix rel
```
Domínio único completo:
```bash
paramstrike -d example.com -p --unsloth
```

---

## FAQ (resumo)
- **Deu 401 ao baixar o modelo?** Use `HF_TOKEN=<token>` ou `--hf-token <token>`. Alguns repositórios do HuggingFace exigem autenticação.
- **Preciso do llama-server já rodando?** Não, `--unsloth-bootstrap` sobe um servidor local (python -m llama_cpp.server em Linux/macOS; binário em Windows).
- **E se o binário `anew` não estiver instalado?** A ferramenta faz fallback para escrita e deduplicação em Rust.
- **Quais extensões são filtradas?** Ver `EXTENSOES_REMOVER` em `src/main.rs` (imagens, docs, mídia, fontes, mapas, binários etc).

---

## Contribuir
PRs são bem-vindos! Passos rápidos:
1) Fork + branch (`feature/…` ou `fix/…`)  
2) `cargo fmt && cargo clippy && cargo test`  
3) Abra o PR com breve descrição.

---

## Licença
MIT. Veja `LICENSE`.

---

## Aviso
Use apenas com autorização explícita. Pentest não autorizado é ilegal.***
