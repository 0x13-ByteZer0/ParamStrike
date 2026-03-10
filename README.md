# ParamStrike

<div align="center">

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

**Uma ferramenta rápida para extração de parâmetros de URL e reconhecimento web**

[Sobre](#sobre) • [Features](#features) • [Instalação](#instalação) • [Uso](#uso) • [Exemplos](#exemplos) • [Contribuir](#contribuir)

</div>

---

## Sobre

**ParamStrike** é uma ferramenta de linha de comando em Rust para extrair, filtrar e analisar parâmetros de URLs. Pensada para segurança ofensiva, pentest e recon:
- 🎯 Filtro de URLs: extrai e normaliza parâmetros
- 🔍 Domínio Único: roda subfinder, katana e urlfinder
- 📑 Batch: processa múltiplos subdomínios a partir de arquivos
- 🧹 Limpeza: remove extensões estáticas/irrelevantes automaticamente
- 🧪 Exploração Ativa: testes básicos de SQLi e XSS (`-p/--explore`)
- 🤖 Validação Local: checagem de achados via Ollama (`--ollama`)
- 🎨 Saída Colorida: feedback visual em tempo real

---

## Features

- ⚡ Alta performance em Rust
- 🔐 Sem dependências perigosas
- 📊 Suporte a listas de URLs e domínios
- 🎯 Filtros inteligentes (extensões + URLs sem parâmetros)
- 🗄️ Saída configurável
- 🌈 Colorização ANSI e modo verbose
- ✅ Verificação de status HTTP (2xx, 3xx, 4xx, 5xx)
- 🔁 Atualização guiada: `-up/--update`
- 🧪 Exploração ativa (SQLi/XSS) com `-p/--explore`
- 🤖 Validação de falsos positivos via Ollama (`--ollama`, `--ollama-model`)

---

## Instalação

### Pré-requisitos
- Rust 1.70+
- Git
- Ollama (opcional, apenas para validação LLM). Instale em https://ollama.com/ e rode `ollama pull phi3:mini`.

### Clonar e compilar
```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
cargo build --release
```
Binário em `target/release/paramstrike` (ou `.exe` no Windows).

---

## Uso

### Sintaxe
```bash
paramstrike [OPÇÃO] [ARGUMENTOS]
```

### Opções
| Flag | Argumento | Descrição |
|------|-----------|-----------|
| `-l` | `<arquivo>` | Arquivo de entrada com URLs (modo padrão) |
| `-o` | `<arquivo>` | Arquivo de saída (padrão: `urls_parametros.txt`) |
| `-d` | `<domínio>` | Domínio único - executa subfinder, katana e urlfinder |
| `-f` | `<arquivo>` | Arquivo com lista de subdomínios para crawler |
| `-v, --verbose` | - | Modo verbose |
| `-status` | - | Verifica status HTTP e salva por código |
| `-p, --explore` | - | Exploração ativa (SQLi/XSS) |
| `--ollama` | - | Valida achados via modelo local do Ollama |
| `--ollama-model` | `<modelo>` | Define o modelo Ollama (padrão: `phi3:mini`) |
| `-up, --update` | - | Atualiza a ferramenta do Git e recompila |
| `-h, --help` | - | Mostra ajuda |

### Modos
- **Padrão**: `paramstrike -l urls.txt -o resultado.txt`
- **Domínio único**: `paramstrike -d example.com`
- **Batch**: `paramstrike -f subs.txt`

### Exploração ativa e validação com LLM
- Ative testes SQLi/XSS: `-p/--explore`
- Valide achados localmente: `--ollama --ollama-model phi3:mini`

---

## Exemplos

1. Filtrar URLs
```bash
paramstrike -l urls.txt -o parametros.txt
```
2. Verificar status HTTP + verbose
```bash
paramstrike -l urls.txt -o parametros.txt -status -v
```
3. Exploração ativa (SQLi/XSS)
```bash
paramstrike -l urls.txt -o parametros.txt -p
```
4. Exploração + validação no Ollama
```bash
paramstrike -l urls.txt -o parametros.txt -p --ollama --ollama-model phi3:mini
```
5. Atualizar a ferramenta
```bash
paramstrike -up
```

---

## Extensões filtradas
A ferramenta remove automaticamente URLs com extensões como: jpg, png, gif, css, js, json, pdf, docx, ttf, woff, mp4, exe, map (veja `EXTENSOES_REMOVER` em `src/main.rs`).

---

## Estrutura do projeto
```
ParamStrike/
├── Cargo.toml
├── src/
│   └── main.rs
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## Contribuir
Contribuições são bem-vindas! Abra issues ou PRs. Passos rápidos:
1. Fork → clone
2. `git checkout -b feature/minha-feature`
3. `cargo fmt && cargo clippy` (se aplicável)
4. Abra o PR

---

## Roadmap
- Suporte a mais ferramentas de recon
- Exportação JSON/CSV
- Integração com Burp Suite
- Análise avançada de parâmetros
- Dashboard web (futuro)

---

## Licença
MIT (veja [LICENSE](LICENSE)).

---

## Créditos
Desenvolvido por [0x13-ByteZer0](https://github.com/0x13-ByteZer0).

---

## Disclaimer
⚠️ Uso apenas com permissão explícita. Ferramenta para fins educacionais e de pesquisa autorizada.

---

## Suporte
- Abra uma [Issue](https://github.com/0x13-ByteZer0/ParamStrike/issues)
- Participe das [Discussões](https://github.com/0x13-ByteZer0/ParamStrike/discussions)

<div align="center">

**[↑ Voltar ao Topo](#paramstrike)**

</div>
