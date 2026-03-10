# ParamStrike

<div align="center">

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Version](https://img.shields.io/badge/Version-1.1.0-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

**Uma ferramenta poderosa e rápida para extração de parâmetros de URL e reconhecimento web**

[Sobre](#sobre) • [Features](#features) • [Instalação](#instalação) • [Uso](#uso) • [Exemplos](#exemplos) • [Contribuir](#contribuir)

</div>

---

## Sobre

**ParamStrike** é uma ferramenta de linha de comando desenvolvida em Rust para extrair, filtrar e analisar parâmetros de URLs. Perfeita para profissionais de segurança, pentesting e reconhecimento web, oferecendo múltiplos modos de operação:

- 🎯 **Filtro de URLs**: Extrai parâmetros de uma lista de URLs
- 🔍 **Modo Domínio Único**: Executa subfinder, katana e urlfinder em um domínio específico
- 📑 **Modo Batch**: Processa múltiplos subdomínios a partir de um arquivo
- 🗑️ **Limpeza Automática**: Remove extensões de arquivo irrelevantes
- 🎨 **Saída Colorida**: Interface amigável com feedback visual em tempo real

---

## Features

✨ **Características Principais:**

- ⚡ **Alta Performance**: Desenvolvido em Rust para máxima velocidade
- 🔐 **Seguro**: Sem dependências externas perigosas
- 📊 **Múltiplos Formatos**: Suporta listas de URLs e domínios
- 🎯 **Filtros Inteligentes**: Remove extensões e parâmetros irrelevantes
- 💾 **Saída Configurável**: Especifique arquivo de saída personalizado
- 🖥️ **CLI Intuitiva**: Flags simples e help integrado
- 🌈 **Colorização ANSI**: Melhor legibilidade do output
- ✅ **Verificação de Status HTTP**: Categoriza URLs por status (2xx, 3xx, 4xx, 5xx)
- 🔄 **Auto-Update**: Atualiza do Git e recompila automaticamente
- 📦 **Versionamento Automático**: Incrementa versão a cada atualização
- 🔍 **Verbose Mode**: Acompanhe o processamento em detalhes
- 🎨 **Status Visual**: Mostra se há atualizações disponíveis

---

## Instalação

### Pré-requisitos

- **Rust 1.70+** ([Instalar Rust](https://www.rust-lang.org/tools/install))
- **Git**

### Método 1: Clonando o Repositório

```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
cargo build --release
```

O binário compilado estará em `target/release/filter_master` (ou `filter_master.exe` no Windows).

### Método 2: Instalação Global (Cargo)

```bash
cargo install --git https://github.com/0x13-ByteZer0/ParamStrike.git
```

---

## Uso

### Sintaxe Geral

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
| `-v, --verbose` | - | Modo verbose (mostra fluxo de processamento detalhado) |
| `-status` | - | Verifica status HTTP e salva URLs em arquivos separados (2xx, 3xx, 4xx, 5xx) |
| `-up, --update` | - | Atualiza a ferramenta do Git e recompila automaticamente |
| `-h, --help` | - | Mostra mensagem de ajuda |

### Modos de Operação

#### 1️⃣ Modo Padrão - Filtrar URLs

Extrai parâmetros de um arquivo contendo URLs:

```bash
paramstrike -l urls.txt -o resultado.txt
```

**Exemplo de arquivo de entrada (`urls.txt`):**
```
https://example.com/pagina?id=123&user=admin
https://example.com/search?q=teste&page=1
https://example.com/api/user?id=456
```

**Saída (`resultado.txt`):**
```
https://example.com/pagina?id=&user=
https://example.com/search?q=&page=
https://example.com/api/user?id=
```

#### 2️⃣ Modo Domínio Único

Executa ferramentas integradas (subfinder, katana, urlfinder) em um domínio:

```bash
paramstrike -d example.com
```

#### 3️⃣ Modo Batch - Processar Subdomínios

```bash
paramstrike -f subdomains.txt
```

---

## Exemplos

### Exemplo 1: Filtrar URLs de um arquivo

```bash
paramstrike -l urls.txt -o parametros.txt
```

### Exemplo 2: Filtrar com modo verbose

```bash
paramstrike -l urls.txt -o parametros.txt -v
```

### Exemplo 3: Verificar status HTTP das URLs

```bash
paramstrike -l urls.txt -o parametros.txt -status
```

Gera arquivos separados:
- `parametros_2xx_sucessos.txt` - URLs com status 200-299
- `parametros_3xx_redirecionamentos.txt` - URLs com status 300-399
- `parametros_4xx_erros_cliente.txt` - URLs com status 400-499
- `parametros_5xx_erros_servidor.txt` - URLs com status 500-599

### Exemplo 4: Combinar verbose e status

```bash
paramstrike -l urls.txt -o parametros.txt -v -status
```

### Exemplo 5: Extrair parâmetros de um domínio único

```bash
paramstrike -d example.com
```

Automáticamente executa:
1. `subfinder -d example.com -all` - Encontra subdomínios
2. `katana -list subdomínios.txt` - Crawla os subdomínios
3. `urlfinder -i subdomínios.txt` - Extrai URLs adicionais
4. Filtra e salva em `example.com_urls_filtradas.txt`

### Exemplo 6: Processar múltiplos subdomínios

```bash
paramstrike -f meus_subdomios.txt
```

### Exemplo 7: Atualizar a ferramenta

```bash
paramstrike -up
```

Automaticamente:
1. Faz `git pull` do repositório
2. Compila com `cargo build --release`
3. Incrementa a versão (1.0.0 → 1.1.0)
4. Salva a nova versão

### Exemplo 8: Ver versão atual e status

```bash
paramstrike -h
```

Mostra:
- Banner com versão
- Status de atualização (ATUALIZADA ou DESATUALIZADA)
- Menu de ajuda
```

---

## Extensões Filtradas

A ferramenta remove automaticamente URLs com as seguintes extensões de arquivo:

```
.md, .jpg, .jpeg, .gif, .css, .tif, .tiff, .png, .ttf, .woff, 
.woff2, .ico, .js, .json
```

Esta lista pode ser personalizada editando a seção de extensões no código.

---

## Estrutura do Projeto

```
ParamStrike/
├── Cargo.toml          # Configuração do projeto
├── src/
│   └── main.rs         # Código fonte principal
├── README.md           # Este arquivo
├── CONTRIBUTING.md     # Guia de contribuição
├── LICENSE             # Licença MIT
└── .gitignore         # Arquivos ignorados pelo Git
```

---

## Contribuir

Contribuições são bem-vindas! 🎉

Por favor, leia [CONTRIBUTING.md](CONTRIBUTING.md) para conhecer nosso processo de contribuição.

### Passos Rápidos:

1. **Fork** o repositório
2. **Clone** seu fork: `git clone https://github.com/seu-usuario/ParamStrike.git`
3. **Crie uma branch** para sua feature: `git checkout -b feature/minha-feature`
4. **Commit** suas mudanças: `git commit -am 'Add minha-feature'`
5. **Push** para a branch: `git push origin feature/minha-feature`
6. **Abra um Pull Request**

---

## Roadmap

- [ ] Suporte a mais ferramentas de reconhecimento web
- [ ] Interface com Burp Suite
- [ ] Exportação em múltiplos formatos (JSON, CSV, XML)
- [ ] Análise avançada de parâmetros
- [ ] Dashboard web opcional
- [ ] Testes automatizados

---

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## Créditos

**Desenvolvido por:** [0x13-ByteZer0](https://github.com/0x13-ByteZer0)

---

## Disclaimer

⚠️ **AVISO LEGAL:** Esta ferramenta é fornecida exclusivamente para fins educacionais e de pesquisa autorizada. Certifique-se sempre de ter permissão antes de testar a segurança de qualquer sistema. Use responsavelmente e dentro da lei.

---

## Suporte

Encontrou um bug ou tem uma sugestão? 
- 🐛 Abra uma [Issue](https://github.com/0x13-ByteZer0/ParamStrike/issues)
- 💬 Participe das [Discussões](https://github.com/0x13-ByteZer0/ParamStrike/discussions)

---

<div align="center">

**[⬆ Voltar ao Topo](#paramstrike)**

Feito com ❤️ por 0x13-ByteZer0

</div>