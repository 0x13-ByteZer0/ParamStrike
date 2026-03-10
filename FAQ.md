# FAQ - Perguntas Frequentes

## Instalação & Setup

### P: Como instalar o ParamStrike?
**R:** Clone o repositório e compile com Rust:
```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
cargo build --release
```

### P: Funciona no Windows?
**R:** Sim! ParamStrike funciona em Windows, macOS e Linux. Use `.exe` no Windows.

### P: Preciso de dependências externas?
**R:** Não, o ParamStrike é compilado com zero dependências externas.

## Uso

### P: Qual é a diferença entre os modos?
**R:**
- **Modo -l**: Filtra URLs de um arquivo de entrada
- **Modo -d**: Executa recon em um domínio único
- **Modo -f**: Processa múltiplos subdomínios

### P: Como faço para não remover certas extensões?
**R:** Edite a constante `EXTENSOES_REMOVER` no `src/main.rs` e recompile.

### P: Posso usar com outputs de outras ferramentas?
**R:** Sim! Qualquer arquivo com uma URL por linha funciona.

## Performance & Troubleshooting

### P: Por que lentidão ao processar arquivos grandes?
**R:** Use a versão Release: `cargo build --release` (muito mais rápida).

### P: Como vejo output em tempo real?
**R:** Use Unix pipes: `cat urls.txt | paramstrike -l /dev/stdin -o resultado.txt`

### P: Não consigo compilar - "cannot find...
**R:** Execute:
```bash
rustup update
cargo clean
cargo build --release
```

## Segurança & Legal

### P: É seguro usar em penetration testing legítimo?
**R:** Sim, use apenas em sistemas que você tem permissão para testar.

### P: Posso usar para fins comerciais?
**R:** Sim! A licença MIT permite uso comercial.

### P: Como reporto uma vulnerabilidade?
**R:** Leia [SECURITY.md](SECURITY.md) para política de divulgação responsável.

## Features & Desenvolvimento

### P: Como sugiro uma feature?
**R:** Abra uma [Issue](https://github.com/0x13-ByteZer0/ParamStrike/issues) com o label `enhancement`.

### P: Como reporto um bug?
**R:** Use o template de [bug report](.github/ISSUE_TEMPLATE/bug_report.md).

### P: Como contribuo com código?
**R:** Leia [CONTRIBUTING.md](CONTRIBUTING.md) para o guia completo.

### P: Qual é o status do projeto?
**R:** ParamStrike está em desenvolvimento ativo! Veja [CHANGELOG.md](CHANGELOG.md) para updates.

## Integração com Outras Ferramentas

### P: Como integro com Burp Suite?
**R:** Exporte URLs do Burp em um arquivo `.txt` e processe com ParamStrike.

### P: Funciona com Nuclei/Subfinder/Katana?
**R:** Sim! ParamStrike é compatível com outputs dessas ferramentas.

## Exemplos do Mundo Real

### P: Como extrair parâmetros de um escaneamento Burp?
```bash
# 1. Exporte sitemap do Burp como .txt
# 2. Execute:
paramstrike -l burp_urls.txt -o parametros.txt
```

### P: Como combinar saída de múltiplas ferramentas?
```bash
# Combine outputs
cat subfinder_output.txt >> urls.txt
cat katana_output.txt >> urls.txt

# Processe
paramstrike -l urls.txt -o resultado.txt
```

---

Não encontrou sua pergunta? [Abra uma Discussion](https://github.com/0x13-ByteZer0/ParamStrike/discussions)!
