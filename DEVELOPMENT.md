# Desenvolvimento Local

Esta documentação ajuda você a configurar o ParamStrike localmente para desenvolvimento.

## Pré-requisitos

- [Rust 1.70+](https://www.rust-lang.org/tools/install)
- Git
- Um editor de texto ou IDE (VS Code recomendado com extensão Rust Analyzer)

## Setup Inicial

### 1. Clone o Repositório

```bash
git clone https://github.com/0x13-ByteZer0/ParamStrike.git
cd ParamStrike
```

### 2. Instale o Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Windows: Baixe em https://www.rust-lang.org/tools/install

### 3. Verifique a Instalação

```bash
rustc --version
cargo --version
```

## Desenvolvimento

### Build para Debug

```bash
cargo build
```

Executável em: `target/debug/paramstrike` (ou `.exe` no Windows)

### Build para Release

```bash
cargo build --release
```

Executável em: `target/release/paramstrike`

### Executar Testes

```bash
cargo test
```

### Verificar Qualidade do Código

```bash
# Formatação
cargo fmt

# Linting
cargo clippy

# Auditoria de segurança
cargo audit
```

### Documentação

```bash
cargo doc --open
```

## Estrutura do Projeto

```
src/
├── main.rs                          # Função main e organização principal
│   ├── mostrar_banner()             # Exibe logo e versão
│   ├── mostrar_help()               # Mostra menu de ajuda
│   ├── verificar_atualizacoes()     # Verifica versão vs local
│   ├── atualizar_ferramenta()       # Git pull + cargo build + increment version
│   ├── incrementar_versao()         # Incrementa versão semântica
│   ├── processar_argumentos()       # Parse das flags -l e -o
│   ├── processar_domain_unico()     # Integração com subfinder/katana/urlfinder
│   ├── processar_lista_dominios()   # Batch processing
│   ├── filtrar_urls()               # Core - filtra URLs com status HTTP opcional
│   ├── verificar_status_http()      # Verifica status HTTP com curl
│   ├── tem_extensao_remover()       # Filtra by extension
│   ├── tem_parametros()             # Valida presença de ?
│   ├── obter_nome_arquivo_status()  # Retorna nome do arquivo por status
│   ├── ler_versao_salva()           # Lê .version local
│   └── salvar_versao()              # Escreve .version local
```

## Funcionalidades Principais

### Sistema de Versionamento (v1.1.0+)

**Arquivos envolvidos:**
- `VERSION` - Source of truth (armazenado em Git)
- `.version` - Versão local do usuário (not in Git)
- `const VERSION` - Fallback na constante

**Fluxo:**
1. `verificar_atualizacoes()` lê ambos os arquivos
2. Se diferem, mostra aviso "DESATUALIZADO"
3. Usuário executa `paramstrike -up`
4. `atualizar_ferramenta()` executa:
   - `git pull` (atualiza source)
   - `cargo build --release` (recompila)
   - `incrementar_versao()` (1.0.0 → 1.1.0)
   - Salva em `.version` e `VERSION`

### Flag -v (Verbose)

**Ativa verbose mode mostrando:**
- Cada URL processada
- Por que URLs foram removidas (extensão/sem parâmetros)
- Progresso a cada 100 URLs
- Status HTTP de cada URL (se com `-status`)

### Flag -status (HTTP Status Checking)

**Verifica cada URL com curl e categoriza:**
- `2xx_sucessos.txt` - URLs com resposta OK
- `3xx_redirecionamentos.txt` - Redirecionados
- `4xx_erros_cliente.txt` - Not Found, Forbidden, etc
- `5xx_erros_servidor.txt` - Server errors
- `_sem_resposta.txt` - URLs que não responderam

**Usa curl com timeout 5s:**
```rust
curl -s -o /dev/null -w %{http_code} --max-time 5 <URL>
```

### Flag -up (Update)

**Processo automatizado de atualização:**
```
[1/2] Git pull...
  ✓ Git pull concluído
  
[2/2] Compilando...
  ✓ Compilação concluída
  
[✓] Versão incrementada: 1.0.0 → 1.1.0
✓ ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!
```

**Subfinder com -all:**
```bash
subfinder -d example.com -all  # Melhor cobertura
```

## Fluxo de Desenvolvimento

### Ao Adicionar uma Feature

1. Crie uma branch: `git checkout -b feature/sua-feature`
2. Faça as mudanças localmente
3. Teste: `cargo test && cargo clippy && cargo fmt`
4. Commit: `git commit -am 'Add: descrição da feature'`
5. Push: `git push origin feature/sua-feature`
6. Abra um PR

### Ao Corrigir um Bug

1. Crie uma branch: `git checkout -b fix/nome-do-bug`
2. Reproduza o bug com um teste
3. Corrija o código
4. Teste: `cargo test`
5. Commit: `git commit -am 'Fix: descrição da correção'`
6. Push e abra um PR

## Debugging

### Com println!

```rust
dbg!(variavel);  // Exibe nome e valor
println!("Debug: {:?}", variavel);  // Exibe debugando
```

### Com VS Code

Instale a extensão [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb):

```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "Launch ParamStrike",
            "cargo": {
                "args": [
                    "build",
                    "--bin=paramstrike",
                    "--package=paramstrike"
                ],
                "filter": {
                    "name": "paramstrike",
                    "kind": "bin"
                }
            },
            "args": ["-h"],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

## Performance

### Profile Release

```bash
cargo build --release
```

### Flamegraph

```bash
cargo install flamegraph
cargo flamegraph
```

## Troubleshooting

### Erro: "rustc not found"

```bash
# Linux/Mac
source $HOME/.cargo/env

# Windows: reinicie o terminal
```

### Erro ao compilar dependências

```bash
cargo clean
cargo build
```

### Teste falha

```bash
cargo test -- --nocapture
```

## Recursos Úteis

- 📖 [Rust Book](https://doc.rust-lang.org/book/)
- 🔗 [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- 📚 [Stdlib Docs](https://doc.rust-lang.org/std/)
- 🛠️ [Cargo Guide](https://doc.rust-lang.org/cargo/)

---

Pronto para começar? Execute `cargo run -- -h` e veja a mágica acontecer! ✨
