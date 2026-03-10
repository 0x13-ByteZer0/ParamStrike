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

Executável em: `target/debug/filter_master` (ou `.exe` no Windows)

### Build para Release

```bash
cargo build --release
```

Executável em: `target/release/filter_master`

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
├── main.rs              # Função main e organização principal
│   ├── mostrar_banner() # Exibe logo
│   ├── mostrar_help()   # Mostra ajuda
│   ├── processar_argumentos()
│   ├── processar_domain_unico()
│   ├── processar_lista_dominios()
│   └── filtrar_urls()   # Core da ferramenta
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
                    "--bin=filter_master",
                    "--package=filter_master"
                ],
                "filter": {
                    "name": "filter_master",
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
