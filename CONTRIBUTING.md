# Guia de Contribuição

Obrigado por considerar contribuir para o **ParamStrike**! 🙌

Este documento oferece diretrizes e instruções para contribuir com o projeto.

## Código de Conduta

Todos os contribuidores devem:
- Ser respeitosos e inclusivos
- Aceitar críticas construtivas
- Focar no que é melhor para a comunidade
- Denunciar comportamentos abusivos

## Como Contribuir

### Reportar Bugs 🐛

Antes de criar um relatório de bug, verifique se o problema já não foi relatado. Se você encontrar um bug:

1. **Use um título descritivo** para a issue
2. **Descreva os passos exatos** para reproduzir o problema
3. **Forneça exemplos específicos** para demonstrar os passos
4. **Descreva o comportamento observado** e **o que você esperava ver**
5. **Inclua capturas de tela** se relevante
6. **Indique sua versão do Rust** e **sistema operacional**

**Exemplo de bug report:**
```
Título: Erro ao processar URLs com caracteres especiais

Passos para reproduzir:
1. Criar arquivo com URL: https://example.com/path?param=café&id=123
2. Executar: paramstrike -l urls.txt
3. Observar erro

Erro observado:
[✗] Erro ao processar o arquivo: caractere inválido

Comportamento esperado:
Arquivo de saída criado com a URL normalizada
```

### Sugerir Melhorias ✨

Sugestões de melhorias são sempre bem-vindas! Para sugerir algo:

1. **Use um título descritivo**
2. **Explique a motivação** - por que essa melhoria seria útil?
3. **Liste exemplos** de como ela funcionaria
4. **Mencione projetos similares** que implementam essa funcionalidade

**Exemplo de sugestão:**
```
Título: Adicionar suporte a exportação JSON

Motivação:
Muitos usuários importam os dados em ferramentas como Burp Suite ou 
ferramentas de análise de dados que trabalham melhor com JSON.

Exemplo de uso:
paramstrike -l urls.txt -o resultado.json -f json

Projetos similares:
- Subfinder suporta -json
- Katana suporta -jl
```

### Pull Requests 🔄

Seguir estas orientações facilita muito a revisão:

1. **Forkue** o repositório
2. **Crie uma branch** a partir de `main`:
   ```bash
   git checkout -b feature/sua-feature
   ```
   
3. **Faça suas mudanças** e **teste localmente**:
   ```bash
   cargo test
   cargo build --release
   ```

4. **Commit com mensagens claras**:
   ```bash
   git commit -am 'Add recurso X

   Descrição mais detalhada da mudança.
   - Melhoria 1
   - Melhoria 2'
   ```

5. **Push para sua branch**:
   ```bash
   git push origin feature/sua-feature
   ```

6. **Abra um Pull Request** descrevendo:
   - O que foi alterado
   - Por que foi alterado
   - Como testar as mudanças
   - Se fecha alguma issue (use `Closes #123`)

**Exemplo de PR:**
```
## Descrição
Add suporte a filtro por padrão regex para parâmetros.

## Tipo de Mudança
- [x] Bug fix (mudança que corrige um problema)
- [ ] Nova feature (mudança que adiciona funcionalidade)
- [ ] Breaking change (mudança que quebra compatibilidade)

## Como foi testado?
- Testado com URLs contendo parâmetros diversos
- Testado regex complexos
- Testado com arquivo de entrada vazio

## Checklist
- [x] Meu código segue o estilo do projeto
- [x] Testei a compilação: `cargo build --release`
- [x] Atualizei a documentação se necessário
- [x] Adicionei testes se apropriado

Closes #42
```

## Versionamento Semântico

ParamStrike usa [Semantic Versioning](https://semver.org) com incremento automático:

- **MAJOR.MINOR.PATCH** (e.g., 1.0.0)
- **MAJOR**: Mudanças incompatíveis com versões anteriores
- **MINOR**: Novas funcionalidades compatíveis
- **PATCH**: Correções de bugs

### Incremento Automático

Quando você executa `paramstrike -up`:
1. Faz `git pull` do repositório
2. Compila com `cargo build --release`
3. **Incrementa automaticamente MINOR** (1.0.0 → 1.1.0)
4. Atualiza `VERSION` e `.version`

### Ao Contribuir

- **Não altere manualmente** `VERSION` ou `.version`
- Essas mudanças são automatizadas pelo `-up`
- Seu PR não deve incluir mudanças de versão

**Mantis:**
- `VERSION` - Arquivo do repositório (versionamento oficial)
- `.version` - Arquivo local do usuário (cache local)
- `const VERSION` - Constante em main.rs (fallback)

### Atualizando CHANGELOG

Para cada novo PR que adicione features:
1. Atualize `CHANGELOG.md` com:
   - Qual versão (planejamos X.Y.Z)
   - Descrição da mudança
   - Categoria (Added, Changed, Fixed, etc)

```markdown
## [X.Y.Z] - Data

### Added
- ✨ Nova feature com emoji descriitivo

### Changed
- 🔄 Mudança em feature existente

### Fixed  
- ✅ Bug corrigido
```

## Padrões de Desenvolvimento

### Estilo de Código

- **Indentação:** 4 espaços
- **Nomes de variáveis:** snake_case para funções e variáveis
- **Nomes de constantes:** SCREAMING_SNAKE_CASE
- **Comentários:** Em português, claros e concisos
- **Módulos:** Organize o código logicamente

**Exemplo:**
```rust
// Bom ✓
fn processar_arquivo_entrada(caminho: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let arquivo = File::open(caminho)?;
    let leitor = BufReader::new(arquivo);
    // ...
}

// Ruim ✗
fn processarArquivo(p: &str) -> Result<Vec<String>, Box<dyn Error>> {
    // não fazer isto
}
```

### Mensagens de Commit

Use commits em português, descritivos:

- ✅ `Add suporte a exportação JSON`
- ✅ `Fix: corrigir parsing de URLs com parâmetros vazios`
- ✅ `Refactor: melhorar estrutura da função de leitura`
- ❌ `Alterações`
- ❌ `Fix stuff`
- ❌ `ASA`

### Branches

Use nomes descritivos:

- `feature/novo-recurso`
- `fix/corrigir-bug`
- `refactor/melhorar-performance`
- `docs/atualizar-readme`

## Configurações Recomendadas

### VS Code
```json
{
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer",
        "editor.formatOnSave": true,
        "editor.rulers": [100]
    }
}
```

### Desenvolvimento Local

```bash
# Instalar dependências
rustup update

# Formatar código
cargo fmt

# Verificar linting
cargo clippy

# Testar
cargo test

# Build de produção
cargo build --release
```

## Processo de Revisão

1. **Compilação:** Deve compilar sem erros ou warnings
2. **Testes:** Deve passar em todos os testes
3. **Documentação:** Mudanças devem ser documentadas
4. **Revisão de código:** Será revisado quanto a estilo e qualidade
5. **Aprovação:** Precisa de pelo menos uma aprovação
6. **Merge:** Será feito após aprovação

## Dúvidas?

- 📖 Leia a [documentação](README.md)
- 💬 Abra uma [discussão](https://github.com/0x13-ByteZer0/ParamStrike/discussions)
- 🐛 Verifique [issues abertas](https://github.com/0x13-ByteZer0/ParamStrike/issues)

---

Obrigado por contribuir para tornar ParamStrike melhor! ❤️

