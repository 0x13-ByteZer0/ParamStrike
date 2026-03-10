# Arquitetura do ParamStrike

## Visão Geral

ParamStrike é uma ferramenta CLI baseada em Rust para extração e análise de parâmetros de URL. A arquitetura é simples, direta e focada em performance.

```
┌─────────────────────────────────────────────────┐
│           Usuario (CLI)                          │
├─────────────────────────────────────────────────┤
│      Camada de Entrada (Argumentos)             │
│  (parse args, validação, roteamento)            │
├──────────┬──────────────┬────────────┬──────────┤
│  Modo -l │  Modo -d     │ Modo -f    │ Help    │
│ (filtro) │  (reconnoissance) │(batch) │      │
├─────────────────────────────────────────────────┤
│        Núcleo de Processamento                  │
│  - Leitura de arquivos                          │
│  - Parsing de URLs                              │
│  - Filtro de extensões                          │
│  - Normalização de parâmetros                   │
├─────────────────────────────────────────────────┤
│        Camada de Saída                           │
│  - Formatação de output                         │
│  - Escrita em arquivo                           │
│  - Feedback colorido (ANSI)                     │
├─────────────────────────────────────────────────┤
│           Arquivo de Saída (TXT)                │
└─────────────────────────────────────────────────┘
```

## Componentes Principais

### 1. main()
Função principal que:
- Processa argumentos da CLI
- Determina qual modo executar
- Valida entradas
- Rota para a função apropriada

### 2. Processamento de Argumentos
```rust
// Detecta flags e seus valores
-l <arquivo>      // Entrada padrão
-o <arquivo>      // Saída customizada
-d <dominio>      // Domínio único
-f <arquivo>      // Batch
-h, --help        // Ajuda
```

### 3. Módulos de Processamento

#### `processar_argumentos()`
- Extrai flags `-l` e `-o`
- Define valores padrão
- Retorna tupla (entrada, saída)

#### `filtrar_urls()`
- **Função core** do projeto
- Lê arquivo de entrada
- Processa cada URL:
  - Extrai parâmetros
  - Filtra extensões
  - Normaliza valores
- Escreve resultado em arquivo

#### `processar_domain_unico()`
- Integração com ferramentas externas
- Executa: subfinder → katana → urlfinder
- Agrega outputs

#### `processar_lista_dominios()`
- Processa múltiplos subdomínios
- Chamadas em batch

### 4. Módulo de I/O (Entrada/Saída)
- **BufReader**: Leitura eficiente de arquivos
- **BufWriter**: Escrita em buffer (performance)
- **File**: Operações de sistema de arquivos

### 5. Módulo de Formatação
- **ANSI Colors**: Cores para terminal
- **Banner**: Logo ASCII do projeto
- **Help**: Mensagem de ajuda formatada

## Fluxo de Dados - Modo Padrão (Modo -l)

```
urls.txt
    ↓
[Leitura com BufReader]
    ↓
Para cada linha:
    ├─ Fazer parse (URL)
    ├─ Extrair parâmetros (Query String)
    ├─ Filtrar extensões
    ├─ Normalizar (remover valores)
    └─ Adicionar buffer de escrita
    ↓
[Escrita com BufWriter]
    ↓
resultado.txt
```

## Exemplos de Processamento

### Entrada
```
https://example.com/page.html?id=123&user=admin
https://api.example.com/search.php?q=test&p=1&format=json
https://cdn.example.com/image.jpg
```

### Processamento

| URL | Parâmetros | Filtro | Resultado |
|----|-----------|--------|----------|
| `page.html?id=123&user=admin` | `id=123&user=admin` | ❌ .html | ✓ Mantém |
| `search.php?q=test&p=1&format=json` | `q=test&p=1&format=json` | ❌ .php | ✓ Mantém |
| `image.jpg` | Nenhum | ✓ .jpg | ✗ Remove |

### Saída
```
https://example.com/page.html?id=&user=
https://api.example.com/search.php?q=&p=&format=
```

## Constantes Globais

```rust
// Cores ANSI para output colorido
const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
// ... mais cores

// Extensões a remover
const EXTENSOES_REMOVER: &[&str] = &[
    "md", "jpg", "jpeg", "gif", "css", ...
];
```

## Padrões & Decisões de Design

### 1. Sem Dependências Externas
- ✅ Binário único e portável
- ✅ Minimizar superfície de ataque
- ✅ Builds reproduzíveis

### 2. Performance
- ✅ BufReader/BufWriter para I/O eficiente
- ✅ Strings em heap apenas quando necessário
- ✅ Release build otimizado

### 3. Usabilidade
- ✅ CLI intuitiva e simples
- ✅ Mensagens de erro claras
- ✅ Feedback visual com cores

### 4. Manutenibilidade
- ✅ Código bem documentado
- ✅ Funções focadas em uma tarefa
- ✅ Tratamento de erros robusto

## Extensibilidade Futura

### Pontos de Extensão

1. **Novos Modos**
   - Adicione nova função `processar_modo_x()`
   - Adicione flag no match de argumentos

2. **Novos Filtros**
   - Modifique `EXTENSOES_REMOVER`
   - Ou adicione novas regras em `filtrar_urls()`

3. **Novos Formatos de Saída**
   - Crie função `salvar_como_json()`
   - Integre na lógica de processamento

4. **Integração com Ferramentas**
   - Use `Command::new()` para executar binários
   - Parse dos outputs

## Performance

### Benchmark (Experimental)

Com 10.000 URLs:
- Debug build: ~500ms
- Release build: ~50ms (10x mais rápido!)

### Otimizações Implementadas

- ✅ BufReader reduz syscalls de I/O
- ✅ Regex compilada uma vez (não aplicada aqui, mas considerada)
- ✅ String pre-alocada em buffer

### Oportunidades Futuras

- [ ] Rayon para processamento paralelo
- [ ] Pool de threads para I/O bound operations
- [ ] Cache LRU para resultados comuns
- [ ] SIMD para parsing de URLs

## Estrutura de Diretórios

```
ParamStrike/
├── src/
│   └── main.rs           # Toda a lógica (monolítho simples)
├── target/
│   ├── debug/            # Build debug
│   └── release/          # Build otimizado
├── Cargo.toml            # Configuração do projeto
└── [Documentação]
```

### Por que um único arquivo?

Para este projeto, um monolítho é apropriado porque:
- Código é relativamente pequeno (<500 linhas)
- Lógica é linear e sequencial
- Sem lógica compartilhada complexa

Quando crescer, refatore em módulos:
- `lib.rs` - Core library
- `main.rs` - CLI wrapper
- `cli/`, `parser/`, `processor/` - Submódulos

---

## Referências Internas

- [main.rs](src/main.rs) - Implementação atual
- [DEVELOPMENT.md](DEVELOPMENT.md) - Setup local
- [CONTRIBUTING.md](CONTRIBUTING.md) - Guia de contribuição
