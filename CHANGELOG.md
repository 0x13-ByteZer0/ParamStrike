# Changelog

Todas as mudanÃ§as notÃ¡veis neste projeto serÃ£o documentadas neste arquivo.

O formato Ã© baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-03-10

### Added
- 🧪 Flag `-p/--explore` para exploração ativa básica (SQLi e XSS) sobre parâmetros
- 🤖 Flags `--ollama` e `--ollama-model` para validação local de achados com modelos leves (padrão `phi3:mini`)

### Changed
- 🔁 Atualização apenas sincroniza `.version` com `VERSION`, sem sobrescrever a versão do repositório
- 🪟 Verificação de status HTTP usa `NUL` no Windows (compatibilidade com `curl`)

### Fixed
- ✅ Removido incremento automático de versão que podia divergir do `VERSION` do repositório

---
## [1.1.0] - 2024-03-10

### Added
- âœ¨ Sistema de versionamento semÃ¢ntico com incremento automÃ¡tico
- ðŸ”„ Flag `-up/--update` para atualizar a ferramenta do Git e recompilar
- ðŸ“Š Flag `-status` para verificar status HTTP de URLs e categorizar por cÃ³digo
- ðŸ” Flag `-v/--verbose` para modo verbose com fluxo de processamento detalhado
- ðŸ“ Arquivos separados por status HTTP (2xx, 3xx, 4xx, 5xx)
- ðŸ” IntegraÃ§Ã£o com subfinder usando flag `-all` para reconhecimento mais completo
- âœ… VerificaÃ§Ã£o automÃ¡tica de versÃ£o ao executar a ferramenta
- ðŸ’¾ Arquivo `VERSION` como source of truth do versionamento
- ðŸŽ¨ Caixas de visualizaÃ§Ã£o formatadas para status de atualizaÃ§Ã£o
- ðŸ“ˆ Indicadores de progresso [1/2], [2/2] no processo de atualizaÃ§Ã£o

### Changed
- ðŸ”§ Sistema de versionamento agora usa arquivo `VERSION` e `.version` local
- ðŸ”„ VerificaÃ§Ã£o de atualizaÃ§Ãµes agora executa SEMPRE (independente da flag)
- ðŸ”§ Subfinder agora executa com `-all` para melhor cobertura de subdomÃ­nios

### Fixed
- âœ… Tratamento adequado de queries em URLs com caminhos
- âœ… DeduplicaÃ§Ã£o de URLs com anew antes de categorizar por status

---

## [1.0.0] - 2024-03-10

### Added
- âœ¨ VersÃ£o inicial do ParamStrike
- ðŸŽ¯ Modo padrÃ£o: filtro de URLs com extraÃ§Ã£o de parÃ¢metros
- ðŸ” Modo domÃ­nio Ãºnico: integraÃ§Ã£o com subfinder, katana e urlfinder
- ðŸ“‘ Modo batch: processamento de mÃºltiplos subdomÃ­nios
- ðŸ—‘ï¸ Limpeza automÃ¡tica de extensÃµes irrelevantes (30+ extensÃµes)
- ðŸŽ¨ Interface colorida com ANSI colors
- ðŸ“Š MÃºltiplos formatos de entrada/saÃ­da
- ðŸ’» Support para Linux, macOS e Windows
- ðŸ›¡ï¸ Tratamento de erros de encoding UTF-8

### Features
- ExtraÃ§Ã£o inteligente de parÃ¢metros de URL
- Filtro configurÃ¡vel de extensÃµes (imagens, docs, scripts, fontes, executÃ¡veis)
- Output colorido para melhor legibilidade
- Help integrado com exemplos
- Argumentos de linha de comando flexÃ­veis
- Processamento eficiente com BufReader/BufWriter

---

## Planejado para Futuras VersÃµes

### [1.2.0] - Planejado
- [ ] Suporte a exportaÃ§Ã£o JSON
- [ ] Suporte a exportaÃ§Ã£o CSV
- [ ] Filtros avanÃ§ados por tipo de parÃ¢metro
- [ ] Cache de resultados

### [1.3.0] - Planejado
- [ ] Interface com Burp Suite
- [ ] IntegraÃ§Ã£o com mais ferramentas de recon
- [ ] AnÃ¡lise de padrÃµes de parÃ¢metros
- [ ] DetecÃ§Ã£o de parÃ¢metros similares

### [2.0.0] - Futuro Distante
- [ ] Dashboard web
- [ ] API REST
- [ ] Sistema de plugins
- [ ] Machine Learning para anÃ¡lise

---

## Como Reportar MudanÃ§as

Para manter este changelog atualizado:

1. Cada revisÃ£o deve ter seu prÃ³prio rÃ³tulo (Added, Fixed, Changed, etc)
2. Ordem: Added, Changed, Deprecated, Removed, Fixed, Security
3. Use presente, terceira pessoa
4. Use emojis para melhor visualizaÃ§Ã£o

---

**Desenvolvido por:** [0x13-ByteZer0](https://github.com/0x13-ByteZer0)
