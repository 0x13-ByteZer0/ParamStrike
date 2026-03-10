# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-03-10

### Added
- ✨ Sistema de versionamento semântico com incremento automático
- 🔄 Flag `-up/--update` para atualizar a ferramenta do Git e recompilar
- 📊 Flag `-status` para verificar status HTTP de URLs e categorizar por código
- 🔍 Flag `-v/--verbose` para modo verbose com fluxo de processamento detalhado
- 📁 Arquivos separados por status HTTP (2xx, 3xx, 4xx, 5xx)
- 🔍 Integração com subfinder usando flag `-all` para reconhecimento mais completo
- ✅ Verificação automática de versão ao executar a ferramenta
- 💾 Arquivo `VERSION` como source of truth do versionamento
- 🎨 Caixas de visualização formatadas para status de atualização
- 📈 Indicadores de progresso [1/2], [2/2] no processo de atualização

### Changed
- 🔧 Sistema de versionamento agora usa arquivo `VERSION` e `.version` local
- 🔄 Verificação de atualizações agora executa SEMPRE (independente da flag)
- 🔧 Subfinder agora executa com `-all` para melhor cobertura de subdomínios

### Fixed
- ✅ Tratamento adequado de queries em URLs com caminhos
- ✅ Deduplicação de URLs com anew antes de categorizar por status

---

## [1.0.0] - 2024-03-10

### Added
- ✨ Versão inicial do ParamStrike
- 🎯 Modo padrão: filtro de URLs com extração de parâmetros
- 🔍 Modo domínio único: integração com subfinder, katana e urlfinder
- 📑 Modo batch: processamento de múltiplos subdomínios
- 🗑️ Limpeza automática de extensões irrelevantes (30+ extensões)
- 🎨 Interface colorida com ANSI colors
- 📊 Múltiplos formatos de entrada/saída
- 💻 Support para Linux, macOS e Windows
- 🛡️ Tratamento de erros de encoding UTF-8

### Features
- Extração inteligente de parâmetros de URL
- Filtro configurável de extensões (imagens, docs, scripts, fontes, executáveis)
- Output colorido para melhor legibilidade
- Help integrado com exemplos
- Argumentos de linha de comando flexíveis
- Processamento eficiente com BufReader/BufWriter

---

## Planejado para Futuras Versões

### [1.2.0] - Planejado
- [ ] Suporte a exportação JSON
- [ ] Suporte a exportação CSV
- [ ] Filtros avançados por tipo de parâmetro
- [ ] Cache de resultados

### [1.3.0] - Planejado
- [ ] Interface com Burp Suite
- [ ] Integração com mais ferramentas de recon
- [ ] Análise de padrões de parâmetros
- [ ] Detecção de parâmetros similares

### [2.0.0] - Futuro Distante
- [ ] Dashboard web
- [ ] API REST
- [ ] Sistema de plugins
- [ ] Machine Learning para análise

---

## Como Reportar Mudanças

Para manter este changelog atualizado:

1. Cada revisão deve ter seu próprio rótulo (Added, Fixed, Changed, etc)
2. Ordem: Added, Changed, Deprecated, Removed, Fixed, Security
3. Use presente, terceira pessoa
4. Use emojis para melhor visualização

---

**Desenvolvido por:** [0x13-ByteZer0](https://github.com/0x13-ByteZer0)
