# FAQ

### O que preciso para validar com LLM?
Um servidor OpenAI-compatible (llama-server/llama_cpp.server). Use `--unsloth` para habilitar e `--unsloth-bootstrap` para subir tudo localmente.

### Recebi 401 ao baixar o modelo no bootstrap.
Alguns modelos do HuggingFace exigem token. Defina `HF_TOKEN=<token>` ou use `--hf-token <token>` junto com `--unsloth-bootstrap`.

### Posso usar outro modelo?
Sim. Passe `--unsloth-model <alias>` e garanta que o modelo esteja carregado no servidor (`/v1/models` precisa listá-lo).

### Não tenho o binário `anew`.
O ParamStrike faz fallback e grava deduplicando em Rust. O `anew` é preferível pela performance, mas não é obrigatório.

### Quais vulnerabilidades são testadas?
SQLi (erros típicos), XSS refletido (marcadores codificados e bruto), IDOR com deltas numéricos (+/-1, +/-2).

### Por que preciso do Python?
Somente para o bootstrap do LLM em Linux/macOS (usa `python -m llama_cpp.server`). Em Windows, o bootstrap baixa `llama-server.exe`.

### Como gero CSV dos achados?
Adicione `--report-prefix relatorio` (gera `relatorio_achados.csv` e `relatorio_falhas.csv`).

### Pinchtab é obrigatório?
Não. Só é usado se você passar `--pinchtab-start`/`--pinchtab-scope`/`--pinchtab-scope-file`. Caso contrário, o fluxo ignora.

### Posso rodar sem rede?
Sim, mas o bootstrap LLM não conseguirá baixar o modelo e o checker de updates mostrará aviso. A exploração ativa funciona apenas nas URLs acessíveis.
