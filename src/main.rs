use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use reqwest::blocking::Client;
use serde_json::Value;
use rayon::prelude::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use indicatif::{ProgressBar, ProgressStyle};

// ─── Versionamento ────────────────────────────────────────────────────────────
// CORREÇÃO #14: usar CARGO_PKG_VERSION como fonte única da verdade.
// Basta atualizar a versão em Cargo.toml; esta constante é preenchida em
// tempo de compilação pelo compilador Rust, eliminando a divergência entre
// a constante codificada e o arquivo VERSION.
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Cores ANSI ───────────────────────────────────────────────────────────────
const RED:     &str = "\x1b[91m";
const GREEN:   &str = "\x1b[92m";
const YELLOW:  &str = "\x1b[93m";
const BLUE:    &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN:    &str = "\x1b[96m";
const RESET:   &str = "\x1b[0m";
const BOLD:    &str = "\x1b[1m";

// ─── Configuração Ollama ──────────────────────────────────────────────────────
const OLLAMA_MODEL_DEFAULT: &str = "phi3:mini";

// CORREÇÃO #12: constante nomeada para o limite de preview do corpo da resposta.
const MAX_CHARS_PREVIEW_CORPO: usize = 8_000;

// ─── Payloads e padrões ───────────────────────────────────────────────────────
const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1\"--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(5)--",
];

const SQLI_PADROES_ERRO: &[&str] = &[
    "sql syntax",
    "mysql",
    "sqlstate",
    "postgresql",
    "sqlite",
    "oracle",
    "ora-",
    "unterminated string",
    "unexpected end of",
];

const XSS_PAYLOADS: &[&str] = &[
    r#"<script>alert(1337)</script>"#,
    r#""><svg/onload=alert(1337)>"#,
];

// Marcadores que indicam reflexo do XSS independentemente de encoding.
// CORREÇÃO #3: checamos tanto o payload cru quanto formas HTML-encoded comuns,
// evitando falsos negativos por encoding e falsos positivos por ocorrências
// em comentários.
const XSS_MARCADORES: &[&str] = &[
    "alert(1337)",
    "alert&#40;1337&#41;",
    "%3Cscript%3Ealert",
];

const IDOR_DELTAS: &[i64] = &[1, -1, 2, -2];

// CORREÇÃO #4: limiar de diferença de tamanho elevado para reduzir falsos positivos.
// 500 bytes é um valor mais conservador que filtra ruído (timestamps, tokens CSRF, ads).
const IDOR_DIFF_MINIMA: usize = 500;

// ─── Limite de seeds do Pinchtab ──────────────────────────────────────────────
// CORREÇÃO #7: constante visível e documentada. O aviso de truncamento será
// exibido independentemente do modo verbose.
const MAX_PINCHTAB_SEEDS: usize = 50;

fn main() {
    let args: Vec<String> = env::args().collect();

    mostrar_banner();
    verificar_atualizacoes();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        mostrar_help();
        return;
    }

    if args.contains(&"-up".to_string()) || args.contains(&"--update".to_string()) {
        atualizar_ferramenta();
        return;
    }

    let verbose      = args.contains(&"-v".to_string()) || args.contains(&"--verbose".to_string());
    let check_status = args.contains(&"-status".to_string()) || args.contains(&"--status".to_string());
    let usar_ollama  = args.contains(&"--ollama".to_string());
    let explorar     = args.contains(&"-p".to_string()) || args.contains(&"--explore".to_string()) || usar_ollama;

    let modelo_ollama = args
        .windows(2)
        .find(|w| w[0] == "--ollama-model")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| OLLAMA_MODEL_DEFAULT.to_string());

    let report_prefix = args
        .windows(2)
        .find(|w| w[0] == "--report-prefix")
        .map(|w| w[1].clone());

    let pinchtab_start = args
        .windows(2)
        .find(|w| w[0] == "--pinchtab-start")
        .map(|w| w[1].clone());

    let pinchtab_host = args
        .windows(2)
        .find(|w| w[0] == "--pinchtab-host")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "http://localhost:9867".to_string());

    let pinchtab_scope = args
        .windows(2)
        .find(|w| w[0] == "--pinchtab-scope")
        .map(|w| w[1].clone());

    let pinchtab_scope_file = args
        .windows(2)
        .find(|w| w[0] == "--pinchtab-scope-file")
        .map(|w| w[1].clone());

    let mut pinchtab_seeds = Vec::new();
    if let Some(s) = pinchtab_start.clone() {
        pinchtab_seeds.push(s);
    }

    let mut pinchtab_scopes = Vec::new();
    if let Some(ref s) = pinchtab_scope {
        pinchtab_scopes.push(s.clone());
    }
    if let Some(ref scope_path) = pinchtab_scope_file {
        if let Ok(file) = File::open(scope_path) {
            for line in BufReader::new(file).lines().flatten() {
                let d = line.trim().to_string();
                if !d.is_empty() { pinchtab_scopes.push(d); }
            }
        }
    }

    let pinchtab_enabled = pinchtab_start.is_some() || pinchtab_scope.is_some() || pinchtab_scope_file.is_some();
    let pinchtab_cfg = if pinchtab_enabled {
        Some(PinchTabConfig { host: pinchtab_host, seeds: pinchtab_seeds, scopes: pinchtab_scopes })
    } else {
        None
    };

    if let Some(pos) = args.iter().position(|x| x == "-d") {
        if pos + 1 < args.len() {
            processar_domain_unico(&args[pos + 1], pinchtab_cfg);
        } else {
            eprintln!("{}[✗] Erro: Domínio não especificado após a flag -d.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }

    if let Some(pos) = args.iter().position(|x| x == "-f") {
        if pos + 1 < args.len() {
            processar_lista_dominios(&args[pos + 1], pinchtab_cfg);
        } else {
            eprintln!("{}[✗] Erro: Arquivo com lista de subdomínios não especificado após a flag -f.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }

    let (arquivo_entrada, arquivo_saida) = processar_argumentos();

    if let Err(e) = filtrar_urls(
        &arquivo_entrada, &arquivo_saida,
        verbose, check_status, explorar,
        usar_ollama, &modelo_ollama,
        report_prefix, pinchtab_cfg,
    ) {
        eprintln!("{}[✗] Erro ao processar o arquivo: {}{}", RED, e, RESET);
        process::exit(1);
    }
}

// ─── Extensões removidas ──────────────────────────────────────────────────────
const EXTENSOES_REMOVER: &[&str] = &[
    "jpg","jpeg","gif","png","tif","tiff","bmp","svg","ico","webp",
    "pdf","doc","docx","xls","xlsx","ppt","pptx","txt","md","zip","rar","7z",
    "css","js","json","xml","yaml","yml",
    "ttf","woff","woff2","eot","otf","font",
    "mp3","mp4","avi","mov","flv","wav","m4a",
    "exe","dll","so","dylib",
    "map",
];

// ─── Banner ───────────────────────────────────────────────────────────────────
fn mostrar_banner() {
    println!("{}", RED);
    println!("{} ______    ______     ______     ______     __    __     ______     ______   ______     __     __  __     ______{}", RED, RESET);
    println!("{}/\\  == \\  /\\  __ \\   /\\  == \\   /\\  __ \\   /\\ \"-./  \\   /\\  ___\\   /\\__  _\\ /\\  == \\   /\\ \\   /\\ \\/ /    /\\  ___\\{}", RED, RESET);
    println!("{}\\ \\  _-/  \\ \\  __ \\  \\ \\  __<   \\ \\  __ \\  \\ \\ \\-./\\ \\  \\ \\___  \\  \\/_/\\ \\/ \\ \\  __<   \\ \\ \\  \\ \\  _\"-. \\ \\  __\\{}", RED, RESET);
    println!("{} \\ \\_\\     \\ \\_\\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\ \\ \\_\\  \\/\\_____\\    \\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\  \\ \\_\\ \\_\\  \\ \\_____\\{}", RED, RESET);
    println!("{}  \\/_/      \\/_/\\/_/   \\/_/ /_/   \\/_/\\/_/   \\/_/  \\/_/   \\/_____/     \\/_/   \\/_/ /_/   \\/_/   \\/_/\\/_/   \\/_____/{}", RED, RESET);
    println!();
    println!("{}                    v{} - URL Parameter Extractor & Web Reconnaissance{}", BOLD, VERSION, RESET);
    println!();
    println!("{}════════════════════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!("{}             ✔ Developed by: 0x13-ByteZer0{}", GREEN, RESET);
    println!("{}════════════════════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!();
}

// ─── Help ─────────────────────────────────────────────────────────────────────
fn mostrar_help() {
    println!("{}Uso:{} paramstrike [OPÇÃO] [ARGUMENTOS]\n", BOLD, RESET);
    println!("{}Opções:{}", BOLD, RESET);
    println!("  {}  -l <arquivo>{}            Arquivo de entrada com URLs (obrigatório para modo padrão)", YELLOW, RESET);
    println!("  {}  -o <arquivo>{}            Arquivo de saída (padrão: urls_parametros.txt)", YELLOW, RESET);
    println!("  {}  -d <domain>{}             Domínio único - executar subfinder, katana e urlfinder", CYAN, RESET);
    println!("  {}  -f <arquivo>{}            Arquivo com lista de subdomínios para crawler", CYAN, RESET);
    println!("  {}  -v, --verbose{}           Modo verbose (mostra fluxo de processamento)", MAGENTA, RESET);
    println!("  {}  -status{}                 Verificar status HTTP e salvar em arquivos separados", MAGENTA, RESET);
    println!("  {}  -p, --explore{}           Explorar ativamente os parâmetros (SQLi/XSS/IDOR)", MAGENTA, RESET);
    println!("  {}  --ollama{}                Validar achados com Ollama (desliga falsos positivos)", MAGENTA, RESET);
    println!("  {}  --ollama-model <m>{}      Modelo Ollama (padrão: {})", MAGENTA, RESET, OLLAMA_MODEL_DEFAULT);
    println!("  {}  --report-prefix <p>{}     Salvar achados em CSV (ex.: relatorio)", MAGENTA, RESET);
    println!("  {}  --pinchtab-start <url>{}  Usar pinchtab para abrir URL no Firefox/Chrome e extrair links", MAGENTA, RESET);
    println!("  {}  --pinchtab-host <host>{}  Host do serviço pinchtab (padrão: http://localhost:9867)", MAGENTA, RESET);
    println!("  {}  --pinchtab-scope <dom>{}  Restringe seeds do pinchtab ao domínio", MAGENTA, RESET);
    println!("  {}  --pinchtab-scope-file <arq>{} Lista de domínios permitidos (um por linha)", MAGENTA, RESET);
    println!("  {}  -up, --update{}           Atualizar a ferramenta do Git e recompilar", MAGENTA, RESET);
    println!("  {}  -h, --help{}              Mostra esta mensagem de ajuda\n", YELLOW, RESET);
    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}$ paramstrike -l urls.txt -o resultado.txt{}", GREEN, RESET);
    println!("  {}$ paramstrike -l urls.txt -o resultado.txt -p{}", GREEN, RESET);
    println!("  {}$ paramstrike -l urls.txt -o resultado.txt -p --ollama --ollama-model {}{}", GREEN, OLLAMA_MODEL_DEFAULT, RESET);
    println!("  {}$ paramstrike -l urls.txt -o resultado.txt -p --report-prefix relatorio{}", GREEN, RESET);
    println!("  {}$ paramstrike -d example.com{}", GREEN, RESET);
    println!("  {}$ paramstrike -f subs.txt{}\n", GREEN, RESET);
}

// ─── Verificação de atualizações ──────────────────────────────────────────────
// CORREÇÃO #1: A lógica anterior comparava dois arquivos locais (VERSION vs .version),
// o que não detecta atualizações reais do repositório remoto. A nova lógica consulta
// a API de releases do GitHub para obter a versão mais recente publicada e compara
// com VERSION (preenchida em tempo de compilação via CARGO_PKG_VERSION).
// Se a consulta falhar (sem rede, rate limit, etc.), exibe aviso não-bloqueante.
fn verificar_atualizacoes() {
    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(_) => {
            println!("{}[!] Não foi possível criar cliente HTTP para verificar atualizações.{}", YELLOW, RESET);
            return;
        }
    };

    // Substitua pelo repositório real do projeto se necessário.
    let url = "https://api.github.com/repos/0x13-ByteZer0/paramstrike/releases/latest";

    match client
        .get(url)
        .header("User-Agent", format!("paramstrike/{}", VERSION))
        .send()
        .and_then(|r| r.json::<Value>())
    {
        Ok(json) => {
            if let Some(tag) = json.get("tag_name").and_then(|v| v.as_str()) {
                // Remove prefixo "v" se presente (ex.: "v1.0.1" -> "1.0.1")
                let versao_remota = tag.trim_start_matches('v');
                if versao_remota != VERSION {
                    println!("{}╔══════════════════════════════════════════════════════════════╗{}", YELLOW, RESET);
                    println!("{}║  ⚠  ATUALIZAÇÃO DISPONÍVEL!                                  ║{}", YELLOW, RESET);
                    println!("{}║  Instalada: {:10}  |  Nova: {:10}                  ║{}", YELLOW, VERSION, versao_remota, RESET);
                    println!("{}║  Execute:  $ paramstrike -up                                  ║{}", YELLOW, RESET);
                    println!("{}╚══════════════════════════════════════════════════════════════╝{}", YELLOW, RESET);
                } else {
                    println!("{}╔══════════════════════════════════════════════════════════════╗{}", GREEN, RESET);
                    println!("{}║  ✔  FERRAMENTA ATUALIZADA  │  Versão: {:10}            ║{}", GREEN, VERSION, RESET);
                    println!("{}╚══════════════════════════════════════════════════════════════╝{}", GREEN, RESET);
                }
            } else {
                println!("{}[!] Não foi possível determinar a versão remota (resposta inesperada).{}", YELLOW, RESET);
            }
        }
        Err(_) => {
            // Falha silenciosa: sem acesso à internet não deve impedir o uso da ferramenta.
            println!("{}[!] Sem acesso à internet — verificação de atualização pulada. Versão local: {}{}", YELLOW, VERSION, RESET);
        }
    }
    println!();
}

// ─── Helpers de filtragem ─────────────────────────────────────────────────────
fn tem_extensao_remover(url: &str) -> bool {
    let path = url.trim().to_lowercase();
    let path = path.split('?').next().unwrap_or(&path);
    EXTENSOES_REMOVER.iter().any(|ext| path.ends_with(&format!(".{}", ext)))
}

fn tem_parametros(url: &str) -> bool {
    url.contains('?')
}

// ─── Verificação de status HTTP ───────────────────────────────────────────────
// CORREÇÃO #6: usa reqwest em vez de spawnar um processo filho `curl`.
// Isso elimina a dependência de runtime no curl estar no PATH e reduz
// bastante o overhead por requisição.
fn verificar_status_http(client: &Client, url: &str) -> Option<u16> {
    client
        .get(url)
        .send()
        .ok()
        .map(|r| r.status().as_u16())
}

// ─── Atualização da ferramenta ────────────────────────────────────────────────
// CORREÇÃO #9: detecta o diretório do binário e faz o git pull/cargo build
// a partir dele, em vez de assumir que o CWD é a raiz do repositório.
fn atualizar_ferramenta() {
    println!("{}╔══════════════════════════════════════════════════════════════╗{}", BLUE, RESET);
    println!("{}║           INICIANDO PROCESSO DE ATUALIZAÇÃO                  ║{}", BLUE, RESET);
    println!("{}╚══════════════════════════════════════════════════════════════╝{}", BLUE, RESET);
    println!();

    // Tenta determinar o diretório-fonte a partir da localização do binário.
    let bin_dir = env::current_exe()
        .ok()
        .and_then(|p| {
            // Binários compilados ficam em <projeto>/target/release/paramstrike.
            // Subindo três níveis chegamos à raiz do projeto.
            p.ancestors().nth(3).map(|a| a.to_path_buf())
        });

    let dir_arg: Option<PathBuf> = bin_dir.filter(|d| d.join("Cargo.toml").exists());

    if dir_arg.is_none() {
        eprintln!(
            "{}[!] Não foi possível localizar a raiz do projeto automaticamente.\n\
             Execute este comando a partir do diretório raiz do repositório.{}",
            YELLOW, RESET
        );
    }

    let mut git_cmd = Command::new("git");
    git_cmd.arg("pull");
    if let Some(ref dir) = dir_arg {
        git_cmd.current_dir(dir);
    }

    println!("{}[1/2] Realizando git pull...{}", CYAN, RESET);
    match git_cmd.output() {
        Ok(output) if output.status.success() => {
            println!("{}✔ Git pull concluído com sucesso!{}", GREEN, RESET);
            let msg = String::from_utf8_lossy(&output.stdout);
            if !msg.trim().is_empty() { println!("{}{}{}", CYAN, msg, RESET); }
        }
        Ok(output) => {
            eprintln!("{}✗ Erro ao executar git pull:{}", RED, RESET);
            eprintln!("{}{}{}", YELLOW, String::from_utf8_lossy(&output.stderr), RESET);
            process::exit(1);
        }
        Err(e) => {
            eprintln!("{}✗ Erro ao executar git: {}{}", RED, e, RESET);
            process::exit(1);
        }
    }

    println!();
    println!("{}[2/2] Compilando com cargo...{}", CYAN, RESET);

    let mut cargo_cmd = Command::new("cargo");
    cargo_cmd.arg("build").arg("--release");
    if let Some(ref dir) = dir_arg {
        cargo_cmd.current_dir(dir);
    }

    match cargo_cmd.output() {
        Ok(output) if output.status.success() => {
            println!("{}✔ Compilação concluída com sucesso!{}", GREEN, RESET);
            println!();
            println!("{}╔══════════════════════════════════════════════════════════════╗{}", BLUE, RESET);
            println!("{}║  ✔  ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!                       ║{}", BLUE, RESET);
            println!("{}║     → Status: RECOMPILADO                                    ║{}", BLUE, RESET);
            println!("{}╚══════════════════════════════════════════════════════════════╝{}", BLUE, RESET);
        }
        Ok(output) => {
            eprintln!("{}[✗] Erro ao compilar:{}", RED, RESET);
            eprintln!("{}{}{}", YELLOW, String::from_utf8_lossy(&output.stderr), RESET);
            process::exit(1);
        }
        Err(e) => {
            eprintln!("{}[✗] Erro ao executar cargo: {}{}", RED, e, RESET);
            eprintln!("{}Certifique-se de que Rust está instalado e no PATH.{}", YELLOW, RESET);
            process::exit(1);
        }
    }
}

// ─── Arquivo de saída por status code ────────────────────────────────────────
fn obter_nome_arquivo_status(status: u16, arquivo_base: &str) -> String {
    let categoria = match status {
        200..=299 => "2xx_sucessos",
        300..=399 => "3xx_redirecionamentos",
        400..=499 => "4xx_erros_cliente",
        500..=599 => "5xx_erros_servidor",
        _         => "desconhecido",
    };
    let sem_ext = arquivo_base.strip_suffix(".txt").unwrap_or(arquivo_base);
    format!("{}_{}.txt", sem_ext, categoria)
}

// ─── Filtro principal de URLs ─────────────────────────────────────────────────
fn filtrar_urls(
    arquivo_entrada: &str,
    arquivo_saida: &str,
    verbose: bool,
    check_status: bool,
    explorar: bool,
    usar_ollama: bool,
    modelo_ollama: &str,
    report_prefix: Option<String>,
    pinchtab_cfg: Option<PinchTabConfig>,
) -> std::io::Result<()> {
    // CORREÇÃO #8: valida a existência do arquivo antes de abrir.
    let entrada_path = PathBuf::from(arquivo_entrada);
    if !entrada_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Arquivo de entrada não encontrado: {}", arquivo_entrada),
        ));
    }

    let file   = File::open(arquivo_entrada)?;
    let reader = BufReader::new(file);

    let mut urls_filtradas = Vec::new();
    let mut total_urls     = 0usize;
    let mut linhas_com_erro = 0usize;

    println!("{}[*] Processando arquivo: {}{}", BLUE, arquivo_entrada, RESET);
    if verbose {
        println!("{}[V] Modo verbose ativado{}", MAGENTA, RESET);
        println!("{}[V] Verificação de status: {}{}", MAGENTA, check_status, RESET);
        println!("{}[V] Exploração ativa: {}{}", MAGENTA, explorar, RESET);
        println!("{}[V] Validação Ollama: {} | Modelo: {}{}", MAGENTA, usar_ollama, modelo_ollama, RESET);
        if let Some(prefix) = &report_prefix {
            println!("{}[V] Relatório CSV prefixo: {}{}", MAGENTA, prefix, RESET);
        }
    }

    // CORREÇÃO #15: barra de progresso com indicatif em vez de contador a cada 100.
    // Contamos as linhas primeiro para inicializar a barra corretamente.
    let total_linhas = BufReader::new(File::open(arquivo_entrada)?)
        .lines()
        .count() as u64;

    let pb = ProgressBar::new(total_linhas);
    pb.set_style(
        ProgressStyle::with_template(
            "{}[*]{} Filtrando URLs [{bar:40.cyan/blue}] {pos}/{len} ({eta})"
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-"),
    );

    for linha in BufReader::new(File::open(arquivo_entrada)?).lines() {
        pb.inc(1);
        match linha {
            Ok(url_str) => {
                let url = url_str.trim().to_string();
                total_urls += 1;

                if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                    if verbose { pb.println(format!("{}[V] URL válida: {}{}", CYAN, url, RESET)); }
                    urls_filtradas.push(url);
                } else if verbose && !url.is_empty() {
                    if tem_extensao_remover(&url) {
                        pb.println(format!("{}[V] Removida (extensão): {}{}", YELLOW, url, RESET));
                    } else if !tem_parametros(&url) {
                        pb.println(format!("{}[V] Removida (sem parâmetros): {}{}", YELLOW, url, RESET));
                    }
                }
            }
            Err(_) => {
                linhas_com_erro += 1;
                total_urls += 1;
            }
        }
    }
    pb.finish_and_clear();

    // ── Coleta via Pinchtab ───────────────────────────────────────────────────
    if let Some(cfg) = pinchtab_cfg {
        if verbose {
            println!("{}[*] Coletando links com pinchtab...{}", CYAN, RESET);
        }

        let mut seeds: Vec<String> = if cfg.seeds.is_empty() {
            urls_filtradas.clone()
        } else {
            cfg.seeds.clone()
        };

        seeds.retain(|s| s.starts_with("http") && !tem_extensao_remover(s));
        if !cfg.scopes.is_empty() {
            seeds.retain(|s| cfg.scopes.iter().any(|d| s.contains(d)));
        }

        // CORREÇÃO #13: deduplica seeds antes de processar.
        let mut uniq = HashSet::new();
        seeds.retain(|s| uniq.insert(s.clone()));

        // CORREÇÃO #7: aviso de truncamento sempre visível (não só em verbose).
        if seeds.len() > MAX_PINCHTAB_SEEDS {
            println!(
                "{}[!] pinchtab: seeds reduzidas de {} para {} (limite configurado).{}",
                YELLOW, seeds.len(), MAX_PINCHTAB_SEEDS, RESET
            );
            seeds.truncate(MAX_PINCHTAB_SEEDS);
        }

        for seed in &seeds {
            match coletar_urls_pinchtab(&cfg.host, seed, verbose) {
                Ok(colhidas) => {
                    for url in colhidas {
                        total_urls += 1;
                        if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                            if verbose { println!("{}[V] (pinchtab) URL válida: {}{}", CYAN, url, RESET); }
                            urls_filtradas.push(url);
                        }
                    }
                }
                Err(e) => eprintln!("{}[!] Falha pinchtab (seed {}): {}{}", YELLOW, seed, e, RESET),
            }
        }
    }

    // CORREÇÃO #13: deduplica URLs coletadas antes de gravar.
    let mut seen = HashSet::new();
    urls_filtradas.retain(|u| seen.insert(u.clone()));

    let removidas = total_urls - urls_filtradas.len();

    println!("{}[+] URLs processadas: {}{}", GREEN, total_urls, RESET);
    println!("{}[+] URLs com parâmetros: {}{}", GREEN, urls_filtradas.len(), RESET);
    println!("{}[-] URLs removidas/ignoradas: {}{}", YELLOW, removidas, RESET);
    if linhas_com_erro > 0 {
        println!("{}[!] Linhas com erro de encoding UTF-8 (ignoradas): {}{}", YELLOW, linhas_com_erro, RESET);
    }

    // ── Verificação de status HTTP ────────────────────────────────────────────
    // CORREÇÃO #6: usa reqwest em vez de curl; CORREÇÃO #2: usa rayon para
    // paralelizar as requisições de status.
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if check_status {
        println!("{}[*] Verificando status HTTP das URLs (paralelo)...{}", MAGENTA, RESET);

        let resultados: Vec<(String, Option<u16>)> = urls_filtradas
            .par_iter()
            .map(|url| {
                let status = verificar_status_http(&client, url);
                (url.clone(), status)
            })
            .collect();

        let mut urls_por_status: HashMap<u16, Vec<String>> = HashMap::new();
        let mut urls_sem_resposta = Vec::new();

        for (url, status) in resultados {
            match status {
                Some(s) => urls_por_status.entry(s).or_default().push(url),
                None    => urls_sem_resposta.push(url),
            }
        }

        for (status, urls) in &urls_por_status {
            let arq = obter_nome_arquivo_status(*status, arquivo_saida);
            salvar_com_anew(&arq, urls)?;
            println!("{}[✔] {} URLs com status {} salvas em '{}'{}", GREEN, urls.len(), status, arq, RESET);
        }

        if !urls_sem_resposta.is_empty() {
            let arq = arquivo_saida.replace(".txt", "_sem_resposta.txt");
            salvar_com_anew(&arq, &urls_sem_resposta)?;
            println!("{}[!] {} URLs sem resposta salvas em '{}'{}", YELLOW, urls_sem_resposta.len(), arq, RESET);
        }
    } else {
        salvar_com_anew(arquivo_saida, &urls_filtradas)?;
        println!("{}[✔] URLs filtradas salvas em '{}'{}", GREEN, arquivo_saida, RESET);
    }

    // ── Exploração ativa ──────────────────────────────────────────────────────
    if explorar {
        explorar_vulnerabilidades(
            &urls_filtradas,
            verbose,
            usar_ollama,
            modelo_ollama,
            report_prefix.as_deref(),
        )?;
    }

    println!();
    Ok(())
}

// ─── Salvar com anew ──────────────────────────────────────────────────────────
fn salvar_com_anew(arquivo: &str, urls: &[String]) -> std::io::Result<()> {
    let mut child = Command::new("anew")
        .arg(arquivo)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        for url in urls {
            writeln!(stdin, "{}", url)?;
        }
    }
    child.wait()?;
    Ok(())
}

// ─── Construção da URL com payload injetado ───────────────────────────────────
// CORREÇÃO #5: aplica percent-encoding completo a todos os payloads
// via o crate `percent-encoding`, garantindo que caracteres como
// `'`, espaço, `=`, `"` sejam sempre codificados corretamente.
fn construir_url_injetada(url: &str, alvo: &str, payload: &str) -> Option<String> {
    let (base, query) = url.split_once('?')?;

    let pares: Vec<(String, String)> = query
        .split('&')
        .filter_map(|p| {
            let mut kv = p.splitn(2, '=');
            let k = kv.next()?.to_string();
            let v = kv.next().unwrap_or("").to_string();
            Some((k, v))
        })
        .collect();

    let mut alterou = false;
    let nova_query = pares
        .iter()
        .map(|(k, v)| {
            if k == alvo {
                alterou = true;
                // Percent-encode completo usando NON_ALPHANUMERIC para máxima compatibilidade.
                let encoded = utf8_percent_encode(payload, NON_ALPHANUMERIC).to_string();
                format!("{}={}", k, encoded)
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    if !alterou { return None; }
    Some(format!("{}?{}", base, nova_query))
}

// ─── Detecção de vulnerabilidades ─────────────────────────────────────────────
fn parece_erro_sql(corpo: &str) -> bool {
    let lower = corpo.to_lowercase();
    SQLI_PADROES_ERRO.iter().any(|p| lower.contains(p))
}

// CORREÇÃO #3: verifica múltiplos marcadores (cru e HTML-encoded)
// e exige que o marcador apareça dentro de uma tag de script ou atributo de evento,
// descartando ocorrências em comentários HTML.
fn reflexo_xss(corpo: &str, _payload: &str) -> bool {
    // Verifica qualquer forma de reflexo
    if !XSS_MARCADORES.iter().any(|m| corpo.contains(m)) {
        return false;
    }

    // Descarta se o marcador aparece apenas dentro de comentário HTML
    let lower = corpo.to_lowercase();
    let em_comentario = lower
        .split("<!--")
        .skip(1)
        .any(|bloco| {
            let ate_fim = bloco.split("-->").next().unwrap_or("");
            XSS_MARCADORES.iter().any(|m| ate_fim.contains(m))
        });

    !em_comentario
}

// ─── Pinchtab ─────────────────────────────────────────────────────────────────
fn coletar_urls_pinchtab(host: &str, start: &str, verbose: bool) -> std::io::Result<Vec<String>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if verbose { println!("{}[*] Abrindo {} via pinchtab ({}){}", CYAN, start, host, RESET); }

    let tab_resp: Value = client
        .post(format!("{}/tab", host))
        .json(&serde_json::json!({"action": "new", "url": start}))
        .send()
        .and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let tab_id = tab_resp
        .get("tabId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Resposta pinchtab sem tabId"))?
        .to_string();

    let snap: Value = client
        .get(format!("{}/snapshot", host))
        .query(&[("tabId", tab_id.as_str()), ("filter", "interactive")])
        .send()
        .and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let mut urls = Vec::new();
    coletar_links_json(&snap, &mut urls);

    // CORREÇÃO #13: deduplica antes de retornar.
    let mut seen = HashSet::new();
    urls.retain(|u| seen.insert(u.clone()) && u.contains('?'));

    if verbose { println!("{}[V] pinchtab retornou {} URLs com '?'.{}", MAGENTA, urls.len(), RESET); }
    Ok(urls)
}

fn coletar_links_json(v: &Value, saida: &mut Vec<String>) {
    match v {
        Value::Array(arr) => arr.iter().for_each(|i| coletar_links_json(i, saida)),
        Value::Object(map) => {
            map.values().for_each(|val| coletar_links_json(val, saida));
            if let Some(href) = map.get("href").and_then(|x| x.as_str()) { saida.push(href.to_string()); }
            if let Some(url)  = map.get("url").and_then(|x| x.as_str())  { saida.push(url.to_string()); }
        }
        Value::String(s) if s.starts_with("http") => saida.push(s.clone()),
        _ => {}
    }
}

fn fetch_with_client(client: &Client, url: &str) -> Option<(u16, String)> {
    client.get(url).send().ok().map(|r| {
        let status = r.status().as_u16();
        let body   = r.text().unwrap_or_default();
        (status, body)
    })
}

// ─── Structs ──────────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct Achado {
    tipo:      &'static str,
    url:       String,
    parametro: String,
    payload:   String,
    corpo:     String,
    llm:       Option<String>,
}

#[derive(Clone)]
struct PinchTabConfig {
    host:   String,
    seeds:  Vec<String>,
    scopes: Vec<String>,
}

// ─── Exploração ativa (SQLi / XSS / IDOR) ────────────────────────────────────
// CORREÇÃO #2: os testes são paralelizados com rayon (par_iter + Mutex para
// acumular resultados), reduzindo dramaticamente o tempo total em alvos grandes.
fn explorar_vulnerabilidades(
    urls: &[String],
    verbose: bool,
    usar_ollama: bool,
    modelo: &str,
    report_prefix: Option<&str>,
) -> std::io::Result<()> {
    println!("{}[*] Explorando parâmetros suspeitos (SQLi/XSS/IDOR) em paralelo...{}", BLUE, RESET);

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let achados: Arc<Mutex<Vec<Achado>>>                    = Arc::new(Mutex::new(Vec::new()));
    let falhas:  Arc<Mutex<Vec<(String, String, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let total_testes: Arc<Mutex<usize>>                     = Arc::new(Mutex::new(0));

    urls.par_iter().for_each(|url| {
        if !url.contains('?') { return; }

        let params: Vec<(String, String)> = url
            .splitn(2, '?')
            .nth(1)
            .unwrap_or("")
            .split('&')
            .filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect();

        let baseline = fetch_with_client(&client, url);

        for (param, valor) in &params {
            // ── SQLi ─────────────────────────────────────────────────────────
            for payload in SQLI_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    match fetch_with_client(&client, &test_url) {
                        Some((_status, body)) => {
                            if parece_erro_sql(&body) {
                                println!("{}[!] Possível SQLi em '{}' parâmetro '{}' com payload \"{}\"{}", YELLOW, url, param, payload, RESET);
                                achados.lock().unwrap().push(Achado {
                                    tipo: "SQLi",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(MAX_CHARS_PREVIEW_CORPO).collect(),
                                    llm: None,
                                });
                            } else if verbose {
                                println!("{}[-] Sem indícios SQLi para {} payload {}{}", BLUE, param, payload, RESET);
                            }
                        }
                        None => {
                            println!("{}[!] Falha ao testar {} ({}): sem resposta{}", YELLOW, url, payload, RESET);
                            falhas.lock().unwrap().push((url.clone(), param.clone(), payload.to_string(), "sem resposta".to_string()));
                        }
                    }
                }
            }

            // ── XSS ──────────────────────────────────────────────────────────
            for payload in XSS_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    match fetch_with_client(&client, &test_url) {
                        Some((_status, body)) => {
                            if reflexo_xss(&body, payload) {
                                println!("{}[!] Possível XSS refletido em '{}' parâmetro '{}'{}", YELLOW, url, param, RESET);
                                achados.lock().unwrap().push(Achado {
                                    tipo: "XSS",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(MAX_CHARS_PREVIEW_CORPO).collect(),
                                    llm: None,
                                });
                            } else if verbose {
                                println!("{}[-] Sem indícios XSS para {} payload {}{}", BLUE, param, payload, RESET);
                            }
                        }
                        None => {
                            println!("{}[!] Falha ao testar {} ({}): sem resposta{}", YELLOW, url, payload, RESET);
                            falhas.lock().unwrap().push((url.clone(), param.clone(), payload.to_string(), "sem resposta".to_string()));
                        }
                    }
                }
            }

            // ── IDOR ─────────────────────────────────────────────────────────
            // CORREÇÃO #4: limiar elevado para IDOR_DIFF_MINIMA (500 bytes)
            // para reduzir falsos positivos causados por ruído dinâmico.
            if let Ok(orig) = valor.parse::<i64>() {
                if let Some((status_base, corpo_base)) = &baseline {
                    for delta in IDOR_DELTAS {
                        let novo_valor = (orig + delta).to_string();
                        if let Some(test_url) = construir_url_injetada(url, param, &novo_valor) {
                            *total_testes.lock().unwrap() += 1;
                            match fetch_with_client(&client, &test_url) {
                                Some((status, body)) => {
                                    let diff = (body.len() as isize - corpo_base.len() as isize).unsigned_abs();
                                    if status == *status_base && diff > IDOR_DIFF_MINIMA {
                                        println!("{}[!] Possível IDOR em '{}' param '{}' ({} -> {}){}", YELLOW, url, param, valor, novo_valor, RESET);
                                        achados.lock().unwrap().push(Achado {
                                            tipo: "IDOR",
                                            url: url.clone(),
                                            parametro: param.clone(),
                                            payload: novo_valor,
                                            corpo: body.chars().take(MAX_CHARS_PREVIEW_CORPO).collect(),
                                            llm: None,
                                        });
                                    } else if verbose {
                                        println!("{}[-] Sem indício IDOR {} delta {} (status {} len diff {}){}", BLUE, param, delta, status, diff, RESET);
                                    }
                                }
                                None => {
                                    println!("{}[!] Falha IDOR {} ({}): sem resposta{}", YELLOW, url, delta, RESET);
                                    falhas.lock().unwrap().push((url.clone(), param.clone(), format!("IDOR {}", delta), "sem resposta".to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let total = *total_testes.lock().unwrap();
    let mut achados_final = Arc::try_unwrap(achados).unwrap().into_inner().unwrap();
    let falhas_final      = Arc::try_unwrap(falhas).unwrap().into_inner().unwrap();

    println!("{}[+] Testes ativos executados: {}{}", GREEN, total, RESET);
    if achados_final.is_empty() {
        println!("{}[-] Nenhum comportamento suspeito detectado nos testes básicos.{}", BLUE, RESET);
    }

    if usar_ollama && !achados_final.is_empty() {
        validar_com_ollama(modelo, &mut achados_final, verbose)?;
    } else if usar_ollama {
        println!("{}[LLM] Nenhum achado para validar com Ollama.{}", BLUE, RESET);
    }

    if let Some(prefix) = report_prefix {
        salvar_relatorios(prefix, &achados_final, &falhas_final)?;
    }

    Ok(())
}

// ─── Validação com Ollama ─────────────────────────────────────────────────────
// CORREÇÃO #10: adicionado timeout de 60 s via `wait_timeout` para evitar que
// um modelo travado congele a ferramenta indefinidamente.
fn validar_com_ollama(modelo: &str, achados: &mut [Achado], verbose: bool) -> std::io::Result<()> {
    println!("{}[*] Validando achados com Ollama (modelo: {}){}", CYAN, modelo, RESET);

    for achado in achados.iter_mut() {
        let prompt = format!(
            "Classifique rapidamente se este achado de segurança é provavelmente verdadeiro ou \
falso positivo.\nTipo: {tipo}\nURL: {url}\nParâmetro: {param}\nPayload: {payload}\n\
Trecho de resposta (pode estar truncado):\n{corpo}\n\
Responda somente com 'true_positive' ou 'false_positive' e uma curta justificativa em português.",
            tipo    = achado.tipo,
            url     = achado.url,
            param   = achado.parametro,
            payload = achado.payload,
            corpo   = achado.corpo,
        );

        match Command::new("ollama")
            .arg("run")
            .arg(modelo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(prompt.as_bytes());
                }

                // Timeout de 60 s: se o modelo não responder, abandona este achado.
                let timeout = Duration::from_secs(60);
                let started = std::time::Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if started.elapsed() >= timeout => {
                            eprintln!("{}[LLM] Timeout ao aguardar Ollama para {}. Pulando.{}", YELLOW, achado.url, RESET);
                            let _ = child.kill();
                            break;
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                        Err(e) => {
                            eprintln!("{}[LLM] Erro ao aguardar processo: {}{}", YELLOW, e, RESET);
                            break;
                        }
                    }
                }

                match child.wait_with_output() {
                    Ok(out) => {
                        let resposta = String::from_utf8_lossy(&out.stdout);
                        println!("{}[LLM] {} -> {}{}", GREEN, achado.url, resposta.trim(), RESET);
                        achado.llm = Some(resposta.trim().to_string());
                    }
                    Err(e) => eprintln!("{}[LLM] Falha ao ler saída: {}{}", YELLOW, e, RESET),
                }
            }
            Err(e) => {
                eprintln!("{}[LLM] Não foi possível executar ollama: {}{}", YELLOW, e, RESET);
                if verbose {
                    eprintln!("{}[V] Instale ollama ou remova --ollama para continuar sem validação.{}", YELLOW, RESET);
                }
            }
        }
    }
    Ok(())
}

// ─── Relatórios CSV ───────────────────────────────────────────────────────────
fn salvar_relatorios(
    prefix: &str,
    achados: &[Achado],
    falhas:  &[(String, String, String, String)],
) -> std::io::Result<()> {
    let achados_path = format!("{}_achados.csv", prefix);
    let falhas_path  = format!("{}_falhas.csv", prefix);

    {
        let mut file = File::create(&achados_path)?;
        writeln!(file, "tipo,url,parametro,payload,llm")?;
        for a in achados {
            writeln!(
                file,
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                a.tipo,
                escape_csv(&a.url),
                escape_csv(&a.parametro),
                escape_csv(&a.payload),
                escape_csv(a.llm.as_deref().unwrap_or("")),
            )?;
        }
    }

    {
        let mut file = File::create(&falhas_path)?;
        writeln!(file, "url,parametro,payload,erro")?;
        for (u, p, pay, err) in falhas {
            writeln!(
                file,
                "\"{}\",\"{}\",\"{}\",\"{}\"",
                escape_csv(u),
                escape_csv(p),
                escape_csv(pay),
                escape_csv(err),
            )?;
        }
    }

    println!("{}[✔] Relatórios salvos em '{}' e '{}'{}", GREEN, achados_path, falhas_path, RESET);
    Ok(())
}

fn escape_csv(texto: &str) -> String {
    texto.replace('"', "\"\"")
}

// ─── Ferramentas externas ─────────────────────────────────────────────────────
fn executar_subfinder(domain: &str, arquivo_saida: &str) -> std::io::Result<()> {
    println!("{}[*] Executando subfinder para: {}{}", MAGENTA, domain, RESET);
    let output = Command::new("subfinder").arg("-d").arg(domain).arg("-all").output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Subfinder falhou"));
    }
    let mut file = File::create(arquivo_saida)?;
    file.write_all(&output.stdout)?;
    println!("{}[+] {} subdomínios encontrados{}", GREEN, String::from_utf8_lossy(&output.stdout).lines().count(), RESET);
    Ok(())
}

fn executar_katana(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando katana para crawling{}", MAGENTA, RESET);
    let output = Command::new("katana").arg("-list").arg(arquivo_subs).output()?;
    if !output.status.success() {
        eprintln!("{}[!] Aviso: Katana pode não estar instalado ou falhou{}", YELLOW, RESET);
    }
    let mut file = File::create(arquivo_urls)?;
    file.write_all(&output.stdout)?;
    println!("{}[+] {} URLs encontradas com katana{}", GREEN, String::from_utf8_lossy(&output.stdout).lines().count(), RESET);
    Ok(())
}

fn executar_urlfinder(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando urlfinder para extração de URLs{}", MAGENTA, RESET);
    let output = Command::new("urlfinder").arg("-i").arg(arquivo_subs).output()?;
    if !output.status.success() {
        eprintln!("{}[!] Aviso: urlfinder pode não estar instalado ou falhou{}", YELLOW, RESET);
    }
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(arquivo_urls)?;
    file.write_all(&output.stdout)?;
    println!("{}[+] {} URLs encontradas com urlfinder{}", GREEN, String::from_utf8_lossy(&output.stdout).lines().count(), RESET);
    Ok(())
}

// ─── Modos de operação ────────────────────────────────────────────────────────
fn processar_domain_unico(domain: &str, pinchtab_cfg: Option<PinchTabConfig>) {
    println!("{}[*] Iniciando processo para domínio: {}{}\n", CYAN, domain, RESET);
    let subs_file  = "dominios_temp.txt";
    let urls_file  = "urls_temp.txt";
    let resultado  = format!("{}_urls_filtradas.txt", domain);

    if let Err(e) = executar_subfinder(domain, subs_file) {
        eprintln!("{}[✗] Erro no subfinder: {}{}", RED, e, RESET);
        process::exit(1);
    }
    if let Err(e) = executar_katana(subs_file, urls_file) {
        eprintln!("{}[!] Aviso katana: {}{}", YELLOW, e, RESET);
    }
    if let Err(e) = executar_urlfinder(subs_file, urls_file) {
        eprintln!("{}[!] Aviso urlfinder: {}{}", YELLOW, e, RESET);
    }

    println!("\n{}[*] Iniciando filtragem de URLs{}\n", BLUE, RESET);

    if let Err(e) = filtrar_urls(urls_file, &resultado, false, false, false, false, OLLAMA_MODEL_DEFAULT, None, pinchtab_cfg) {
        eprintln!("{}[✗] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }

    let _ = std::fs::remove_file(subs_file);
    let _ = std::fs::remove_file(urls_file);
    println!("{}[✔] Processo concluído! Resultados em: {}{}", GREEN, resultado, RESET);
}

fn processar_lista_dominios(arquivo_subs: &str, pinchtab_cfg: Option<PinchTabConfig>) {
    println!("{}[*] Iniciando processo para lista de subdomínios: {}{}\n", CYAN, arquivo_subs, RESET);

    // CORREÇÃO #8: valida existência do arquivo antes de prosseguir.
    if !PathBuf::from(arquivo_subs).exists() {
        eprintln!("{}[✗] Arquivo não encontrado: {}{}", RED, arquivo_subs, RESET);
        process::exit(1);
    }

    let urls_file     = "urls_crawled.txt";
    let resultado_file = "urls_filtradas_lote.txt";

    if let Ok(file) = File::open(arquivo_subs) {
        println!("{}[+] {} subdomínios para processar{}", GREEN, BufReader::new(file).lines().count(), RESET);
    }

    if let Err(e) = executar_katana(arquivo_subs, urls_file) {
        eprintln!("{}[!] Aviso katana: {}{}", YELLOW, e, RESET);
    }
    if let Err(e) = executar_urlfinder(arquivo_subs, urls_file) {
        eprintln!("{}[!] Aviso urlfinder: {}{}", YELLOW, e, RESET);
    }

    println!("\n{}[*] Iniciando filtragem de URLs{}\n", BLUE, RESET);

    if let Err(e) = filtrar_urls(urls_file, resultado_file, false, false, false, false, OLLAMA_MODEL_DEFAULT, None, pinchtab_cfg) {
        eprintln!("{}[✗] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }

    let _ = std::fs::remove_file(urls_file);
    println!("{}[✔] Processo concluído! Resultados em: {}{}", GREEN, resultado_file, RESET);
}

// ─── Argumentos ───────────────────────────────────────────────────────────────
fn processar_argumentos() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());

    let arquivo_entrada = if let Some(pos) = args.iter().position(|x| x == "-l") {
        if pos + 1 < args.len() {
            let caminho = args[pos + 1].clone();
            let path = PathBuf::from(&caminho);
            let abs = if path.is_absolute() { path } else { PathBuf::from(&cwd).join(&caminho) };

            // CORREÇÃO #8: valida existência imediatamente com mensagem clara.
            if !abs.exists() {
                eprintln!("{}[✗] Arquivo de entrada não encontrado: {}{}", RED, abs.display(), RESET);
                process::exit(1);
            }
            abs.to_string_lossy().into_owned()
        } else {
            eprintln!("{}[✗] Caminho do arquivo não especificado após -l.{}", RED, RESET);
            process::exit(1);
        }
    } else {
        eprintln!("{}[✗] A flag -l é obrigatória. Use -h para ajuda.{}", RED, RESET);
        process::exit(1);
    };

    let arquivo_saida = if let Some(pos) = args.iter().position(|x| x == "-o") {
        if pos + 1 < args.len() { args[pos + 1].clone() }
        else {
            eprintln!("{}[✗] Caminho não especificado após -o.{}", RED, RESET);
            process::exit(1);
        }
    } else {
        String::from("urls_parametros.txt")
    };

    (arquivo_entrada, arquivo_saida)
}