use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::collections::HashMap;
use std::time::Duration;
use reqwest::blocking::Client;
use serde_json::Value;

// Versionamento
const VERSION: &str = "1.0.0";

const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN: &str = "\x1b[96m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

// ConfiguraÃ§Ã£o de LLM local (Ollama)
const OLLAMA_MODEL_DEFAULT: &str = "phi3:mini"; // modelo leve e rÃ¡pido

// Payloads e padrÃµes para exploraÃ§Ã£o ativa
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
const IDOR_DELTAS: &[i64] = &[1, -1, 2, -2];

fn main() {
    let args: Vec<String> = env::args().collect();
    
    mostrar_banner();
    
    // Verifica se a ferramenta estÃ¡ atualizada - SEMPRE executa
    verificar_atualizacoes();
    
    // Verifica se Ã© solicitado help
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        mostrar_help();
        return;
    }
    
    // Verifica se Ã© solicitado update
    if args.contains(&"-up".to_string()) || args.contains(&"--update".to_string()) {
        atualizar_ferramenta();
        return;
    }
    
    // Verifica as flags globais
    let verbose = args.contains(&"-v".to_string()) || args.contains(&"--verbose".to_string());
    let check_status = args.contains(&"-status".to_string()) || args.contains(&"--status".to_string());
    let usar_ollama = args.contains(&"--ollama".to_string());
    let explorar = args.contains(&"-p".to_string()) || args.contains(&"--explore".to_string()) || usar_ollama;
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
    
    // Verifica se Ã© passado um domÃ­nio Ãºnico (-d)
    if let Some(pos) = args.iter().position(|x| x == "-d") {
        if pos + 1 < args.len() {
            let domain = &args[pos + 1];
            processar_domain_unico(domain);
        } else {
            eprintln!("{}[âœ—] Erro: DomÃ­nio nÃ£o especificado apÃ³s a flag -d.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }
    
    // Verifica se Ã© passado um arquivo com lista de domÃ­nios (-f)
    if let Some(pos) = args.iter().position(|x| x == "-f") {
        if pos + 1 < args.len() {
            let arquivo_subs = &args[pos + 1];
            processar_lista_dominios(arquivo_subs);
        } else {
            eprintln!("{}[âœ—] Erro: Arquivo com lista de subdomÃ­nios nÃ£o especificado apÃ³s a flag -f.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }
    
    // Modo padrÃ£o: apenas filtrar URLs passadas por -l
    let (arquivo_entrada, arquivo_saida) = processar_argumentos();
    
    let pinchtab_cfg = pinchtab_start.map(|s| PinchTabConfig { start: s, host: pinchtab_host });

    if let Err(e) = filtrar_urls(&arquivo_entrada, &arquivo_saida, verbose, check_status, explorar, usar_ollama, &modelo_ollama, report_prefix, pinchtab_cfg) {
        eprintln!("{}[âœ—] Erro ao processar o arquivo: {}{}", RED, e, RESET);
        process::exit(1);
    }
}

// Lista de extensÃµes de arquivos a serem removidas
const EXTENSOES_REMOVER: &[&str] = &[
    // Imagens
    "jpg", "jpeg", "gif", "png", "tif", "tiff", "bmp", "svg", "ico", "webp",
    // Documentos
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "zip", "rar", "7z",
    // Estilos e Scripts
    "css", "js", "json", "xml", "yaml", "yml",
    // Fontes
    "ttf", "woff", "woff2", "eot", "otf", "font",
    // Ãudio e VÃ­deo
    "mp3", "mp4", "avi", "mov", "flv", "wav", "m4a",
    // ExecutÃ¡veis
    "exe", "dll", "so", "dylib",
    // Mapas
    "map",
];

// FunÃ§Ã£o para mostrar o banner
fn mostrar_banner() {
    println!("{}", RED);
    println!("{}{}{}", RED, r#" ______    ______     ______     ______     __    __     ______     ______   ______     __     __  __     ______                                         "#, RESET);
    println!("{}{}{}", RED, r#"/\  == \  /\  __ \   /\  == \   /\  __ \   /\ "-./  \   /\  ___\   /\__  _\ /\  == \   /\ \   /\ \/ /    /\  ___\ "#, RESET); 
    println!("{}{}{}", RED, r#"\ \  _-/  \ \  __ \  \ \  __<   \ \  __ \  \ \ \-./\ \  \ \___  \  \/_/\ \/ \ \  __<   \ \ \  \ \  _"-. \ \  __\  "#, RESET); 
    println!("{}{}{}", RED, r#" \ \_\     \ \_\ \_\  \ \_\ \_\  \ \_\ \_\  \ \_\ \ \_\  \/\_____\    \ \_\  \ \_\ \_\  \ \_\  \ \_\ \_\  \ \_____\ "#, RESET);
    println!("{}{}{}", RED, r#"  \/_/      \/_/\/_/   \/_/ /_/   \/_/\/_/   \/_/  \/_/   \/_____/     \/_/   \/_/ /_/   \/_/   \/_/\/_/   \/_____/ "#, RESET);
    println!();
    println!("{}                    v1.0 - URL Parameter Extractor & Web Reconnaissance{}", BOLD, RESET);
    println!();
    println!("{}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", BLUE, RESET);
    println!("{}             âœ“ Developed by: 0x13-ByteZer0{}", GREEN, RESET);
    println!("{}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", BLUE, RESET);
    println!("{}", RESET);
    println!();
}

// FunÃ§Ã£o para mostrar a ajuda
fn mostrar_help() {
    println!("{}Uso:{} paramstrike [OPÃ‡ÃƒO] [ARGUMENTOS]\n", BOLD, RESET);
    
    println!("{}OpÃ§Ãµes:{}", BOLD, RESET);
    println!("  {}  -l <arquivo>{}    Arquivo de entrada com URLs (obrigatÃ³rio para modo padrÃ£o)", YELLOW, RESET);
    println!("  {}  -o <arquivo>{}    Arquivo de saÃ­da (padrÃ£o: urls_parametros.txt)", YELLOW, RESET);
    println!("  {}  -d <domain>{}     DomÃ­nio Ãºnico - executar subfinder, katana e urlfinder", CYAN, RESET);
    println!("  {}  -f <arquivo>{}    Arquivo com lista de subdomÃ­nios para crawler", CYAN, RESET);
    println!("  {}  -v, --verbose{}   Modo verbose (mostra fluxo de processamento)", MAGENTA, RESET);
    println!("  {}  -status{}          Verificar status HTTP e salvar em arquivos separados", MAGENTA, RESET);
    println!("  {}  -p, --explore{}   Explorar ativamente os parÃ¢metros (SQLi/XSS bÃ¡sicos)", MAGENTA, RESET);
    println!("  {}  --ollama{}         Validar achados com Ollama (desliga falsos positivos)", MAGENTA, RESET);
    println!("  {}  --ollama-model <m>{} Modelo Ollama (padrÃ£o: {})", MAGENTA, RESET, OLLAMA_MODEL_DEFAULT);
    println!("  {}  --report-prefix <p>{} Salvar achados em CSV (ex.: relatorio)", MAGENTA, RESET);
    println!("  {}  --pinchtab-start <url>{} Usar pinchtab para abrir URL no Firefox/Chrome e extrair links", MAGENTA, RESET);
    println!("  {}  --pinchtab-host <host>{} Host do serviÃ§o pinchtab (padrÃ£o: http://localhost:9867)", MAGENTA, RESET);
    println!("  {}  -up, --update{}   Atualizar a ferramenta do Git e recompilar", MAGENTA, RESET);
    println!("  {}  -h, --help{}      Mostra esta mensagem de ajuda\n", YELLOW, RESET);
    
    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}Modo padrÃ£o (filtrar URLs):{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt{}", GREEN, RESET);
    println!("  {}Com exploraÃ§Ã£o ativa de parÃ¢metros:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -p{}", GREEN, RESET);
    println!("  {}Com exploraÃ§Ã£o + validaÃ§Ã£o no LLM local:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -p --ollama --ollama-model {}{}", GREEN, OLLAMA_MODEL_DEFAULT, RESET);
    println!("  {}Gerar relatÃ³rio em CSV dos achados:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -p --report-prefix relatorio{}", GREEN, RESET);
    println!("  {}Com verbose e verificaÃ§Ã£o de status:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -v -status{}", GREEN, RESET);
    println!("  {}Atualizar ferramenta:{}", GREEN, RESET);
    println!("    {}$ paramstrike -up{}", GREEN, RESET);
    println!("  {}Modo domÃ­nio Ãºnico:{}", GREEN, RESET);
    println!("    {}$ paramstrike -d example.com{}", GREEN, RESET);
    println!("  {}Modo lista de subdomÃ­nios:{}", GREEN, RESET);
    println!("    {}$ paramstrike -f subs.txt{}\n", GREEN, RESET);
}

// FunÃ§Ã£o para obter a versÃ£o atual do repositÃ³rio (lÃª do arquivo VERSION na raiz)
fn obter_versao_repositorio() -> Option<String> {
    match std::fs::read_to_string("VERSION") {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

// FunÃ§Ã£o para ler a versÃ£o salva localmente
fn ler_versao_salva() -> Option<String> {
    match std::fs::read_to_string(".version") {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

// FunÃ§Ã£o para salvar a versÃ£o localmente
fn salvar_versao(versao: &str) -> std::io::Result<()> {
    std::fs::write(".version", versao)
}

// FunÃ§Ã£o para verificar se hÃ¡ atualizaÃ§Ãµes disponÃ­veis
fn verificar_atualizacoes() {
    // LÃª a versÃ£o do arquivo VERSION (source of truth)
    let versao_local = match std::fs::read_to_string("VERSION") {
        Ok(content) => content.trim().to_string(),
        Err(_) => VERSION.to_string(), // fallback para a constante
    };
    
    // VersÃ£o no repositÃ³rio (ou versÃ£o salva se estivemos offline)
    let versao_salva = ler_versao_salva();
    
    match versao_salva {
        Some(salva) => {
            if versao_local != salva {
                // VersÃ£o desatualizada
                println!("{}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{}", YELLOW, RESET);
                println!("{}â•‘                                                               â•‘{}", YELLOW, RESET);
                println!("{}â•‘  {}âš   FERRAMENTA DESATUALIZADA!                          {}â•‘{}", YELLOW, RED, YELLOW, RESET);
                println!("{}â•‘                                                               â•‘{}", YELLOW, RESET);
                println!("{}â•‘  {}VersÃ£o atual: {} | VersÃ£o instalada: {}{}      {}â•‘{}", YELLOW, CYAN, versao_local, salva, YELLOW, YELLOW, RESET);
                println!("{}â•‘                                                               â•‘{}", YELLOW, RESET);
                println!("{}â•‘  {}Nova versÃ£o disponÃ­vel. Execute para atualizar:  {}â•‘{}", YELLOW, CYAN, YELLOW, RESET);
                println!("{}â•‘                                                               â•‘{}", YELLOW, RESET);
                println!("{}â•‘         {}$ paramstrike -up                             {}â•‘{}", YELLOW, BOLD, YELLOW, RESET);
                println!("{}â•‘                                                               â•‘{}", YELLOW, RESET);
                println!("{}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", YELLOW, RESET);
                println!();
            } else {
                // VersÃ£o atualizada
                println!("{}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{}", GREEN, RESET);
                println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
                println!("{}â•‘  {}âœ“  FERRAMENTA ATUALIZADA{}                                   {}â•‘{}", GREEN, BOLD, RESET, GREEN, RESET);
                println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
                println!("{}â•‘         {}VersÃ£o: {}{}                                         {}â•‘{}", GREEN, BOLD, versao_local, RESET, GREEN, RESET);
                println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
                println!("{}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", GREEN, RESET);
                println!();
            }
        }
        None => {
            // Primeira execuÃ§Ã£o - salva a versÃ£o
            println!("{}[*] Primeira execuÃ§Ã£o - salvando versÃ£o {}{}", BLUE, versao_local, RESET);
            let _ = salvar_versao(&versao_local);
            println!("{}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{}", GREEN, RESET);
            println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
            println!("{}â•‘  {}âœ“  FERRAMENTA ATUALIZADA{}                                   {}â•‘{}", GREEN, BOLD, RESET, GREEN, RESET);
            println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
            println!("{}â•‘         {}VersÃ£o: {}{}                                         {}â•‘{}", GREEN, BOLD, versao_local, RESET, GREEN, RESET);
            println!("{}â•‘                                                               â•‘{}", GREEN, RESET);
            println!("{}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", GREEN, RESET);
            println!();
        }
    }
}


// FunÃ§Ã£o para verificar se a URL contÃ©m uma das extensÃµes especificadas
fn tem_extensao_remover(url: &str) -> bool {
    let url = url.trim().to_lowercase();
    
    // Extrai sÃ³ o path, antes dos parÃ¢metros (?)
    let path = url.split('?').next().unwrap_or(&url);
    
    for ext in EXTENSOES_REMOVER {
        if path.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    false
}
// FunÃ§Ã£o para verificar se a URL contÃ©m parÃ¢metros
fn tem_parametros(url: &str) -> bool {
    url.contains('?')
}

// FunÃ§Ã£o para verificar o status HTTP de uma URL
fn verificar_status_http(url: &str) -> Option<u16> {
    let output = Command::new("curl")
        .arg("-s")
        .arg("-o")
        .arg(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .arg("-w")
        .arg("%{http_code}")
        .arg("--max-time")
        .arg("5")
        .arg(url)
        .output();
    
    match output {
        Ok(out) => {
            let status_str = String::from_utf8_lossy(&out.stdout);
            status_str.trim().parse::<u16>().ok()
        }
        Err(_) => None,
    }
}

// FunÃ§Ã£o para atualizar a ferramenta do Git e recompilar
fn atualizar_ferramenta() {
    println!("{}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{}", BLUE, RESET);
    println!("{}â•‘           {}INICIANDO PROCESSO DE ATUALIZAÃ‡ÃƒO{}                       {}â•‘{}", BLUE, BOLD, RESET, BLUE, RESET);
    println!("{}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", BLUE, RESET);
    println!();
    
    // Executa git pull
    println!("{}[1/2] Realizando git pull...{}", CYAN, RESET);
    println!("{}â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€{}", MAGENTA, RESET);
    let git_output = Command::new("git")
        .arg("pull")
        .output();
    
    match git_output {
        Ok(output) => {
            if output.status.success() {
                let msg = String::from_utf8_lossy(&output.stdout);
                println!("{}âœ“ Git pull concluÃ­do com sucesso!{}", GREEN, RESET);
                if !msg.trim().is_empty() {
                    println!("{}{}{}", CYAN, msg, RESET);
                }
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                eprintln!("{}âœ— Erro ao executar git pull:{}", RED, RESET);
                eprintln!("{}{}{}", YELLOW, err, RESET);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}âœ— Erro ao executar git: {}{}", RED, e, RESET);
            process::exit(1);
        }
    }
    
    println!();
    
    // LÃª a versÃ£o do repositÃ³rio apÃ³s o pull (fonte de verdade)
    let versao_repo = obter_versao_repositorio().unwrap_or_else(|| VERSION.to_string());
    
    // Executa cargo build --release
    println!("{}[2/2] Compilando com cargo...{}", CYAN, RESET);
    println!("{}â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€{}", MAGENTA, RESET);
    let cargo_output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .output();
    
    match cargo_output {
        Ok(output) => {
            if output.status.success() {
                println!("{}âœ“ CompilaÃ§Ã£o concluÃ­da com sucesso!{}", GREEN, RESET);
                let msg = String::from_utf8_lossy(&output.stdout);
                if !msg.trim().is_empty() {
                    println!("{}{}{}", CYAN, msg, RESET);
                }
                println!();
                
                // Sincroniza .version com a versÃ£o do repositÃ³rio, sem modificar VERSION
                match salvar_versao(&versao_repo) {
                    Ok(_) => println!("{}[âœ“] VersÃ£o sincronizada: {}{}", GREEN, versao_repo, RESET),
                    Err(e) => eprintln!("{}[!] Aviso ao salvar .version: {}{}", YELLOW, e, RESET),
                }
                
                println!();
                println!("{}â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—{}", BLUE, RESET);
                println!("{}â•‘                                                               â•‘{}", BLUE, RESET);
                println!("{}â•‘  {}âœ“  ATUALIZAÃ‡ÃƒO CONCLUÃDA COM SUCESSO!{}                     {}â•‘{}", BLUE, GREEN, RESET, BLUE, RESET);
                println!("{}â•‘                                                               â•‘{}", BLUE, RESET);
                println!("{}â•‘         {}â†’ VersÃ£o: {}{}                                   {}â•‘{}", BLUE, BOLD, versao_repo, RESET, BLUE, RESET);
                println!("{}â•‘         {}â†’ Status: RECOMPILADO{}                              {}â•‘{}", BLUE, BOLD, RESET, BLUE, RESET);
                println!("{}â•‘                                                               â•‘{}", BLUE, RESET);
                println!("{}â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•{}", BLUE, RESET);
                println!();
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                eprintln!("{}[âœ—] Erro ao compilar:{}", RED, RESET);
                eprintln!("{}{}{}", YELLOW, err, RESET);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}[âœ—] Erro ao executar cargo: {}{}", RED, e, RESET);
            eprintln!("{}Certifique-se de que Rust estÃ¡ instalado e no PATH.{}", YELLOW, RESET);
            process::exit(1);
        }
    }
}


// FunÃ§Ã£o para obter nome do arquivo baseado no status code
fn obter_nome_arquivo_status(status: u16, arquivo_base: &str) -> String {
    let categoria = match status {
        200..=299 => "2xx_sucessos",
        300..=399 => "3xx_redirecionamentos",
        400..=499 => "4xx_erros_cliente",
        500..=599 => "5xx_erros_servidor",
        _ => "desconhecido",
    };
    
    let sem_extensao = arquivo_base.strip_suffix(".txt").unwrap_or(arquivo_base);
    format!("{}_{}.txt", sem_extensao, categoria)
}
// FunÃ§Ã£o para filtrar URLs e salvar as vÃ¡lidas
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
    // LÃª o arquivo de entrada
    let file = File::open(arquivo_entrada)?;
    let reader = BufReader::new(file);
    
    let mut urls_filtradas = Vec::new();
    let mut total_urls = 0;
    let mut linhas_com_erro = 0;
    
    println!("{}[*] Processando arquivo: {}{}", BLUE, arquivo_entrada, RESET);
    if verbose {
        println!("{}[V] Modo verbose ativado{}", MAGENTA, RESET);
        println!("{}[V] VerificaÃ§Ã£o de status: {}{}", MAGENTA, check_status, RESET);
        println!("{}[V] ExploraÃ§Ã£o ativa: {}{}", MAGENTA, explorar, RESET);
        println!("{}[V] ValidaÃ§Ã£o Ollama: {} | Modelo: {}{}", MAGENTA, usar_ollama, modelo_ollama, RESET);
        if let Some(prefix) = &report_prefix {
            println!("{}[V] RelatÃ³rio CSV prefixo: {}{}", MAGENTA, prefix, RESET);
        }
    }
    
    // Filtra as URLs que tÃªm parÃ¢metros e nÃ£o contÃªm as extensÃµes especificadas
    for linha in reader.lines() {
        match linha {
            Ok(url_str) => {
                let url = url_str.trim().to_string();
                total_urls += 1;
                
                if verbose && total_urls % 100 == 0 {
                    println!("{}[V] Processadas {} URLs...", MAGENTA, total_urls);
                }
                
                if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                    if verbose {
                        println!("{}[V] URL vÃ¡lida: {}{}", CYAN, url, RESET);
                    }
                    urls_filtradas.push(url);
                } else if verbose && !url.is_empty() {
                    if tem_extensao_remover(&url) {
                        println!("{}[V] Removida (extensÃ£o): {}{}", YELLOW, url, RESET);
                    } else if !tem_parametros(&url) {
                        println!("{}[V] Removida (sem parÃ¢metros): {}{}", YELLOW, url, RESET);
                    }
                }
            }
            Err(_e) => {
                // Ignora linhas com erro de UTF-8 e continua
                linhas_com_erro += 1;
                total_urls += 1;
                if verbose {
                    println!("{}[V] Erro UTF-8 ignorado na linha {}{}", YELLOW, total_urls, RESET);
                }
            }
        }
    }

    // URLs coletadas via pinchtab
    if let Some(cfg) = pinchtab_cfg {
        if verbose {
            println!("{}[*] Coletando links com pinchtab...{}", CYAN, RESET);
        }
        match coletar_urls_pinchtab(&cfg, verbose) {
            Ok(colhidas) => {
                for url in colhidas {
                    total_urls += 1;
                    if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                        if verbose {
                            println!("{}[V] (pinchtab) URL vÃ¡lida: {}{}", CYAN, url, RESET);
                        }
                        urls_filtradas.push(url);
                    } else if verbose {
                        println!("{}[V] (pinchtab) descartada: {}{}", YELLOW, url, RESET);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}[!] Falha ao usar pinchtab: {}{}", YELLOW, e, RESET);
            }
        }
    }
    
    let removidas = total_urls - urls_filtradas.len();
    
    println!("{}[+] URLs processadas: {}{}", GREEN, total_urls, RESET);
    println!("{}[+] URLs com parÃ¢metros: {}{}", GREEN, urls_filtradas.len(), RESET);
    println!("{}[-] URLs removidas: {}{}", YELLOW, removidas, RESET);
    
    if linhas_com_erro > 0 {
        println!("{}[!] Linhas com erro de encoding UTF-8 (ignoradas): {}{}", YELLOW, linhas_com_erro, RESET);
    }
    
    // Se check_status Ã© true, verifica status HTTP de cada URL
    if check_status {
        println!("{}[*] Verificando status HTTP das URLs...", MAGENTA);
        let mut urls_por_status: HashMap<u16, Vec<String>> = HashMap::new();
        let mut urls_sem_resposta = Vec::new();
        
        for (idx, url) in urls_filtradas.iter().enumerate() {
            if verbose {
                print!("{}[V] Verificando {} ({}/{})", CYAN, url, idx + 1, urls_filtradas.len());
                let _ = std::io::stdout().flush();
            }
            
            match verificar_status_http(url) {
                Some(status) => {
                    if verbose {
                        println!(" -> Status: {}{}", status, RESET);
                    }
                    urls_por_status.entry(status).or_insert_with(Vec::new).push(url.clone());
                }
                None => {
                    if verbose {
                        println!(" -> Sem resposta{}", RESET);
                    }
                    urls_sem_resposta.push(url.clone());
                }
            }
        }
        
        // Salva URLs por status code usando anew
        for (status, urls) in urls_por_status.iter() {
            let arquivo_status = obter_nome_arquivo_status(*status, arquivo_saida);
            let mut child = Command::new("anew")
                .arg(&arquivo_status)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()?;
            
            if let Some(mut stdin) = child.stdin.take() {
                for url in urls.iter() {
                    writeln!(stdin, "{}", url)?
                }
            }
            child.wait()?;
            println!("{}[âœ“] {} URLs com status {} salvas em '{}'{}", GREEN, urls.len(), status, arquivo_status, RESET);
        }
        
        // Salva URLs sem resposta
        if !urls_sem_resposta.is_empty() {
            let arquivo_sem_resposta = arquivo_saida.replace(".txt", "_sem_resposta.txt");
            let mut child = Command::new("anew")
                .arg(&arquivo_sem_resposta)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()?;
            
            if let Some(mut stdin) = child.stdin.take() {
                for url in urls_sem_resposta.iter() {
                    writeln!(stdin, "{}", url)?
                }
            }
            child.wait()?;
            println!("{}[!] {} URLs sem resposta salvas em '{}'{}", YELLOW, urls_sem_resposta.len(), arquivo_sem_resposta, RESET);
        }
    } else {
        // Salva as URLs filtradas no arquivo de saÃ­da usando anew (remove duplicatas)
        let mut child = Command::new("anew")
            .arg(arquivo_saida)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
        
        if let Some(mut stdin) = child.stdin.take() {
            for url in urls_filtradas.iter() {
                writeln!(stdin, "{}", url)?;
            }
        }
        
        child.wait()?;
        println!("{}[âœ“] URLs filtradas salvas em '{}'{}", GREEN, arquivo_saida, RESET);
    }
    
    // ExploraÃ§Ã£o ativa de parÃ¢metros (SQLi / XSS bÃ¡sicos)
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

// Codifica payloads para uso seguro na query string
fn url_encode(texto: &str) -> String {
    texto
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect::<Vec<String>>()
        .join("")
}

// ConstrÃ³i URL com um parÃ¢metro substituÃ­do pelo payload escolhido
fn construir_url_injetada(url: &str, alvo: &str, payload: &str) -> Option<String> {
    let (base, query) = url.split_once('?')?;
    let mut pares: Vec<(String, String)> = query
        .split('&')
        .filter_map(|p| {
            let mut kv = p.splitn(2, '=');
            let k = kv.next()?.to_string();
            let v = kv.next().unwrap_or("").to_string();
            Some((k, v))
        })
        .collect();
    
    let mut alterou = false;
    for (k, v) in pares.iter_mut() {
        if k == alvo {
            *v = url_encode(payload);
            alterou = true;
        }
    }
    
    if !alterou {
        return None;
    }
    
    let nova_query = pares
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");
    
    Some(format!("{}?{}", base, nova_query))
}

fn parece_erro_sql(corpo: &str) -> bool {
    let lower = corpo.to_lowercase();
    SQLI_PADROES_ERRO.iter().any(|padrao| lower.contains(padrao))
}

fn reflexo_xss(corpo: &str, marcador: &str) -> bool {
    corpo.contains(marcador)
}

fn coletar_urls_pinchtab(cfg: &PinchTabConfig, verbose: bool) -> std::io::Result<Vec<String>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if verbose {
        println!("{}[*] Abrindo {} via pinchtab ({}){}", CYAN, cfg.start, cfg.host, RESET);
    }

    let tab_resp: Value = client
        .post(format!("{}/tab", cfg.host))
        .json(&serde_json::json!({"action": "new", "url": cfg.start}))
        .send()
        .and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let tab_id = tab_resp
        .get("tabId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Resposta pinchtab sem tabId"))?
        .to_string();

    let snap: Value = client
        .get(format!("{}/snapshot", cfg.host))
        .query(&[("tabId", tab_id.as_str()), ("filter", "interactive")])
        .send()
        .and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let mut urls = Vec::new();
    coletar_links_json(&snap, &mut urls);
    urls.retain(|u| u.contains('?')); // sÃ³ URLs com parÃ¢metros

    if verbose {
        println!("{}[V] pinchtab retornou {} URLs com '?'.{}", MAGENTA, urls.len(), RESET);
    }
    Ok(urls)
}

fn coletar_links_json(v: &Value, saida: &mut Vec<String>) {
    match v {
        Value::Array(arr) => {
            for item in arr {
                coletar_links_json(item, saida);
            }
        }
        Value::Object(map) => {
            for (_k, val) in map {
                coletar_links_json(val, saida);
            }
            if let Some(href) = map.get("href").and_then(|x| x.as_str()) {
                saida.push(href.to_string());
            }
            if let Some(url) = map.get("url").and_then(|x| x.as_str()) {
                saida.push(url.to_string());
            }
        }
        Value::String(s) => {
            if s.starts_with("http") {
                saida.push(s.to_string());
            }
        }
        _ => {}
    }
}

fn fetch_with_client(client: &Client, url: &str) -> Option<(u16, String)> {
    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            Some((status, body))
        }
        Err(_) => None,
    }
}

struct Achado {
    tipo: &'static str,
    url: String,
    parametro: String,
    payload: String,
    corpo: String,
    llm: Option<String>,
}

struct PinchTabConfig {
    start: String,
    host: String,
}

// Explora ativamente parÃ¢metros identificados nas URLs
// Explora ativamente parâmetros identificados nas URLs (SQLi/XSS/IDOR)
fn explorar_vulnerabilidades(
    urls: &[String],
    verbose: bool,
    usar_ollama: bool,
    modelo: &str,
    report_prefix: Option<&str>,
) -> std::io::Result<()> {
    println!("{}[*] Explorando parâmetros suspeitos (SQLi/XSS/IDOR)...{}", BLUE, RESET);
    let mut total_testes = 0usize;
    let mut achados: Vec<Achado> = Vec::new();
    let mut falhas: Vec<(String, String, String, String)> = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    
    for url in urls {
        if !url.contains('?') {
            continue;
        }
        
        let params: Vec<(String, String)> = url
            .splitn(2, '?')
            .nth(1)
            .unwrap_or("")
            .split('&')
            .filter_map(|p| p.split_once('=') .map(|(k, v)| (k.to_string(), v.to_string())))
            .collect();

        let baseline = fetch_with_client(&client, url);
        
        for (param, valor) in params {
            // SQLi
            for payload in SQLI_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, &param, payload) {
                    total_testes += 1;
                    match fetch_with_client(&client, &test_url) {
                        Some((_status, body)) => {
                            if parece_erro_sql(&body) {
                                println!("{}[!] Possível SQLi em '{}' parâmetro '{}' com payload \"{}\"{}", YELLOW, url, param, payload, RESET);
                                achados.push(Achado {
                                    tipo: "SQLi",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(8000).collect(),
                                    llm: None,
                                });
                            } else {
                                println!("{}[-] Sem indícios SQLi para {} payload {}{}", BLUE, param, payload, RESET);
                            }
                        }
                        None => {
                            println!("{}[!] Falha ao testar {} ({}): sem resposta{}", YELLOW, url, payload, RESET);
                            falhas.push((url.clone(), param.clone(), payload.to_string(), "sem resposta".to_string()));
                        }
                    }
                }
            }
            
            // XSS
            for payload in XSS_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, &param, payload) {
                    total_testes += 1;
                    match fetch_with_client(&client, &test_url) {
                        Some((_status, body)) => {
                            if reflexo_xss(&body, "alert(1337)") {
                                println!("{}[!] Possível XSS refletido em '{}' parâmetro '{}'{}", YELLOW, url, param, RESET);
                                achados.push(Achado {
                                    tipo: "XSS",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(8000).collect(),
                                    llm: None,
                                });
                            } else {
                                println!("{}[-] Sem indícios XSS para {} payload {}{}", BLUE, param, payload, RESET);
                            }
                        }
                        None => {
                            println!("{}[!] Falha ao testar {} ({}): sem resposta{}", YELLOW, url, payload, RESET);
                            falhas.push((url.clone(), param.clone(), payload.to_string(), "sem resposta".to_string()));
                        }
                    }
                }
            }

            // IDOR (valores numéricos)
            if let Ok(orig) = valor.parse::<i64>() {
                if let Some((status_base, corpo_base)) = &baseline {
                    for delta in IDOR_DELTAS {
                        let novo_valor = (orig + delta).to_string();
                        if let Some(test_url) = construir_url_injetada(url, &param, &novo_valor) {
                            total_testes += 1;
                            match fetch_with_client(&client, &test_url) {
                                Some((status, body)) => {
                                    let diff = (body.len() as isize - corpo_base.len() as isize).abs();
                                    if status == *status_base && diff > 50 {
                                        println!("{}[!] Possível IDOR em '{}' param '{}' ({} -> {}){}", YELLOW, url, param, valor, novo_valor, RESET);
                                        achados.push(Achado {
                                            tipo: "IDOR",
                                            url: url.clone(),
                                            parametro: param.clone(),
                                            payload: novo_valor,
                                            corpo: body.chars().take(8000).collect(),
                                            llm: None,
                                        });
                                    } else if verbose {
                                        println!("{}[-] Sem indício IDOR {} delta {} (status {} len diff {}){}", BLUE, param, delta, status, diff, RESET);
                                    }
                                }
                                None => {
                                    println!("{}[!] Falha IDOR {} ({}): sem resposta{}", YELLOW, url, delta, RESET);
                                    falhas.push((url.clone(), param.clone(), format!("IDOR {}", delta), "sem resposta".to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    println!("{}[+] Testes ativos executados: {}{}", GREEN, total_testes, RESET);
    if achados.is_empty() {
        println!("{}[-] Nenhum comportamento suspeito detectado nos testes básicos.{}", BLUE, RESET);
    }

    if usar_ollama && !achados.is_empty() {
        validar_com_ollama(modelo, &mut achados, verbose)?;
    } else if usar_ollama {
        println!("{}[LLM] Nenhum achado para validar com Ollama.{}", BLUE, RESET);
    }

    if let Some(prefix) = report_prefix {
        salvar_relatorios(prefix, &achados, &falhas)?;
    }
    
    Ok(())
}
fn validar_com_ollama(modelo: &str, achados: &mut [Achado], verbose: bool) -> std::io::Result<()> {
    println!("{}[*] Validando achados com Ollama (modelo: {}){}", CYAN, modelo, RESET);
    for achado in achados.iter_mut() {
        let prompt = format!(
            "Classifique rapidamente se este achado de seguranÃ§a Ã© provavelmente verdadeiro ou falso positivo.\n\
Tipo: {tipo}\nURL: {url}\nParÃ¢metro: {param}\nPayload: {payload}\nTrecho de resposta (pode estar truncado):\n{corpo}\n\
Responda somente com 'true_positive' ou 'false_positive' e uma curta justificativa em portuguÃªs.",
            tipo = achado.tipo,
            url = achado.url,
            param = achado.parametro,
            payload = achado.payload,
            corpo = achado.corpo
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
                let output = child.wait_with_output();
                match output {
                    Ok(out) => {
                        let resposta = String::from_utf8_lossy(&out.stdout);
                        println!("{}[LLM] {} -> {}{}", GREEN, achado.url, resposta.trim(), RESET);
                        achado.llm = Some(resposta.trim().to_string());
                    }
                    Err(e) => {
                        eprintln!("{}[LLM] Falha ao ler saÃ­da: {}{}", YELLOW, e, RESET);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}[LLM] NÃ£o foi possÃ­vel executar ollama: {}{}", YELLOW, e, RESET);
                if verbose {
                    eprintln!("{}[V] Instale ollama ou remova --ollama para continuar sem validaÃ§Ã£o.{}", YELLOW, RESET);
                }
            }
        }
    }
    Ok(())
}

fn salvar_relatorios(prefix: &str, achados: &[Achado], falhas: &[(String, String, String, String)]) -> std::io::Result<()> {
    use std::io::Write as _;

    let achados_path = format!("{}_achados.csv", prefix);
    let falhas_path = format!("{}_falhas.csv", prefix);

    // Achados
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
                escape_csv(a.llm.as_deref().unwrap_or(""))
            )?;
        }
    }

    // Falhas
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
                escape_csv(err)
            )?;
        }
    }

    println!("{}[âœ“] RelatÃ³rios salvos em '{}' e '{}'{}", GREEN, achados_path, falhas_path, RESET);
    Ok(())
}

fn escape_csv(texto: &str) -> String {
    texto.replace('\"', "\"\"")
}

// FunÃ§Ã£o para executar subfinder
fn executar_subfinder(domain: &str, arquivo_saida: &str) -> std::io::Result<()> {
    println!("{}[*] Executando subfinder para: {}{}", MAGENTA, domain, RESET);
    
    let output = Command::new("subfinder")
        .arg("-d")
        .arg(domain)
        .arg("-all")
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[âœ—] Erro ao executar subfinder{}", RED, RESET);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Subfinder falhou"));
    }
    
    let mut file = File::create(arquivo_saida)?;
    file.write_all(&output.stdout)?;
    
    let linhas = String::from_utf8_lossy(&output.stdout).lines().count();
    println!("{}[+] {} subdomÃ­nios encontrados{}", GREEN, linhas, RESET);
    
    Ok(())
}

// FunÃ§Ã£o para executar katana em um arquivo de domÃ­nios
fn executar_katana(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando katana para crawling{}", MAGENTA, RESET);
    
    let output = Command::new("katana")
        .arg("-list")
        .arg(arquivo_subs)
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[!] Aviso: Katana pode nÃ£o estar instalado ou falhou{}", YELLOW, RESET);
    }
    
    let mut file = File::create(arquivo_urls)?;
    file.write_all(&output.stdout)?;
    
    let linhas = String::from_utf8_lossy(&output.stdout).lines().count();
    println!("{}[+] {} URLs encontradas com katana{}", GREEN, linhas, RESET);
    
    Ok(())
}

// FunÃ§Ã£o para executar urlfinder em um arquivo de domÃ­nios
fn executar_urlfinder(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando urlfinder para extraÃ§Ã£o de URLs{}", MAGENTA, RESET);
    
    let output = Command::new("urlfinder")
        .arg("-i")
        .arg(arquivo_subs)
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[!] Aviso: urlfinder pode nÃ£o estar instalado ou falhou{}", YELLOW, RESET);
    }
    
    // Mescla com arquivo anterior de katana
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(arquivo_urls)?;
    
    file.write_all(&output.stdout)?;
    
    let linhas = String::from_utf8_lossy(&output.stdout).lines().count();
    println!("{}[+] {} URLs encontradas com urlfinder{}", GREEN, linhas, RESET);
    
    Ok(())
}

// FunÃ§Ã£o para processar um domÃ­nio Ãºnico
fn processar_domain_unico(domain: &str) {
    println!("{}[*] Iniciando processo para domÃ­nio: {}{}\n", CYAN, domain, RESET);
    
    let subs_file = "dominios_temp.txt";
    let urls_file = "urls_temp.txt";
    let resultado_file = format!("{}_urls_filtradas.txt", domain);
    
    // Execute subfinder
    if let Err(e) = executar_subfinder(domain, subs_file) {
        eprintln!("{}[âœ—] Erro no subfinder: {}{}", RED, e, RESET);
        process::exit(1);
    }
    
    // Execute katana
    if let Err(e) = executar_katana(subs_file, urls_file) {
        eprintln!("{}[!] Aviso ao executar katana: {}{}", YELLOW, e, RESET);
    }
    
    // Execute urlfinder
    if let Err(e) = executar_urlfinder(subs_file, urls_file) {
        eprintln!("{}[!] Aviso ao executar urlfinder: {}{}", YELLOW, e, RESET);
    }
    
    println!("\n{}[*] Iniciando filtragem de URLs{}\n", BLUE, RESET);
    
    // Filtra as URLs
    if let Err(e) = filtrar_urls(urls_file, &resultado_file, false, false, false, false, OLLAMA_MODEL_DEFAULT, None) {
        eprintln!("{}[âœ—] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }
    
    // Limpa arquivos temporÃ¡rios
    let _ = std::fs::remove_file(subs_file);
    let _ = std::fs::remove_file(urls_file);
    
    println!("{}[âœ“] Processo concluÃ­do! Resultados em: {}{}", GREEN, resultado_file, RESET);
}

// FunÃ§Ã£o para processar uma lista de domÃ­nios
fn processar_lista_dominios(arquivo_subs: &str) {
    println!("{}[*] Iniciando processo para lista de subdomÃ­nios: {}{}\n", CYAN, arquivo_subs, RESET);
    
    let urls_file = "urls_crawled.txt";
    let resultado_file = "urls_filtradas_lote.txt";
    
    // Tenta ler o arquivo de subs
    if let Ok(file) = File::open(arquivo_subs) {
        let reader = BufReader::new(file);
        let total_subs: usize = reader.lines().count();
        println!("{}[+] {} subdomÃ­nios para processar{}", GREEN, total_subs, RESET);
    }
    
    // Execute katana
    if let Err(e) = executar_katana(arquivo_subs, urls_file) {
        eprintln!("{}[!] Aviso ao executar katana: {}{}", YELLOW, e, RESET);
    }
    
    // Execute urlfinder
    if let Err(e) = executar_urlfinder(arquivo_subs, urls_file) {
        eprintln!("{}[!] Aviso ao executar urlfinder: {}{}", YELLOW, e, RESET);
    }
    
    println!("\n{}[*] Iniciando filtragem de URLs{}\n", BLUE, RESET);
    
    // Filtra as URLs
    if let Err(e) = filtrar_urls(urls_file, resultado_file, false, false, false, false, OLLAMA_MODEL_DEFAULT, None) {
        eprintln!("{}[âœ—] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }
    
    // Limpa arquivos temporÃ¡rios
    let _ = std::fs::remove_file(urls_file);
    
    println!("{}[âœ“] Processo concluÃ­do! Resultados em: {}{}", GREEN, resultado_file, RESET);
}

// FunÃ§Ã£o para tratar os argumentos da linha de comando
fn processar_argumentos() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    let diretorio_atual = env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    
    // Processa a flag -l para o arquivo de entrada
    let arquivo_entrada = if let Some(pos) = args.iter().position(|x| x == "-l") {
        if pos + 1 < args.len() {
            let mut caminho = args[pos + 1].clone();
            
            // Se o caminho nÃ£o for absoluto, adiciona o diretÃ³rio atual
            let path = PathBuf::from(&caminho);
            if !path.is_absolute() {
                caminho = PathBuf::from(&diretorio_atual)
                    .join(&caminho)
                    .to_string_lossy()
                    .into_owned();
            }
            
            caminho
        } else {
            eprintln!("{}[âœ—] Erro: Caminho do arquivo de entrada nÃ£o especificado apÃ³s a flag -l.{}", RED, RESET);
            eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
            process::exit(1);
        }
    } else {
        eprintln!("{}[âœ—] Erro: A flag -l deve ser utilizada para passar o arquivo de entrada.{}", RED, RESET);
        eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
        process::exit(1);
    };
    
    // Processa a flag -o para o arquivo de saÃ­da
    let arquivo_saida = if let Some(pos) = args.iter().position(|x| x == "-o") {
        if pos + 1 < args.len() {
            args[pos + 1].clone()
        } else {
            eprintln!("{}[âœ—] Erro: Caminho do arquivo de saÃ­da nÃ£o especificado apÃ³s a flag -o.{}", RED, RESET);
            eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
            process::exit(1);
        }
    } else {
        String::from("urls_parametros.txt")
    };
    
    (arquivo_entrada, arquivo_saida)
}
