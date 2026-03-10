use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::collections::HashMap;

// Versionamento
const VERSION: &str = "1.0.0";

// Padrões de parâmetros com potencial para vulnerabilidades
const PARAMETROS_SUSPEITOS: &[&str] = &[
    // SQL Injection
    "id", "user_id", "product_id", "post_id", "page", "num", "limit", "offset",
    "sort", "order", "search", "q", "query", "keyword", "filter", "where", "select",
    
    // XSS (Cross-Site Scripting)
    "message", "msg", "comment", "text", "content", "input", "data", "name",
    "title", "description", "email", "subject", "body", "template",
    
    // LFI/RFI (Local/Remote File Inclusion)
    "file", "path", "dir", "include", "load", "page", "template", "view",
    "action", "module", "plugin", "theme", "skin",
    
    // SSRF (Server-Side Request Forgery)
    "url", "uri", "redirect", "return", "return_to", "redirect_to", "goto",
    "next", "target", "proxy", "fetch", "load_url",
    
    // Command Injection
    "cmd", "command", "exec", "execute", "process", "run", "system",
    
    // Path Traversal
    "filename", "filepath", "document", "resource", "asset",
    
    // Open Redirect
    "link", "href", "ref", "from", "back", "continue",
];
const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN: &str = "\x1b[96m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

// Configuração de LLM local (Ollama)
const OLLAMA_MODEL_DEFAULT: &str = "phi3:mini"; // modelo leve e rápido

// Payloads e padrões para exploração ativa
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

fn main() {
    let args: Vec<String> = env::args().collect();
    
    mostrar_banner();
    
    // Verifica se a ferramenta está atualizada - SEMPRE executa
    verificar_atualizacoes();
    
    // Verifica se é solicitado help
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        mostrar_help();
        return;
    }
    
    // Verifica se é solicitado update
    if args.contains(&"-up".to_string()) || args.contains(&"--update".to_string()) {
        atualizar_ferramenta();
        return;
    }
    
    // Verifica as flags globais
    let verbose = args.contains(&"-v".to_string()) || args.contains(&"--verbose".to_string());
    let check_status = args.contains(&"-status".to_string()) || args.contains(&"--status".to_string());
    let explorar = args.contains(&"-p".to_string()) || args.contains(&"--explore".to_string());
    let usar_ollama = args.contains(&"--ollama".to_string());
    let modelo_ollama = args
        .windows(2)
        .find(|w| w[0] == "--ollama-model")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| OLLAMA_MODEL_DEFAULT.to_string());
    
    // Verifica se é passado um domínio único (-d)
    if let Some(pos) = args.iter().position(|x| x == "-d") {
        if pos + 1 < args.len() {
            let domain = &args[pos + 1];
            processar_domain_unico(domain);
        } else {
            eprintln!("{}[✗] Erro: Domínio não especificado após a flag -d.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }
    
    // Verifica se é passado um arquivo com lista de domínios (-f)
    if let Some(pos) = args.iter().position(|x| x == "-f") {
        if pos + 1 < args.len() {
            let arquivo_subs = &args[pos + 1];
            processar_lista_dominios(arquivo_subs);
        } else {
            eprintln!("{}[✗] Erro: Arquivo com lista de subdomínios não especificado após a flag -f.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }
    
    // Modo padrão: apenas filtrar URLs passadas por -l
    let (arquivo_entrada, arquivo_saida) = processar_argumentos();
    
    if let Err(e) = filtrar_urls(&arquivo_entrada, &arquivo_saida, verbose, check_status, explorar, usar_ollama, &modelo_ollama) {
        eprintln!("{}[✗] Erro ao processar o arquivo: {}{}", RED, e, RESET);
        process::exit(1);
    }
}

// Lista de extensões de arquivos a serem removidas
const EXTENSOES_REMOVER: &[&str] = &[
    // Imagens
    "jpg", "jpeg", "gif", "png", "tif", "tiff", "bmp", "svg", "ico", "webp",
    // Documentos
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "zip", "rar", "7z",
    // Estilos e Scripts
    "css", "js", "json", "xml", "yaml", "yml",
    // Fontes
    "ttf", "woff", "woff2", "eot", "otf", "font",
    // Áudio e Vídeo
    "mp3", "mp4", "avi", "mov", "flv", "wav", "m4a",
    // Executáveis
    "exe", "dll", "so", "dylib",
    // Mapas
    "map",
];

// Função para mostrar o banner
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
    println!("{}════════════════════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!("{}             ✓ Developed by: 0x13-ByteZer0{}", GREEN, RESET);
    println!("{}═════════════════════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!("{}", RESET);
    println!();
}

// Função para mostrar a ajuda
fn mostrar_help() {
    println!("{}Uso:{} paramstrike [OPÇÃO] [ARGUMENTOS]\n", BOLD, RESET);
    
    println!("{}Opções:{}", BOLD, RESET);
    println!("  {}  -l <arquivo>{}    Arquivo de entrada com URLs (obrigatório para modo padrão)", YELLOW, RESET);
    println!("  {}  -o <arquivo>{}    Arquivo de saída (padrão: urls_parametros.txt)", YELLOW, RESET);
    println!("  {}  -d <domain>{}     Domínio único - executar subfinder, katana e urlfinder", CYAN, RESET);
    println!("  {}  -f <arquivo>{}    Arquivo com lista de subdomínios para crawler", CYAN, RESET);
    println!("  {}  -v, --verbose{}   Modo verbose (mostra fluxo de processamento)", MAGENTA, RESET);
    println!("  {}  -status{}          Verificar status HTTP e salvar em arquivos separados", MAGENTA, RESET);
    println!("  {}  -p, --explore{}   Explorar ativamente os parâmetros (SQLi/XSS básicos)", MAGENTA, RESET);
    println!("  {}  --ollama{}         Validar achados com Ollama (desliga falsos positivos)", MAGENTA, RESET);
    println!("  {}  --ollama-model <m>{} Modelo Ollama (padrão: {})", MAGENTA, RESET, OLLAMA_MODEL_DEFAULT);
    println!("  {}  -up, --update{}   Atualizar a ferramenta do Git e recompilar", MAGENTA, RESET);
    println!("  {}  -h, --help{}      Mostra esta mensagem de ajuda\n", YELLOW, RESET);
    
    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}Modo padrão (filtrar URLs):{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt{}", GREEN, RESET);
    println!("  {}Com exploração ativa de parâmetros:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -p{}", GREEN, RESET);
    println!("  {}Com exploração + validação no LLM local:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -p --ollama --ollama-model {}{}", GREEN, OLLAMA_MODEL_DEFAULT, RESET);
    println!("  {}Com verbose e verificação de status:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -v -status{}", GREEN, RESET);
    println!("  {}Atualizar ferramenta:{}", GREEN, RESET);
    println!("    {}$ paramstrike -up{}", GREEN, RESET);
    println!("  {}Modo domínio único:{}", GREEN, RESET);
    println!("    {}$ paramstrike -d example.com{}", GREEN, RESET);
    println!("  {}Modo lista de subdomínios:{}", GREEN, RESET);
    println!("    {}$ paramstrike -f subs.txt{}\n", GREEN, RESET);
}

// Função para obter a versão atual do repositório (lê do arquivo VERSION na raiz)
fn obter_versao_repositorio() -> Option<String> {
    match std::fs::read_to_string("VERSION") {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

// Função para ler a versão salva localmente
fn ler_versao_salva() -> Option<String> {
    match std::fs::read_to_string(".version") {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

// Função para salvar a versão localmente
fn salvar_versao(versao: &str) -> std::io::Result<()> {
    std::fs::write(".version", versao)
}

// Função para verificar se há atualizações disponíveis
fn verificar_atualizacoes() {
    // Lê a versão do arquivo VERSION (source of truth)
    let versao_local = match std::fs::read_to_string("VERSION") {
        Ok(content) => content.trim().to_string(),
        Err(_) => VERSION.to_string(), // fallback para a constante
    };
    
    // Versão no repositório (ou versão salva se estivemos offline)
    let versao_salva = ler_versao_salva();
    
    match versao_salva {
        Some(salva) => {
            if versao_local != salva {
                // Versão desatualizada
                println!("{}╔═══════════════════════════════════════════════════════════════╗{}", YELLOW, RESET);
                println!("{}║                                                               ║{}", YELLOW, RESET);
                println!("{}║  {}⚠  FERRAMENTA DESATUALIZADA!                          {}║{}", YELLOW, RED, YELLOW, RESET);
                println!("{}║                                                               ║{}", YELLOW, RESET);
                println!("{}║  {}Versão atual: {} | Versão instalada: {}{}      {}║{}", YELLOW, CYAN, versao_local, salva, YELLOW, YELLOW, RESET);
                println!("{}║                                                               ║{}", YELLOW, RESET);
                println!("{}║  {}Nova versão disponível. Execute para atualizar:  {}║{}", YELLOW, CYAN, YELLOW, RESET);
                println!("{}║                                                               ║{}", YELLOW, RESET);
                println!("{}║         {}$ paramstrike -up                             {}║{}", YELLOW, BOLD, YELLOW, RESET);
                println!("{}║                                                               ║{}", YELLOW, RESET);
                println!("{}╚═══════════════════════════════════════════════════════════════╝{}", YELLOW, RESET);
                println!();
            } else {
                // Versão atualizada
                println!("{}╔═══════════════════════════════════════════════════════════════╗{}", GREEN, RESET);
                println!("{}║                                                               ║{}", GREEN, RESET);
                println!("{}║  {}✓  FERRAMENTA ATUALIZADA{}                                   {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
                println!("{}║                                                               ║{}", GREEN, RESET);
                println!("{}║         {}Versão: {}{}                                         {}║{}", GREEN, BOLD, versao_local, RESET, GREEN, RESET);
                println!("{}║                                                               ║{}", GREEN, RESET);
                println!("{}╚═══════════════════════════════════════════════════════════════╝{}", GREEN, RESET);
                println!();
            }
        }
        None => {
            // Primeira execução - salva a versão
            println!("{}[*] Primeira execução - salvando versão {}{}", BLUE, versao_local, RESET);
            let _ = salvar_versao(&versao_local);
            println!("{}╔═══════════════════════════════════════════════════════════════╗{}", GREEN, RESET);
            println!("{}║                                                               ║{}", GREEN, RESET);
            println!("{}║  {}✓  FERRAMENTA ATUALIZADA{}                                   {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
            println!("{}║                                                               ║{}", GREEN, RESET);
            println!("{}║         {}Versão: {}{}                                         {}║{}", GREEN, BOLD, versao_local, RESET, GREEN, RESET);
            println!("{}║                                                               ║{}", GREEN, RESET);
            println!("{}╚═══════════════════════════════════════════════════════════════╝{}", GREEN, RESET);
            println!();
        }
    }
}


// Função para verificar se a URL contém uma das extensões especificadas
fn tem_extensao_remover(url: &str) -> bool {
    let url = url.trim().to_lowercase();
    
    // Extrai só o path, antes dos parâmetros (?)
    let path = url.split('?').next().unwrap_or(&url);
    
    for ext in EXTENSOES_REMOVER {
        if path.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    false
}
// Função para verificar se a URL contém parâmetros
fn tem_parametros(url: &str) -> bool {
    url.contains('?')
}

// Função para verificar o status HTTP de uma URL
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

// Função para atualizar a ferramenta do Git e recompilar
fn atualizar_ferramenta() {
    println!("{}╔═══════════════════════════════════════════════════════════════╗{}", BLUE, RESET);
    println!("{}║           {}INICIANDO PROCESSO DE ATUALIZAÇÃO{}                       {}║{}", BLUE, BOLD, RESET, BLUE, RESET);
    println!("{}╚═══════════════════════════════════════════════════════════════╝{}", BLUE, RESET);
    println!();
    
    // Executa git pull
    println!("{}[1/2] Realizando git pull...{}", CYAN, RESET);
    println!("{}─────────────────────────────────────────────────────────────────{}", MAGENTA, RESET);
    let git_output = Command::new("git")
        .arg("pull")
        .output();
    
    match git_output {
        Ok(output) => {
            if output.status.success() {
                let msg = String::from_utf8_lossy(&output.stdout);
                println!("{}✓ Git pull concluído com sucesso!{}", GREEN, RESET);
                if !msg.trim().is_empty() {
                    println!("{}{}{}", CYAN, msg, RESET);
                }
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                eprintln!("{}✗ Erro ao executar git pull:{}", RED, RESET);
                eprintln!("{}{}{}", YELLOW, err, RESET);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}✗ Erro ao executar git: {}{}", RED, e, RESET);
            process::exit(1);
        }
    }
    
    println!();
    
    // Lê a versão do repositório após o pull (fonte de verdade)
    let versao_repo = obter_versao_repositorio().unwrap_or_else(|| VERSION.to_string());
    
    // Executa cargo build --release
    println!("{}[2/2] Compilando com cargo...{}", CYAN, RESET);
    println!("{}─────────────────────────────────────────────────────────────────{}", MAGENTA, RESET);
    let cargo_output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .output();
    
    match cargo_output {
        Ok(output) => {
            if output.status.success() {
                println!("{}✓ Compilação concluída com sucesso!{}", GREEN, RESET);
                let msg = String::from_utf8_lossy(&output.stdout);
                if !msg.trim().is_empty() {
                    println!("{}{}{}", CYAN, msg, RESET);
                }
                println!();
                
                // Sincroniza .version com a versão do repositório, sem modificar VERSION
                match salvar_versao(&versao_repo) {
                    Ok(_) => println!("{}[✓] Versão sincronizada: {}{}", GREEN, versao_repo, RESET);
                    Err(e) => eprintln!("{}[!] Aviso ao salvar .version: {}{}", YELLOW, e, RESET),
                }
                
                println!();
                println!("{}╔═══════════════════════════════════════════════════════════════╗{}", BLUE, RESET);
                println!("{}║                                                               ║{}", BLUE, RESET);
                println!("{}║  {}✓  ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!{}                     {}║{}", BLUE, GREEN, RESET, BLUE, RESET);
                println!("{}║                                                               ║{}", BLUE, RESET);
                println!("{}║         {}→ Versão: {}{}                                   {}║{}", BLUE, BOLD, versao_repo, RESET, BLUE, RESET);
                println!("{}║         {}→ Status: RECOMPILADO{}                              {}║{}", BLUE, BOLD, RESET, BLUE, RESET);
                println!("{}║                                                               ║{}", BLUE, RESET);
                println!("{}╚═══════════════════════════════════════════════════════════════╝{}", BLUE, RESET);
                println!();
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                eprintln!("{}[✗] Erro ao compilar:{}", RED, RESET);
                eprintln!("{}{}{}", YELLOW, err, RESET);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}[✗] Erro ao executar cargo: {}{}", RED, e, RESET);
            eprintln!("{}Certifique-se de que Rust está instalado e no PATH.{}", YELLOW, RESET);
            process::exit(1);
        }
    }
}


// Função para obter nome do arquivo baseado no status code
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
// Função para filtrar URLs e salvar as válidas
fn filtrar_urls(
    arquivo_entrada: &str,
    arquivo_saida: &str,
    verbose: bool,
    check_status: bool,
    explorar: bool,
    usar_ollama: bool,
    modelo_ollama: &str,
) -> std::io::Result<()> {
    // Lê o arquivo de entrada
    let file = File::open(arquivo_entrada)?;
    let reader = BufReader::new(file);
    
    let mut urls_filtradas = Vec::new();
    let mut total_urls = 0;
    let mut linhas_com_erro = 0;
    
    println!("{}[*] Processando arquivo: {}{}", BLUE, arquivo_entrada, RESET);
    if verbose {
        println!("{}[V] Modo verbose ativado{}", MAGENTA, RESET);
        println!("{}[V] Verificação de status: {}{}", MAGENTA, check_status, RESET);
        println!("{}[V] Exploração ativa: {}{}", MAGENTA, explorar, RESET);
        println!("{}[V] Validação Ollama: {} | Modelo: {}{}", MAGENTA, usar_ollama, modelo_ollama, RESET);
    }
    
    // Filtra as URLs que têm parâmetros e não contêm as extensões especificadas
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
                        println!("{}[V] URL válida: {}{}", CYAN, url, RESET);
                    }
                    urls_filtradas.push(url);
                } else if verbose && !url.is_empty() {
                    if tem_extensao_remover(&url) {
                        println!("{}[V] Removida (extensão): {}{}", YELLOW, url, RESET);
                    } else if !tem_parametros(&url) {
                        println!("{}[V] Removida (sem parâmetros): {}{}", YELLOW, url, RESET);
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
    
    let removidas = total_urls - urls_filtradas.len();
    
    println!("{}[+] URLs processadas: {}{}", GREEN, total_urls, RESET);
    println!("{}[+] URLs com parâmetros: {}{}", GREEN, urls_filtradas.len(), RESET);
    println!("{}[-] URLs removidas: {}{}", YELLOW, removidas, RESET);
    
    if linhas_com_erro > 0 {
        println!("{}[!] Linhas com erro de encoding UTF-8 (ignoradas): {}{}", YELLOW, linhas_com_erro, RESET);
    }
    
    // Se check_status é true, verifica status HTTP de cada URL
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
            println!("{}[✓] {} URLs com status {} salvas em '{}'{}", GREEN, urls.len(), status, arquivo_status, RESET);
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
        // Salva as URLs filtradas no arquivo de saída usando anew (remove duplicatas)
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
        println!("{}[✓] URLs filtradas salvas em '{}'{}", GREEN, arquivo_saida, RESET);
    }
    
    // Exploração ativa de parâmetros (SQLi / XSS básicos)
    if explorar {
        explorar_vulnerabilidades(&urls_filtradas, verbose, usar_ollama, modelo_ollama)?;
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

// Constrói URL com um parâmetro substituído pelo payload escolhido
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

struct Achado {
    tipo: &'static str,
    url: String,
    parametro: String,
    payload: String,
    corpo: String,
}

// Explora ativamente parâmetros identificados nas URLs
fn explorar_vulnerabilidades(urls: &[String], verbose: bool, usar_ollama: bool, modelo: &str) -> std::io::Result<()> {
    println!("{}[*] Explorando parâmetros suspeitos (SQLi/XSS)...{}", BLUE, RESET);
    let mut total_testes = 0usize;
    let mut achados: Vec<Achado> = Vec::new();
    
    for url in urls {
        if !url.contains('?') {
            continue;
        }
        
        let params: Vec<String> = url
            .splitn(2, '?')
            .nth(1)
            .unwrap_or("")
            .split('&')
            .filter_map(|p| p.split_once('=').map(|(k, _)| k.to_string()))
            .collect();
        
        for param in params {
            // SQLi
            for payload in SQLI_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, &param, payload) {
                    total_testes += 1;
                    match Command::new("curl")
                        .arg("-s")
                        .arg("--max-time")
                        .arg("8")
                        .arg(&test_url)
                        .output()
                    {
                        Ok(out) => {
                            let body = String::from_utf8_lossy(&out.stdout);
                            if parece_erro_sql(&body) {
                                println!("{}[!] Possível SQLi em '{}' parâmetro '{}' com payload \"{}\"{}", YELLOW, url, param, payload, RESET);
                                achados.push(Achado {
                                    tipo: "SQLi",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(8000).collect(),
                                });
                            } else if verbose {
                                println!("{}[V] Testado SQLi {}={}{}", MAGENTA, param, payload, RESET);
                            }
                        }
                        Err(e) => {
                            if verbose {
                                println!("{}[V] Falha ao testar {}: {}{}", YELLOW, url, e, RESET);
                            }
                        }
                    }
                }
            }
            
            // XSS
            for payload in XSS_PAYLOADS {
                if let Some(test_url) = construir_url_injetada(url, &param, payload) {
                    total_testes += 1;
                    match Command::new("curl")
                        .arg("-s")
                        .arg("--max-time")
                        .arg("8")
                        .arg(&test_url)
                        .output()
                    {
                        Ok(out) => {
                            let body = String::from_utf8_lossy(&out.stdout);
                            if reflexo_xss(&body, "alert(1337)") {
                                println!("{}[!] Possível XSS refletido em '{}' parâmetro '{}'{}", YELLOW, url, param, RESET);
                                achados.push(Achado {
                                    tipo: "XSS",
                                    url: url.clone(),
                                    parametro: param.clone(),
                                    payload: payload.to_string(),
                                    corpo: body.chars().take(8000).collect(),
                                });
                            } else if verbose {
                                println!("{}[V] Testado XSS {}={}{}", MAGENTA, param, payload, RESET);
                            }
                        }
                        Err(e) => {
                            if verbose {
                                println!("{}[V] Falha ao testar {}: {}{}", YELLOW, url, e, RESET);
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
        validar_com_ollama(modelo, &achados, verbose)?;
    }
    
    Ok(())
}

fn validar_com_ollama(modelo: &str, achados: &[Achado], verbose: bool) -> std::io::Result<()> {
    println!("{}[*] Validando achados com Ollama (modelo: {}){}", CYAN, modelo, RESET);
    for achado in achados {
        let prompt = format!(
            "Classifique rapidamente se este achado de segurança é provavelmente verdadeiro ou falso positivo.\n\
Tipo: {tipo}\nURL: {url}\nParâmetro: {param}\nPayload: {payload}\nTrecho de resposta (pode estar truncado):\n{corpo}\n\
Responda somente com 'true_positive' ou 'false_positive' e uma curta justificativa em português.",
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
                    }
                    Err(e) => {
                        eprintln!("{}[LLM] Falha ao ler saída: {}{}", YELLOW, e, RESET);
                    }
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

// Função para executar subfinder
fn executar_subfinder(domain: &str, arquivo_saida: &str) -> std::io::Result<()> {
    println!("{}[*] Executando subfinder para: {}{}", MAGENTA, domain, RESET);
    
    let output = Command::new("subfinder")
        .arg("-d")
        .arg(domain)
        .arg("-all")
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[✗] Erro ao executar subfinder{}", RED, RESET);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Subfinder falhou"));
    }
    
    let mut file = File::create(arquivo_saida)?;
    file.write_all(&output.stdout)?;
    
    let linhas = String::from_utf8_lossy(&output.stdout).lines().count();
    println!("{}[+] {} subdomínios encontrados{}", GREEN, linhas, RESET);
    
    Ok(())
}

// Função para executar katana em um arquivo de domínios
fn executar_katana(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando katana para crawling{}", MAGENTA, RESET);
    
    let output = Command::new("katana")
        .arg("-list")
        .arg(arquivo_subs)
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[!] Aviso: Katana pode não estar instalado ou falhou{}", YELLOW, RESET);
    }
    
    let mut file = File::create(arquivo_urls)?;
    file.write_all(&output.stdout)?;
    
    let linhas = String::from_utf8_lossy(&output.stdout).lines().count();
    println!("{}[+] {} URLs encontradas com katana{}", GREEN, linhas, RESET);
    
    Ok(())
}

// Função para executar urlfinder em um arquivo de domínios
fn executar_urlfinder(arquivo_subs: &str, arquivo_urls: &str) -> std::io::Result<()> {
    println!("{}[*] Executando urlfinder para extração de URLs{}", MAGENTA, RESET);
    
    let output = Command::new("urlfinder")
        .arg("-i")
        .arg(arquivo_subs)
        .output()?;
    
    if !output.status.success() {
        eprintln!("{}[!] Aviso: urlfinder pode não estar instalado ou falhou{}", YELLOW, RESET);
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

// Função para processar um domínio único
fn processar_domain_unico(domain: &str) {
    println!("{}[*] Iniciando processo para domínio: {}{}\n", CYAN, domain, RESET);
    
    let subs_file = "dominios_temp.txt";
    let urls_file = "urls_temp.txt";
    let resultado_file = format!("{}_urls_filtradas.txt", domain);
    
    // Execute subfinder
    if let Err(e) = executar_subfinder(domain, subs_file) {
        eprintln!("{}[✗] Erro no subfinder: {}{}", RED, e, RESET);
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
    if let Err(e) = filtrar_urls(urls_file, &resultado_file, false, false, false, false, OLLAMA_MODEL_DEFAULT) {
        eprintln!("{}[✗] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }
    
    // Limpa arquivos temporários
    let _ = std::fs::remove_file(subs_file);
    let _ = std::fs::remove_file(urls_file);
    
    println!("{}[✓] Processo concluído! Resultados em: {}{}", GREEN, resultado_file, RESET);
}

// Função para processar uma lista de domínios
fn processar_lista_dominios(arquivo_subs: &str) {
    println!("{}[*] Iniciando processo para lista de subdomínios: {}{}\n", CYAN, arquivo_subs, RESET);
    
    let urls_file = "urls_crawled.txt";
    let resultado_file = "urls_filtradas_lote.txt";
    
    // Tenta ler o arquivo de subs
    if let Ok(file) = File::open(arquivo_subs) {
        let reader = BufReader::new(file);
        let total_subs: usize = reader.lines().count();
        println!("{}[+] {} subdomínios para processar{}", GREEN, total_subs, RESET);
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
    if let Err(e) = filtrar_urls(urls_file, resultado_file, false, false, false, false, OLLAMA_MODEL_DEFAULT) {
        eprintln!("{}[✗] Erro ao filtrar URLs: {}{}", RED, e, RESET);
        process::exit(1);
    }
    
    // Limpa arquivos temporários
    let _ = std::fs::remove_file(urls_file);
    
    println!("{}[✓] Processo concluído! Resultados em: {}{}", GREEN, resultado_file, RESET);
}

// Função para tratar os argumentos da linha de comando
fn processar_argumentos() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    let diretorio_atual = env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    
    // Processa a flag -l para o arquivo de entrada
    let arquivo_entrada = if let Some(pos) = args.iter().position(|x| x == "-l") {
        if pos + 1 < args.len() {
            let mut caminho = args[pos + 1].clone();
            
            // Se o caminho não for absoluto, adiciona o diretório atual
            let path = PathBuf::from(&caminho);
            if !path.is_absolute() {
                caminho = PathBuf::from(&diretorio_atual)
                    .join(&caminho)
                    .to_string_lossy()
                    .into_owned();
            }
            
            caminho
        } else {
            eprintln!("{}[✗] Erro: Caminho do arquivo de entrada não especificado após a flag -l.{}", RED, RESET);
            eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
            process::exit(1);
        }
    } else {
        eprintln!("{}[✗] Erro: A flag -l deve ser utilizada para passar o arquivo de entrada.{}", RED, RESET);
        eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
        process::exit(1);
    };
    
    // Processa a flag -o para o arquivo de saída
    let arquivo_saida = if let Some(pos) = args.iter().position(|x| x == "-o") {
        if pos + 1 < args.len() {
            args[pos + 1].clone()
        } else {
            eprintln!("{}[✗] Erro: Caminho do arquivo de saída não especificado após a flag -o.{}", RED, RESET);
            eprintln!("{}Use -h para ver a ajuda.{}\n", YELLOW, RESET);
            process::exit(1);
        }
    } else {
        String::from("urls_parametros.txt")
    };
    
    (arquivo_entrada, arquivo_saida)
}
