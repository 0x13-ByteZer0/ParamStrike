use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::collections::HashMap;

// Cores ANSI
const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN: &str = "\x1b[96m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

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
    
    if let Err(e) = filtrar_urls(&arquivo_entrada, &arquivo_saida, verbose, check_status) {
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
    println!("  {}  -up, --update{}   Atualizar a ferramenta do Git e recompilar", MAGENTA, RESET);
    println!("  {}  -h, --help{}      Mostra esta mensagem de ajuda\n", YELLOW, RESET);
    
    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}Modo padrão (filtrar URLs):{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt{}", GREEN, RESET);
    println!("  {}Com verbose e verificação de status:{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt -v -status{}", GREEN, RESET);
    println!("  {}Atualizar ferramenta:{}", GREEN, RESET);
    println!("    {}$ paramstrike -up{}", GREEN, RESET);
    println!("  {}Modo domínio único:{}", GREEN, RESET);
    println!("    {}$ paramstrike -d example.com{}", GREEN, RESET);
    println!("  {}Modo lista de subdomínios:{}", GREEN, RESET);
    println!("    {}$ paramstrike -f subs.txt{}\n", GREEN, RESET);
}

// Função para obter o hash do último commit
fn obter_hash_commit() -> Option<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output();
    
    match output {
        Ok(out) => {
            if out.status.success() {
                let hash = String::from_utf8_lossy(&out.stdout);
                Some(hash.trim().to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// Função para ler o hash salvo localmente
fn ler_hash_salvo() -> Option<String> {
    match std::fs::read_to_string(".version") {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

// Função para salvar o hash do commit
fn salvar_hash_commit(hash: &str) -> std::io::Result<()> {
    std::fs::write(".version", hash)
}

// Função para verificar se há atualizações disponíveis
fn verificar_atualizacoes() {
    match obter_hash_commit() {
        Some(hash_atual) => {
            match ler_hash_salvo() {
                Some(hash_salvo) => {
                    if hash_atual != hash_salvo {
                        println!("{}╔═══════════════════════════════════════════════════════════════╗{}", YELLOW, RESET);
                        println!("{}║                                                               ║{}", YELLOW, RESET);
                        println!("{}║  {}⚠  FERRAMENTA DESATUALIZADA!                          {}║{}", YELLOW, RED, YELLOW, RESET);
                        println!("{}║                                                               ║{}", YELLOW, RESET);
                        println!("{}║  {}Nova versão disponível. Execute para atualizar:  {}║{}", YELLOW, CYAN, YELLOW, RESET);
                        println!("{}║                                                               ║{}", YELLOW, RESET);
                        println!("{}║         {}$ paramstrike -up                             {}║{}", YELLOW, BOLD, YELLOW, RESET);
                        println!("{}║                                                               ║{}", YELLOW, RESET);
                        println!("{}╚═══════════════════════════════════════════════════════════════╝{}", YELLOW, RESET);
                        println!();
                    } else {
                        println!("{}╔═══════════════════════════════════════════════════════════════╗{}", GREEN, RESET);
                        println!("{}║                                                               ║{}", GREEN, RESET);
                        println!("{}║  {}✓  FERRAMENTA ATUALIZADA{}                                   {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
                        println!("{}║                                                               ║{}", GREEN, RESET);
                        println!("{}║         {}Versão: LATEST{}                                      {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
                        println!("{}║                                                               ║{}", GREEN, RESET);
                        println!("{}╚═══════════════════════════════════════════════════════════════╝{}", GREEN, RESET);
                        println!();
                    }
                }
                None => {
                    println!("{}[*] Primeira execução - salvando versão{}", BLUE, RESET);
                    let _ = salvar_hash_commit(&hash_atual);
                    println!("{}╔═══════════════════════════════════════════════════════════════╗{}", GREEN, RESET);
                    println!("{}║                                                               ║{}", GREEN, RESET);
                    println!("{}║  {}✓  FERRAMENTA ATUALIZADA{}                                   {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
                    println!("{}║                                                               ║{}", GREEN, RESET);
                    println!("{}║         {}Versão: LATEST{}                                      {}║{}", GREEN, BOLD, RESET, GREEN, RESET);
                    println!("{}║                                                               ║{}", GREEN, RESET);
                    println!("{}╚═══════════════════════════════════════════════════════════════╝{}", GREEN, RESET);
                    println!();
                }
            }
        }
        None => {
            println!("{}[!] Não foi possível verificar versão (Git não disponível){}", YELLOW, RESET);
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
        .arg("/dev/null")
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
                
                // Obter novo hash e salvar
                if let Some(novo_hash) = obter_hash_commit() {
                    match salvar_hash_commit(&novo_hash) {
                        Ok(_) => {
                            println!("{}[✓] Versão salva: {}...{}", GREEN, &novo_hash[..12], RESET);
                        }
                        Err(e) => {
                            eprintln!("{}[!] Aviso ao salvar versão: {}{}", YELLOW, e, RESET);
                        }
                    }
                }
                
                println!();
                println!("{}╔═══════════════════════════════════════════════════════════════╗{}", BLUE, RESET);
                println!("{}║                                                               ║{}", BLUE, RESET);
                println!("{}║  {}✓  ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!{}                     {}║{}", BLUE, GREEN, RESET, BLUE, RESET);
                println!("{}║                                                               ║{}", BLUE, RESET);
                println!("{}║         {}→ Versão: LATEST{}                                   {}║{}", BLUE, BOLD, RESET, BLUE, RESET);
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
fn filtrar_urls(arquivo_entrada: &str, arquivo_saida: &str, verbose: bool, check_status: bool) -> std::io::Result<()> {
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
    
    println!();
    Ok(())
}

// Função para executar subfinder
fn executar_subfinder(domain: &str, arquivo_saida: &str) -> std::io::Result<()> {
    println!("{}[*] Executando subfinder para: {}{}", MAGENTA, domain, RESET);
    
    let output = Command::new("subfinder")
        .arg("-d")
        .arg(domain)
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
    if let Err(e) = filtrar_urls(urls_file, &resultado_file, false, false) {
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
    if let Err(e) = filtrar_urls(urls_file, resultado_file, false, false) {
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
