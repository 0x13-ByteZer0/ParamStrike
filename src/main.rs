use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command};

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
    
    // Verifica se é solicitado help
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        mostrar_banner();
        mostrar_help();
        return;
    }
    
    mostrar_banner();
    
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
    
    if let Err(e) = filtrar_urls(&arquivo_entrada, &arquivo_saida) {
        eprintln!("{}[✗] Erro ao processar o arquivo: {}{}", RED, e, RESET);
        process::exit(1);
    }
}

// Lista de extensões de arquivos a serem removidas
const EXTENSOES_REMOVER: &[&str] = &[
    "md", "jpg", "jpeg", "gif", "css", "tif", "tiff", "png", "ttf", "woff",
    "woff2", "ico", "js", "json",
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
    println!("  {}  -h, --help{}      Mostra esta mensagem de ajuda\n", YELLOW, RESET);
    
    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}Modo padrão (filtrar URLs):{}", GREEN, RESET);
    println!("    {}$ paramstrike -l urls.txt -o resultado.txt{}", GREEN, RESET);
    println!("  {}Modo domínio único:{}", GREEN, RESET);
    println!("    {}$ paramstrike -d example.com{}", GREEN, RESET);
    println!("  {}Modo lista de subdomínios:{}", GREEN, RESET);
    println!("    {}$ paramstrike -f subs.txt{}\n", GREEN, RESET);
}

// Função para verificar se a URL contém uma das extensões especificadas
fn tem_extensao_remover(url: &str) -> bool {
    let url = url.trim().to_lowercase();
    
    for ext in EXTENSOES_REMOVER {
        if url.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    false
}
// Função para verificar se a URL contém parâmetros
fn tem_parametros(url: &str) -> bool {
    url.contains('?')
}
// Função para filtrar URLs e salvar as válidas
fn filtrar_urls(arquivo_entrada: &str, arquivo_saida: &str) -> std::io::Result<()> {
    // Lê o arquivo de entrada
    let file = File::open(arquivo_entrada)?;
    let reader = BufReader::new(file);
    
    let mut urls_filtradas = Vec::new();
    let mut total_urls = 0;
    let mut linhas_com_erro = 0;
    
    println!("{}[*] Processando arquivo: {}{}", BLUE, arquivo_entrada, RESET);
    
    // Filtra as URLs que têm parâmetros e não contêm as extensões especificadas
    for linha in reader.lines() {
        match linha {
            Ok(url_str) => {
                let url = url_str.trim().to_string();
                total_urls += 1;
                
                if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                    urls_filtradas.push(url);
                }
            }
            Err(_e) => {
                // Ignora linhas com erro de UTF-8 e continua
                linhas_com_erro += 1;
                total_urls += 1;
            }
        }
    }
    
    // Salva as URLs filtradas no arquivo de saída
    let mut output_file = File::create(arquivo_saida)?;
    for url in urls_filtradas.iter() {
        writeln!(output_file, "{}", url)?;
    }
    
    let removidas = total_urls - urls_filtradas.len();
    
    println!("{}[+] URLs processadas: {}{}", GREEN, total_urls, RESET);
    println!("{}[+] URLs com parâmetros: {}{}", GREEN, urls_filtradas.len(), RESET);
    println!("{}[-] URLs removidas: {}{}", YELLOW, removidas, RESET);
    
    if linhas_com_erro > 0 {
        println!("{}[!] Linhas com erro de encoding UTF-8 (ignoradas): {}{}", YELLOW, linhas_com_erro, RESET);
    }
    
    println!("{}[✓] URLs filtradas salvas em '{}'{}\n", GREEN, arquivo_saida, RESET);
    
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
    if let Err(e) = filtrar_urls(urls_file, &resultado_file) {
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
    if let Err(e) = filtrar_urls(urls_file, resultado_file) {
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
