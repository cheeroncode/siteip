use std::{collections::HashMap, error::Error, fmt::Display, fs};

use clap::{App, Arg};
use develop_debug::*;

fn main() {
    dd___title!("解析域名IP地址命令正在运行");
    // 默认域名服务器
    let default_domain_name_servers = ["8.8.8.8", "223.5.5.5", "114.114.114.114"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    // 配置命令
    let (input_site, input_file, input_dns) = cfg_cmd_args(&default_domain_name_servers);

    dd____step!("提取输入的参数");
    // 输入的域名
    let domains = extract_domains(&input_site, &input_file);
    // 输入的域名服务器
    let dnss = extract_dnss(&input_dns).unwrap_or(default_domain_name_servers.clone());
    dd____iter!(domains.iter(), dnss.iter());

    dd____step!("检查域名不能为空");
    if domains.is_empty() {
        let msg = "输入域名为空,运行结束.";
        dd___error!(msg);
        println!("{}", msg);
        return;
    }
    dd____done!(format!("共提取 {} 个域名", domains.len()));

    // 存储解析到的 域名和地址
    let mut domain_ip_map: HashMap<String, Vec<String>> = HashMap::new();

    dd____step!("执行 nslookup 命令获取域名地址");
    let mut indexs = vec![];

    for (index, domain) in domains.iter().enumerate().rev() {
        let mut find = false;
        println!("\nnslookup {}", domain);
        for dns in &dnss {
            match nslookup(domain, dns) {
                Ok(ip) => {
                    find = true;
                    let ips = domain_ip_map.entry(domain.to_string()).or_insert(vec![]);
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                Err(err) => {
                    eprintln!("nslookup error : {}", err);
                }
            }
        }
        if find {
            indexs.push(index);
        }
    }
    dd____done!("执行 nslookup 完毕");

    // 删除处理过的网址
    dd____step!("检查是否全部域名都获取到IP地址");
    let mut ipaddress = domains.clone();
    for index in indexs {
        ipaddress.remove(index);
    }

    if ipaddress.is_empty() {
        dd____iter!(domain_ip_map.iter());
        dd____done!("检查完毕");
    } else {
        // 如果 domains 未处理完,使用 ipaddress 继续处理
        dd___error!(format!("剩余 {} 个域名获取IP地址失败", ipaddress.len()));
        dd____step!("从 ipaddress.com 获取IP地址");
        for domain in ipaddress {
            match resolve_domain_ip(&domain) {
                Ok(ip) => {
                    let ips = domain_ip_map.entry(domain).or_insert(vec![]);
                    ips.push(ip);
                }
                Err(err) => {
                    dd___error!(format!("从 ipaddress.com 获取出错 {}", err));
                    println!("{}", err);
                }
            }
        }
        dd____iter!(domain_ip_map.iter());
        dd____done!("从 ipaddress.com 获取结束");
    }

    dd____step!("对多个IP地址执行 ping 并获取响应最快的");
    let need_do_ping = domain_ip_map
        .clone()
        .into_iter()
        .filter(|item| item.1.len() > 1)
        .collect::<HashMap<String, Vec<String>>>();
    dd_____var!(need_do_ping.len());
    // 分解异步任务
    let mut do_ping = vec![];
    for (k, v) in need_do_ping {
        for ip in v {
            do_ping.push((k.clone(), ip));
        }
    }
    // 创建异步任务??
    let rt = tokio::runtime::Runtime::new().unwrap();

    let tasks: Vec<_> = do_ping
        .iter_mut()
        .map(|(domain, ip)| {
            dd________!("add task ping {} {}", domain, ip);
            rt.spawn(ping(domain.to_string(), ip.to_string()))
        })
        .collect();

    rt.block_on(async {
        let mut result: HashMap<String, (String, f64)> = HashMap::new();
        for task in tasks {
            let (domain, ip, time) = task.await.unwrap();
            let (oip, otime) = result.entry(domain).or_insert((ip.to_string(), time));
            if time < *otime {
                *oip = ip;
                *otime = time;
            }
        }

        for (domain, (ip, _time)) in result {
            domain_ip_map.entry(domain).and_modify(|item| {
                *item = vec![ip];
            });
        }
        dd____done!("执行 ping 结束");

        // 按顺序打印
        println!("\n# 解析 {} 个域名\n\n", domain_ip_map.len());
        for site in &domains {
            let no_find = vec!["# Parse failure".to_string()];
            let ip = domain_ip_map.get(site).unwrap_or(&no_find);
            println!("{:<15}    {}", ip[0], site);
        }

        println!();
    });
}

/// config command and return args (input_site,input_file,input_dns)
fn cfg_cmd_args(dnss: &Vec<String>) -> (String, String, String) {
    let app = App::new("Look at the site IP address")
        .version("0.1.0")
        .author("cheeroncode <code@autodo.xyz>")
        .about("A simple tool")
        .arg(
            Arg::with_name("site")
                .short("s")
                .long("site")
                .value_name("Domain")
                .help("Set a site domain name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("File")
                .help("Set the path to the file, and each line in the file contains a domain name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dns")
                .short("n")
                .long("dns")
                .value_name("Dns")
                .help(
                    &format!("Set which DNS to return the domain name IP address from.\ndefault use DNS:\n{:?}",&dnss
                ))
                .takes_value(true),
        )
        .get_matches();

    // 获取参数
    let input_site = app.value_of("site").unwrap_or_default();
    let input_file = app.value_of("file").unwrap_or_default();
    let input_dns = app.value_of("dns").unwrap_or_default();
    dd_____var!(input_site, input_file, input_dns);
    // 返回参数
    (
        input_site.to_string(),
        input_file.to_string(),
        input_dns.to_string(),
    )
}

fn extract_domains(site: &String, file: &String) -> Vec<String> {
    let mut domains = vec![];
    // 如果设置了多个以空格隔开的域名,添加到 domains
    if !site.is_empty() {
        domains.append(
            &mut site
                .split_ascii_whitespace()
                .filter(|&d| !d.is_empty())
                .map(|d| d.to_string())
                .collect::<Vec<String>>(),
        );
    }
    // 如果设置了文件参数,且文件中每行有一个域名,添加到 domains
    if !file.is_empty() {
        match fs::read_to_string(file) {
            Ok(fc) => {
                domains.append(
                    &mut fc
                        .split('\n')
                        .filter(|&d| !d.is_empty() && !d.contains(&['#', ' ', '\t'][..]))
                        .map(|d| d.to_string())
                        .collect::<Vec<String>>(),
                );
            }
            Err(err) => {
                eprintln!("读取文件 `{}` 出错 : {}", file, err);
            }
        };
    }
    return domains;
}

fn extract_dnss(dns: &String) -> Option<Vec<String>> {
    let mut dnss = vec![];
    // 如果设置了多个以空格隔开的域名,添加到 domains
    if !dns.is_empty() {
        dnss.append(
            &mut dns
                .split_ascii_whitespace()
                .filter(|&d| !d.is_empty())
                .map(|d| d.to_string())
                .collect::<Vec<String>>(),
        );
        Some(dnss)
    } else {
        None
    }
}

fn resolve_domain_ip(domain: &String) -> Result<String, Box<dyn Error>> {
    println!("query {}", domain);
    let res = reqwest::blocking::get(format!("http://{}.ipaddress.com", domain))?;

    // let status = res.status();
    // dd_____var!(status);

    // let header = res.headers();
    // dd____iter!(header.iter());

    let body = res.text()?;
    let start = "https://www.ipaddress.com/ipv4/";
    let end = "\\";
    let split_ip = body
        .splitn(2, start)
        .nth(1)
        .and_then(|s| s.splitn(2, end).next());

    match split_ip {
        Some(ip) => {
            println!("{} from ipaddress.com", ip);
            Ok(ip.to_string())
        }
        None => Err(Box::new(ResolveIPError {
            msg: format!("解析域名 `{}` 的IP地址失败 :\n{}", domain, body),
        })),
    }
}

fn nslookup(domain: &String, dns: &String) -> Result<String, Box<dyn Error>> {
    match std::process::Command::new("nslookup")
        .arg(domain)
        .arg(dns)
        .output()
    {
        Ok(ok) => {
            if ok.stdout.is_empty() {
                println!("{}", ok.status);
                return Err(Box::new(ResolveIPError {
                    msg: format!("转换 `nslookup` {} {} 结果出错 :\n{:#?}", domain, dns, ok),
                }));
            } else {
                let out = String::from_utf8(ok.stdout.as_slice().to_vec());
                match out {
                    Ok(content) => {
                        let split = content.rsplitn(2, ':').next();
                        match split {
                            Some(ip_text) => {
                                let ip = ip_text.trim().to_string();
                                println!("{}\t from  {}", ip, dns);
                                return Ok(ip);
                            }
                            None => {
                                return Err(Box::new(ResolveIPError {
                                    msg: format!(
                                        "提取 `nslookup` {} {} 结果出错 :\n{}",
                                        domain, dns, content
                                    ),
                                }));
                            }
                        }
                    }
                    Err(err) => {
                        return Err(Box::new(ResolveIPError {
                            msg: format!("转换 `nslookup` {} {} 结果出错 :\n{}", domain, dns, err),
                        }));
                    }
                }
            }
        }
        Err(err) => {
            return Err(Box::new(ResolveIPError {
                msg: format!("执行 `nslookup` {} {} 出错 :\n{}", domain, dns, err),
            }));
        }
    }
}

// ping -c 5 github.com
async fn ping(domain: String, ip: String) -> (String, String, f64) {
    match std::process::Command::new("ping")
        .arg("-c")
        .arg("5")
        .arg(&ip)
        .output()
    {
        Ok(ok) => {
            // 提取响应时间
            if ok.stdout.is_empty() {
                println!("转换 `ping` 结果出错 {}", ok.status);
                return (domain, ip, 10000.2);
            } else {
                let out = String::from_utf8(ok.stdout.as_slice().to_vec());
                match out {
                    Ok(content) => {
                        // 64 bytes from 192.30.255.113: icmp_seq=4 ttl=48 time=398.154 ms
                        let time = content
                            .split("min/avg/max/stddev = ")
                            .nth(1)
                            .and_then(|s| s.split('/').nth(1))
                            .and_then(|f| f.parse::<f64>().ok());

                        match time {
                            Some(tf) => {
                                println!("{:<15}  time = {}  # {}", &ip, tf, &domain);
                                return (domain, ip, tf);
                            }
                            None => {
                                println!("{} timeout # {}", ip, domain);
                                return (domain, ip, 10000.4);
                            }
                        }
                    }
                    Err(err) => {
                        println!("提取 `ping` 结果出错 {}", err);
                        return (domain, ip, 10000.3);
                    }
                }
            }
        }
        Err(_) => (domain, ip, 10000.1),
    }
}
#[derive(Debug)]
struct ResolveIPError {
    msg: String,
}

impl Error for ResolveIPError {}

impl Display for ResolveIPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}
