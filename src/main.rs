use std::{collections::HashMap, error::Error, fmt::Display, fs};

use clap::{App, Arg};
use develop_debug::*;

fn main() {
    dd___title!("准备查看网站IP地址");
    let siteip = App::new("Look at the site IP address")
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
        .get_matches();

    dd________!("查看 `site` 参数");
    let site = siteip.value_of("site").unwrap_or_default();
    dd_____var!(site);

    dd________!("查看 `file` 参数");
    let file = siteip.value_of("file").unwrap_or_default();
    dd_____var!(file);

    dd____step!("收集要查看IP的网站域名");
    let mut sites: Vec<String> = vec![];

    // 测试数据
    // sites.push("github.com".to_string());
    // sites.push("api.github.com".to_string());

    if !site.is_empty() {
        dd________!("添加 `site` 参数中指定的域名");
        let domains = site.split_ascii_whitespace();
        sites.append(
            &mut domains
                .filter(|&d| !d.is_empty())
                .map(|d| d.to_string())
                .collect::<Vec<String>>(),
        );
    }
    if !file.is_empty() {
        dd________!("添加 `file` 文件中的所有域名");
        match fs::read_to_string(file) {
            Ok(domains) => {
                sites.append(
                    &mut domains
                        .split('\n')
                        .filter(|&d| !d.is_empty() && !d.contains(&['#', ' ', '\t'][..]))
                        .map(|d| d.to_string())
                        .collect::<Vec<String>>(),
                );
            }
            Err(err) => {
                eprintln!("请求文件 `{}` 出错 :\n{}", file, err);
            }
        };
    }
    dd____iter!(sites.iter());
    dd_____var!(sites.len());
    dd____done!();

    let mut ips = HashMap::new();
    // 可用的dns;
    let dns = vec![
        // "223.5.5.5".to_string(),
        // "114.114.114.114".to_string(),
        "8.8.8.8".to_string(),
    ];
    // 尝试使用nslookup;
    let mut find = vec![];
    let first_find = sites.clone();
    for (index, domain) in first_find.iter().enumerate().rev() {
        let mut find_ip = String::default();
        for dns in dns.iter() {
            match nslookup(domain, dns) {
                Ok(ip) => {
                    find_ip = ip.clone();
                    ips.insert(domain, ip.clone());
                }
                Err(err) => {
                    println!("{}", err);
                }
            }
        }
        if !find_ip.is_empty() {
            find.push(index);
        }
    }
    // 删除处理过的网址
    let mut second_find = sites.clone();
    for index in find {
        second_find.remove(index);
    }

    // 如果网址都处理完了,结束.
    if !second_find.is_empty() {
        dd____step!("使用 `ipaddress.com` 解析域名IP地址");

        sites.iter().for_each(|d| {
            let ip = resolve_domain_ip(d);
            match ip {
                Ok(ok) => {
                    ips.insert(d, ok);
                }
                Err(err) => {
                    println!("{}", err);
                }
            }
        });
    }

    dd____step!("按参数顺序打印结果");
    println!("\n# 解析结果\n\n");
    sites.iter().for_each(|s| {
        let no_find = String::from("# Parse failure");
        let ip = ips.get(s).unwrap_or(&no_find);
        println!("{}    {}", ip, s);
    });
    println!();
}

fn resolve_domain_ip(domain: &String) -> Result<String, Box<dyn Error>> {
    println!("请求 {}", domain);
    let res = reqwest::blocking::get(format!("http://{}.ipaddress.com", domain))?;

    let status = res.status();
    dd_____var!(status);

    let header = res.headers();
    dd____iter!(header.iter());

    let body = res.text()?;
    let start = "https://www.ipaddress.com/ipv4/";
    let end = "\\";
    let split_ip = body
        .splitn(2, start)
        .nth(1)
        .and_then(|s| s.splitn(2, end).next());

    match split_ip {
        Some(ip) => {
            dd_____var!(ip);
            dd____done!();
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
                                println!("‹{}›\tnslookup {} from {}", ip, domain, dns);
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
