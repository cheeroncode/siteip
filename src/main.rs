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

    if sites.is_empty() {
        println!("未收集到有效的域名,命令结束.");
        return;
    }

    dd____step!("解析域名IP地址");
    let mut ips = HashMap::new();

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

    dd____step!("按参数顺序打印结果");
    println!("\n# 解析结果\n\n");
    sites.iter().for_each(|s| {
        let no_find = String::from("# Parse failure");
        let ip = ips.get(&s).unwrap_or(&no_find);
        println!("{}    {}", ip, s);
    });
    println!();
}

fn resolve_domain_ip(domain: &String) -> Result<String, Box<dyn Error>> {
    dd________!("请求 {}", domain);
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
