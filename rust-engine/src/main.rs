use clap::Parser;
use pcap_engine::pcap_parser::parse_pcap_file;
use pcap_engine::http_session::reconstruct_http_sessions;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let args = Args::parse();

    println!("PCAP 流量解析引擎启动...");
    println!("输入文件: {:?}", args.input);

    let packets = parse_pcap_file(&args.input).expect("解析 PCAP 文件失败");
    println!("成功解析 {} 个数据包", packets.len());

    let sessions = reconstruct_http_sessions(&packets);
    println!("成功还原 {} 个 HTTP 会话", sessions.len());

    let json_output = serde_json::to_string_pretty(&sessions).expect("序列化失败");

    if let Some(output_path) = args.output {
        let mut file = File::create(&output_path).expect("创建输出文件失败");
        file.write_all(json_output.as_bytes()).expect("写入文件失败");
        println!("结果已保存到: {:?}", output_path);
    } else {
        println!("{}", json_output);
    }

    println!("处理完成!");
}
