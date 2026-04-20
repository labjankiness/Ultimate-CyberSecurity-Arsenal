use chrono::Local;
use clap::Parser;
use colored::*;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::process;

#[derive(Parser)]
#[command(name = "packet-sniffer")]
#[command(about = "A lightweight CLI packet sniffer for network traffic analysis")]
struct Args {
    /// Network interface to sniff on (e.g., eth0, wlan0)
    #[arg(short, long)]
    interface: Option<String>,

    /// Filter by protocol: tcp, udp, icmp, arp
    #[arg(short, long)]
    protocol: Option<String>,

    /// Filter by port number
    #[arg(long)]
    port: Option<u16>,

    /// Maximum number of packets to capture (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    count: usize,

    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// Show packet payload as hex dump
    #[arg(long)]
    hex: bool,
}

fn list_interfaces() {
    println!("{}", "Available network interfaces:".bold());
    for iface in datalink::interfaces() {
        let status = if iface.is_up() {
            "UP".green()
        } else {
            "DOWN".red()
        };
        let ips: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();
        let ip_str = if ips.is_empty() {
            "no address".dimmed().to_string()
        } else {
            ips.join(", ")
        };
        println!("  {} [{}] {}", iface.name.cyan(), status, ip_str);
    }
}

fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
}

fn hex_dump(data: &[u8], max_bytes: usize) {
    let len = data.len().min(max_bytes);
    for (i, chunk) in data[..len].chunks(16).enumerate() {
        print!("    {:04x}  ", i * 16);
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }
        for j in chunk.len()..16 {
            print!("   ");
            if j == 7 {
                print!(" ");
            }
        }
        print!(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    if data.len() > max_bytes {
        println!("    ... ({} more bytes)", data.len() - max_bytes);
    }
}

fn handle_tcp(ipv4: &Ipv4Packet, args: &Args) {
    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
        if let Some(port_filter) = args.port {
            if tcp.get_source() != port_filter && tcp.get_destination() != port_filter {
                return;
            }
        }

        let mut flags = String::new();
        let f = tcp.get_flags();
        if f & 0x02 != 0 { flags.push_str("SYN "); }
        if f & 0x10 != 0 { flags.push_str("ACK "); }
        if f & 0x01 != 0 { flags.push_str("FIN "); }
        if f & 0x04 != 0 { flags.push_str("RST "); }
        if f & 0x08 != 0 { flags.push_str("PSH "); }

        let timestamp = Local::now().format("%H:%M:%S%.3f");
        println!(
            "{} {} {}:{} {} {}:{} {} [{}] len={}",
            timestamp.to_string().dimmed(),
            "TCP".green().bold(),
            ipv4.get_source().to_string().cyan(),
            tcp.get_source().to_string().yellow(),
            "->".dimmed(),
            ipv4.get_destination().to_string().cyan(),
            tcp.get_destination().to_string().yellow(),
            flags.trim().blue(),
            tcp.get_sequence(),
            ipv4.get_total_length()
        );

        if args.hex && !tcp.payload().is_empty() {
            hex_dump(tcp.payload(), 128);
        }
    }
}

fn handle_udp(ipv4: &Ipv4Packet, args: &Args) {
    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
        if let Some(port_filter) = args.port {
            if udp.get_source() != port_filter && udp.get_destination() != port_filter {
                return;
            }
        }

        let timestamp = Local::now().format("%H:%M:%S%.3f");
        let label = if udp.get_source() == 53 || udp.get_destination() == 53 {
            "DNS".magenta().bold()
        } else {
            "UDP".blue().bold()
        };

        println!(
            "{} {} {}:{} {} {}:{} len={}",
            timestamp.to_string().dimmed(),
            label,
            ipv4.get_source().to_string().cyan(),
            udp.get_source().to_string().yellow(),
            "->".dimmed(),
            ipv4.get_destination().to_string().cyan(),
            udp.get_destination().to_string().yellow(),
            udp.get_length()
        );

        if args.hex && !udp.payload().is_empty() {
            hex_dump(udp.payload(), 128);
        }
    }
}

fn handle_icmp(ipv4: &Ipv4Packet, args: &Args) {
    if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
        let timestamp = Local::now().format("%H:%M:%S%.3f");
        let icmp_type = match icmp.get_icmp_type().0 {
            0 => "Echo Reply",
            3 => "Dest Unreachable",
            8 => "Echo Request",
            11 => "Time Exceeded",
            _ => "Other",
        };

        println!(
            "{} {} {} {} {} type={} code={}",
            timestamp.to_string().dimmed(),
            "ICMP".red().bold(),
            ipv4.get_source().to_string().cyan(),
            "->".dimmed(),
            ipv4.get_destination().to_string().cyan(),
            icmp_type.yellow(),
            icmp.get_icmp_code().0
        );

        if args.hex && !icmp.payload().is_empty() {
            hex_dump(icmp.payload(), 64);
        }
    }
}

fn handle_arp(arp_packet: &ArpPacket, args: &Args) {
    let timestamp = Local::now().format("%H:%M:%S%.3f");
    let op = match arp_packet.get_operation().0 {
        1 => "Request".yellow(),
        2 => "Reply".green(),
        _ => "Unknown".dimmed(),
    };

    println!(
        "{} {} {} {} {} {} ({})",
        timestamp.to_string().dimmed(),
        "ARP".purple().bold(),
        op,
        arp_packet.get_sender_proto_addr().to_string().cyan(),
        "->".dimmed(),
        arp_packet.get_target_proto_addr().to_string().cyan(),
        arp_packet.get_sender_hw_addr()
    );
    let _ = args;
}

fn handle_ipv4(ipv4: &Ipv4Packet, args: &Args) {
    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if args.protocol.is_none() || args.protocol.as_deref() == Some("tcp") {
                handle_tcp(ipv4, args);
            }
        }
        IpNextHeaderProtocols::Udp => {
            if args.protocol.is_none() || args.protocol.as_deref() == Some("udp") {
                handle_udp(ipv4, args);
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if args.protocol.is_none() || args.protocol.as_deref() == Some("icmp") {
                handle_icmp(ipv4, args);
            }
        }
        _ => {
            if args.protocol.is_none() {
                let timestamp = Local::now().format("%H:%M:%S%.3f");
                println!(
                    "{} {} {} {} {} proto={}",
                    timestamp.to_string().dimmed(),
                    "IPv4".white().bold(),
                    ipv4.get_source().to_string().cyan(),
                    "->".dimmed(),
                    ipv4.get_destination().to_string().cyan(),
                    ipv4.get_next_level_protocol()
                );
            }
        }
    }
}

fn handle_ipv6(ipv6: &Ipv6Packet, args: &Args) {
    if args.protocol.is_some() {
        return;
    }
    let timestamp = Local::now().format("%H:%M:%S%.3f");
    println!(
        "{} {} {} {} {} next={}",
        timestamp.to_string().dimmed(),
        "IPv6".white().bold(),
        ipv6.get_source().to_string().cyan(),
        "->".dimmed(),
        ipv6.get_destination().to_string().cyan(),
        ipv6.get_next_header()
    );
}

fn main() {
    let args = Args::parse();

    if args.list {
        list_interfaces();
        return;
    }

    let interface = if let Some(ref name) = args.interface {
        match find_interface(name) {
            Some(iface) => iface,
            None => {
                eprintln!("{} Interface '{}' not found", "Error:".red().bold(), name);
                eprintln!("Run with --list to see available interfaces");
                process::exit(1);
            }
        }
    } else {
        match get_default_interface() {
            Some(iface) => iface,
            None => {
                eprintln!("{} No suitable network interface found", "Error:".red().bold());
                eprintln!("Run with --list to see available interfaces");
                process::exit(1);
            }
        }
    };

    println!(
        "{} Sniffing on {} {}",
        ">>>".green().bold(),
        interface.name.cyan().bold(),
        if let Some(ref proto) = args.protocol {
            format!("(filter: {})", proto)
        } else {
            String::new()
        }
    );
    if let Some(port) = args.port {
        println!("    Port filter: {}", port.to_string().yellow());
    }
    if args.count > 0 {
        println!("    Capturing {} packets", args.count);
    }
    println!("{}", "Press Ctrl+C to stop".dimmed());
    println!();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("{} Unhandled channel type", "Error:".red().bold());
            process::exit(1);
        }
        Err(e) => {
            eprintln!("{} Failed to open channel: {}", "Error:".red().bold(), e);
            eprintln!("Try running with sudo: sudo ./packet-sniffer");
            process::exit(1);
        }
    };

    let mut captured = 0usize;

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    match ethernet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                handle_ipv4(&ipv4, &args);
                                if args.protocol.is_none()
                                    || matches!(
                                        (args.protocol.as_deref(), ipv4.get_next_level_protocol()),
                                        (Some("tcp"), IpNextHeaderProtocols::Tcp)
                                            | (Some("udp"), IpNextHeaderProtocols::Udp)
                                            | (Some("icmp"), IpNextHeaderProtocols::Icmp)
                                    )
                                {
                                    captured += 1;
                                }
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                                handle_ipv6(&ipv6, &args);
                                if args.protocol.is_none() {
                                    captured += 1;
                                }
                            }
                        }
                        EtherTypes::Arp => {
                            if args.protocol.is_none()
                                || args.protocol.as_deref() == Some("arp")
                            {
                                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                    handle_arp(&arp, &args);
                                    captured += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Error receiving packet: {}", "Error:".red().bold(), e);
            }
        }

        if args.count > 0 && captured >= args.count {
            println!(
                "\n{} Captured {} packets",
                "Done.".green().bold(),
                captured
            );
            break;
        }
    }
}
