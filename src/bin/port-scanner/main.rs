use std::{net::Ipv4Addr, env, fs, collections::HashMap};

use pnet::{packet::{tcp::{TcpFlags, MutableTcpPacket, self}, ip::IpNextHeaderProtocols}, transport::{self, TransportReceiver}};

const TCP_SIZE: usize = 20;
const MAXIMUM_PORT_NUM: u16 = 1023;

struct PacketInfo {
    my_ip_addr: Ipv4Addr,
    target_ip_addr: Ipv4Addr,
    my_port: u16,
    maximum_port: u16,
    scan_type: ScanType
}

#[derive(Copy, Clone)]
enum ScanType {
    Syn = TcpFlags::SYN as isize,
    Fin = TcpFlags::FIN as isize,
    Xmas = (TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH) as isize,
    Null = 0
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Bad number of arguments");
        std::process::exit(1);
    }

    let packet_info = {
        let contents = fs::read_to_string(".env").expect("Failed to read env file");
        let lines: Vec<_> = contents.split("\n").collect();
        let mut map = HashMap::new();
        for line in lines {
            let elm: Vec<_> = line.split("=").map(str::trim).collect();
            if elm.len() == 2 {
                map.insert(elm[0], elm[1]);
            }
        }

        PacketInfo {
            my_ip_addr: map["MY_IP_ADDR"].parse().expect("invalid ip addr"),
            target_ip_addr: args[1].parse().expect("invalid target ip addr"),
            my_port: map["MY_PORT"].parse().expect("invalid port number"),
            maximum_port: map["MAXIMUM_PORT_NUM"]
                .parse()
                .expect("invalid maximum port num"),
            scan_type: match args[2].as_str() {
                "sS" => ScanType::Syn,
                "sF" => ScanType::Fin,
                "sX" => ScanType::Xmas,
                "sN" => ScanType::Null,
                _ => {
                    log::error!("Undefined scan method, only accept [sS|sF|sN|sX].");
                    std::process::exit(1)
                }
            }
        }

    };

    let (mut ts, mut tr) = transport::transport_channel(
        1024, 
        transport::TransportChannelType::Layer4(transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp))
    )
    .expect("Failed to open channel.");

    rayon::join(|| send_packet(&mut ts, &packet_info), 
                || receive_packets(&mut tr, &packet_info)
    );
}

fn send_packet(ts: &mut transport::TransportSender, packet_info: &PacketInfo) {
    let mut packet = build_packet(packet_info);
    for i in 1..MAXIMUM_PORT_NUM+1 {
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet).unwrap();
        reregister_destination_port(i, &mut tcp_header, packet_info);
        std::thread::sleep(std::time::Duration::from_millis(5));
        ts.send_to(tcp_header, std::net::IpAddr::V4(packet_info.target_ip_addr)).expect("failed to send");
    }
}


fn build_packet(packet_info: &PacketInfo) -> [u8; TCP_SIZE] {
    let mut tcp_buffer = [0u8; TCP_SIZE];
    let mut tcp_header = MutableTcpPacket::new(& mut tcp_buffer[..]).unwrap();
    tcp_header.set_source(packet_info.my_port);

    tcp_header.set_data_offset(5);
    tcp_header.set_flags(packet_info.scan_type as u16);
    let checksum = tcp::ipv4_checksum(
        &tcp_header.to_immutable(), 
        &packet_info.my_ip_addr, 
        &packet_info.target_ip_addr
    );
    tcp_header.set_checksum(checksum);

    tcp_buffer
}

fn reregister_destination_port(
    target: u16,
    tcp_header: &mut MutableTcpPacket,
    packet_info: &PacketInfo
) {
    tcp_header.set_destination(target);
    let checksum = tcp::ipv4_checksum(
        &tcp_header.to_immutable(), 
        &packet_info.my_ip_addr, 
        &packet_info.target_ip_addr
    );

    tcp_header.set_checksum(checksum);
}

fn receive_packets(
    tr: &mut TransportReceiver,
    packet_info: &PacketInfo
) -> Result<(), failure::Error> {
    let mut replay_ports = Vec::new();
    let mut packet_iter = transport::tcp_packet_iter(tr);

    loop {
        let tcp_packet = match packet_iter.next() {
            Ok((tcp_packet, _)) => {
                if tcp_packet.get_destination() == packet_info.my_port {
                    tcp_packet
                } else {
                    continue;
                }
            }
            Err(_) => continue,
        };

        let target_port = tcp_packet.get_source();
        match packet_info.scan_type {
            ScanType::Syn => {
                if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
                    println!("port {} is open", target_port);
                }
            }
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                replay_ports.push(target_port);
            }
        }

        if target_port != packet_info.maximum_port {
            continue;
        }

        match packet_info.scan_type {
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                for i in 1..=packet_info.maximum_port {
                    if replay_ports.iter().find(|&&x| x == i).is_none() {
                        println!("port {} is open", i);
                    }
                }
            }
            _ => {}
        }
        return Ok(());
    }
}
