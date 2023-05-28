use std::{net::Ipv4Addr, env, fs, collections::HashMap};

use pnet::{packet::{tcp::{TcpFlags, MutableTcpPacket, self}, ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}}, transport};

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
