use std::{net::{Ipv4Addr, IpAddr}, sync::mpsc};

use log::info;
use pnet::{util::MacAddr, packet::icmp::echo_request::EchoRequestPacket};
use rusqlite::{params, Connection, Rows, Transaction, NO_PARAMS};

pub fn select_entry(
    con: &Connection,
    mack_addr: MacAddr,
) -> Result<Option<Ipv4Addr>, failure::Error> {

    let mut stmnt = con.prepare("SELECT ip_addr FROM mac_ip_map WHERE mac_addr=?1")?;
    let mut row = stmnt.query(params![mack_addr.to_string()])?;

    if let Some(entry) = row.next()? {
        let ip = entry.get(0)?;
        let ip_string: String = ip;
        Ok(Some(ip_string.parse()?))
    } else {
        info!("specified MAC address not found in database");
        Ok(None)
    }
}

fn get_address_from_row(mut ip_addrs: Rows) -> Result<Vec<Ipv4Addr>, failure::Error> {
    let mut leased_addrs: Vec<Ipv4Addr> = Vec::new();

    while let Some(entry) = ip_addrs.next()? {
        let ip_addr = match entry.get(0) {
            Ok(ip) => {
                let ip_string: String = ip;
                ip_string.parse()?
            },
            Err(_) => continue,
        };
        leased_addrs.push(ip_addr);
    }

    Ok(leased_addrs)
}

pub fn select_address(
    con: &Connection,
    deleted: Option<u8>
) -> Result<Vec<Ipv4Addr>, failure::Error> {
    if let Some(deleted) = deleted {
        let mut statement = con.prepare("SELECT ip_addr FROM lease_entries WHERE deleted = ?")?;
        let ip_addrs = statement.query(params![deleted.to_string()])?;
        get_address_from_row(ip_addrs)
    } else {
        let mut statement = con.prepare("SELECT ip_addr FROM lease_entries")?;
        let ip_addrs = statement.query(NO_PARAMS)?;
        get_address_from_row(ip_addrs)
    }
}

pub fn count_records_by_mac_addr(
    tx: &Transaction,
    mac_addr: MacAddr
) -> Result<u8, failure::Error> {
    let mut statement = tx.prepare("SELECT COUNT (*) FROM lease_entries WHERE mac_addr = ?")?;
    let mut count_result = statement.query(params![mac_addr.to_string()])?;

    let count: u8 = match count_result.next()? {
        Some(row) => row.get(0)?,
        None => {
            return Err(failure::err_msg("No query returned."));
        }
    };

    Ok(count)
}

pub fn insert_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr
) -> Result<(), failure::Error> {
    tx.execute(
        "INSERT INTO lease_entries (mac_addr, ip_addr) VALUES (?1, ?2)",
        params![mac_addr.to_string(), ip_addr.to_string()]
    )?;
    Ok(())
}

pub fn update_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr,
    deleted: u8,
) -> Result<(), failure::Error> {
    tx.execute(
        "UPDATE lease_entries SET ip_addr = ?2, deleted = ?3 WHERE mac_addr=?1", 
        params![
            mac_addr.to_string(),
            ip_addr.to_string(),
            deleted.to_string()
        ]
    )?;

    Ok(())
}

pub fn delete_entry(
    tx: &Transaction,
    mac_addr: MacAddr
) -> Result<(), failure::Error> {
    tx.execute(
        "UPDATE lease_entries SET delete = ?1 WHERE mac_addr = ?2",
        params![1.to_string(), mac_addr.to_string()],
    )?;
    Ok(())
}
