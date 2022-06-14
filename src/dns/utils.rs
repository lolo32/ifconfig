use std::net::IpAddr;

pub fn addr_to_arpa(ip: IpAddr) -> Vec<String> {
    match ip {
        IpAddr::V4(ip4) => vec![
            ip4.octets()
                .iter()
                .rev()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            ["in-addr".to_owned(), "arpa".to_owned(), "".to_owned()].to_vec(),
        ]
        .concat(),
        IpAddr::V6(ip6) => vec![
            ip6.octets()
                .iter()
                .rev()
                .map(|byte| [byte & 0xF, (byte & 0xF0) >> 4])
                .collect::<Vec<_>>()
                .concat()
                .iter()
                .map(|char| format!("{:x}", char))
                .collect::<Vec<_>>(),
            ["ip6".to_owned(), "arpa".to_owned(), "".to_owned()].to_vec(),
        ]
        .concat(),
    }
}

pub fn qname(vec_name: &[String]) -> Vec<Vec<u8>> {
    tracing::debug!("{:?}", vec_name);
    vec_name
        .iter()
        .map(|part| [[part.len() as u8].to_vec(), part.as_bytes().to_vec()].concat())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_addr_to_arpa() {
        let ip4: Ipv4Addr = "192.168.0.15".parse().expect("ipv4 addr");
        let ip6: Ipv6Addr = "2001:db8::567:89ab".parse().expect("ipv6 addr");

        assert_eq!(
            addr_to_arpa(IpAddr::from(ip6)).join("."),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );

        assert_eq!(
            addr_to_arpa(IpAddr::from(ip4)).join("."),
            "15.0.168.192.in-addr.arpa."
        );
    }
}
