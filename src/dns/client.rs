use std::time::Duration;

use async_std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    prelude::FutureExt,
};

#[derive(Debug, Clone)]
pub struct Resolver {
    nameservers: Vec<IpAddr>,
}

impl Resolver {
    #[cfg(unix)]
    pub fn new() -> Result<Self, std::io::Error> {
        use std::{
            fs::File,
            io::{BufRead, BufReader},
        };

        let f = File::open("/etc/resolv.conf")?;
        let reader = BufReader::new(f);

        let mut nameservers = Vec::new();
        for line in reader.lines() {
            let line = line?;

            if let Some(nameserver_str) = line.strip_prefix("nameserver ") {
                match nameserver_str.parse::<IpAddr>() {
                    Ok(ip) => nameservers.push(ip),
                    Err(e) => tracing::warn!("Failed to parse nameserver line {:?}: {}", line, e),
                };
            }
        }

        if nameservers.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Nameserver not found",
            ))
        } else {
            Ok(Self { nameservers })
        }
    }

    #[cfg(windows)]
    pub fn new() -> Result<Self, io::Error> {
        use std::net::{IpAddr, UdpSocket};

        // get the IP of the Network adapter that is used to access the Internet
        // https://stackoverflow.com/questions/24661022/getting-ip-adress-associated-to-real-hardware-ethernet-controller-in-windows-c
        fn get_ipv4(nameserver: &str) -> io::Result<IpAddr> {
            let s = UdpSocket::bind("0.0.0.0:0")?;
            s.connect(nameserver)?;
            let addr = s.local_addr()?;
            Ok(addr.ip())
        }

        fn get_ipv6(nameserver: &str) -> io::Result<IpAddr> {
            let s = UdpSocket::bind("[::]:0")?;
            s.connect(nameserver)?;
            let addr = s.local_addr()?;
            Ok(addr.ip())
        }

        let ip = self::utils::get_ipv6().or(self::utils::get_ipv4()).ok();

        let adapters = ipconfig::get_adapters()?;
        let active_adapters = adapters.iter().filter(|a| {
            a.oper_status() == ipconfig::OperStatus::IfOperStatusUp && !a.gateways().is_empty()
        });

        if let Some(dns_server) = active_adapters
            .clone()
            .find(|a| ip.map(|ip| a.ip_addresses().contains(&ip)).unwrap_or(false))
            .map(|a| a.dns_servers().first())
            .flatten()
        {
            tracing::debug!("Found first nameserver {:?}", dns_server);
            let nameserver = dns_server.to_string();
            Ok(Self { nameservers })
        }
        // Fallback
        else if let Some(dns_server) = active_adapters
            .flat_map(|a| a.dns_servers())
            .find(|d| d.is_ipv4() || d.is_ipv6())
        {
            tracing::debug!("Found first fallback nameserver {:?}", dns_server);
            let nameserver = dns_server.to_string();
            Ok(Resolver {
                nameserver,
                search_list,
            })
        } else {
            Err(ResolverLookupError::NoNameserver)
        }
    }

    pub async fn send(&self, query: &[u8]) -> Result<Vec<u8>, io::Error> {
        async fn connect_and_query(nameserver: IpAddr, query: &[u8]) -> Result<Vec<u8>, io::Error> {
            // Choose to use either ipv6 or ipv4 addr to bind to
            let local_addr = match nameserver {
                IpAddr::V6(_) => IpAddr::from(Ipv6Addr::UNSPECIFIED),
                IpAddr::V4(_) => IpAddr::from(Ipv4Addr::UNSPECIFIED),
            };
            let socket = UdpSocket::bind((local_addr, 0)).await?;
            // established the connection
            socket.connect((nameserver, 53)).await?;
            // send the query
            let _sent = socket.send(query).await?;
            // read the response
            let mut response = vec![0; 512];
            let response_len = socket
                .recv(&mut response)
                .await
                .map_err(|_err| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
            // limit the response to the read length
            response.truncate(response_len);
            Ok(response)
        }

        // Try each nameserver
        let result = match self.nameservers.len() {
            0 => unreachable!(),
            1 => {
                io::timeout(
                    Duration::from_secs(200),
                    connect_and_query(self.nameservers[0], query),
                )
                .await
            }
            2 => {
                io::timeout(
                    Duration::from_secs(200),
                    connect_and_query(self.nameservers[0], query)
                        .try_race(connect_and_query(self.nameservers[1], query)),
                )
                .await
            }
            3 => {
                io::timeout(
                    Duration::from_secs(200),
                    connect_and_query(self.nameservers[0], query)
                        .try_race(connect_and_query(self.nameservers[1], query))
                        .try_race(connect_and_query(self.nameservers[2], query)),
                )
                .await
            }
            _ => {
                io::timeout(
                    Duration::from_secs(200),
                    connect_and_query(self.nameservers[0], query)
                        .try_race(connect_and_query(self.nameservers[1], query))
                        .try_race(connect_and_query(self.nameservers[2], query))
                        .try_race(connect_and_query(self.nameservers[3], query)),
                )
                .await
            }
        };
        match result {
            Ok(result) => Ok(result),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Resolv timeout")),
        }
    }
}
