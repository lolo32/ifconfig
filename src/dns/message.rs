use std::{io, net::IpAddr};

use nom::{error::Error, sequence::tuple, streaming::take, IResult};

use super::utils::{addr_to_arpa, qname};

pub struct Message {
    ip: IpAddr,
    id: u16,
}

impl Message {
    pub const fn new(ip: IpAddr, id: u16) -> Self {
        Self { ip, id }
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut datagram = vec![
            // |                      ID                       | = Request ID
            self.id.to_be_bytes().to_vec(),
            // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
            0_u16.to_be_bytes().to_vec(),
            // |                    QDCOUNT                    | = Nb of question
            1_u16.to_be_bytes().to_vec(),
            // |                    ANCOUNT                    | = Always 0
            0_u16.to_be_bytes().to_vec(),
            // |                    NSCOUNT                    | = Always 0
            0_u16.to_be_bytes().to_vec(),
            // |                    ARCOUNT                    | = Always 0
            0_u16.to_be_bytes().to_vec(),
        ];

        // QNAME
        let mut qname = qname(&addr_to_arpa(self.ip));
        datagram.append(&mut qname);

        // |                     QTYPE                     | = PTR
        datagram.push(12_u16.to_be_bytes().to_vec());
        // |                     QCLASS                    | = IN
        datagram.push(1_u16.to_be_bytes().to_vec());

        // glue all part into a single array of byte, ready to send
        datagram.concat()
    }

    pub fn unpack<'a>(&self, data: &'a [u8]) -> IResult<&'a [u8], Option<String>> {
        let (data, id) = nom::number::streaming::be_u16(data)?;
        // if id != self.id {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         "The id of the query is not the one passed",
        //     ));
        // }

        let (data, qr) = nom::bytes::streaming::take(2_usize)(data)?;
        if (qr[0] & 0x80) == 0x00 {
            return Ok((data, None));
        }
        let (data, _unused) = nom::number::streaming::be_i64(data)?;

        Ok((&[], None))
    }
}
