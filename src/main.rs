use std::{
    fs::File,
    io::Read as _,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
};

type Result<T> = std::result::Result<T, BytePacketBufferError>;

const MAX_JUMPS: usize = 5;

#[derive(Debug, Clone, Copy)]
pub enum BytePacketBufferError {
    EndOfBuffer,
    ExceededJumps,
    Exceeded63Chars,
}

#[derive(Debug, Clone, Copy)]
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        let r: [u8; 512] = std::array::from_fn(|i| i as u8);

        Self { buf: r, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn set_u8(&mut self, pos: usize, val: u8) -> Result<()> {
        if pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }

        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        if pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }

        self.set_u8(pos, (val >> 8) as u8)?;
        self.set_u8(pos + 1, (val & u8::MAX as u16) as u8)?;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }

        // get that single byte from the buffer
        let one_byte = self.buf[self.pos];

        self.pos += 1;

        Ok(one_byte)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }
        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }

        // gets the full length of the start
        // start = 20
        // len = 6
        //
        // 20..26
        Ok(&self.buf[start..start + len])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32);
        Ok(res)
    }

    fn read_qname(&mut self, out_buf: &mut String) -> Result<()> {
        let mut pos = self.pos();

        let mut has_jumped = false;
        let mut jumps_count = 0;

        let mut delim = "";

        loop {
            if jumps_count > MAX_JUMPS {
                return Err(BytePacketBufferError::ExceededJumps);
            }

            // read the first byte
            // e.g 08
            //
            // which represent the lenght of the next name we need to parse
            let len = self.get(pos)?;

            // we check if that length is a jump (a pointer to another place) so we can go to there
            // and get the name from there
            if (len & 0xC0) == 0xC0 {
                if !has_jumped {
                    self.seek(pos + 2)?;
                }

                // the next byte represent where we should jump to in the array
                //
                // 0xC00C
                //
                // the first byte is the jump (0XC0) the second (0X0C) is the pointer to go to
                // e.g 12
                let pointer_place = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | pointer_place;

                // so we reset the local position to there so the next loop parses the name
                pos = offset as usize;

                // we also need to tell if we jumped or not, so we can go back and go on
                has_jumped = true;
                jumps_count += 1;

                continue;
            } else {
                pos += 1;

                // we keep reading until we find a 0, which is the end
                if len == 0 {
                    break;
                }

                // the first delim is empty, but from the second we append `.`
                out_buf.push_str(delim);

                // we now get a slice of bytes from the current position to the specifed lenght
                let str_buffer = self.get_range(pos, len as usize)?;
                out_buf.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                // we adjust it to be `.` so the next loop puts a `.` after
                delim = ".";

                // we now jump to the next name
                pos += len as usize;
            }
        }
        // if we did not jump, then seek the main position to the local position
        // if not then we don't move from where the pointer is
        // e.g 0xC0
        if !has_jumped {
            self.seek(pos)?;
        }
        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos() >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }

        self.buf[self.pos()] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & u8::MAX as u16/*0xFF*/) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u16((val >> 16) as u16)?;
        self.write_u16((val & u16::MAX as u32/*0xFFFF*/) as u16)?;
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            // 0x3F => 63
            if len > 0x3F {
                return Err(BytePacketBufferError::Exceeded63Chars);
            }

            // we write the lenght of the next part of the qname before
            self.write_u8(len as u8)?;

            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        // we indicate that we are done by setting a null terminated character at the end
        self.write_u8(0)?;

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResultCode {
    #[default]
    NOERROR = 0,

    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl From<u8> for ResultCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // the first 2 bytes is the id
        self.id = buffer.read_u16()?;

        // flags are 2 bytes
        // e.g 81 80
        let flags = buffer.read_u16()?;

        // shifting them >> by 8 bits gets the first byte
        //
        // e.g 80 81 => 80
        let a = (flags >> 8) as u8;

        /* mask the flags with an 8 bit mask to get the other vlaue

           e.g 80 81 => 81

           bin:
            ---- this is the 80 81 in binary
            1000 0001 1000 0000 ----
                                    --- bitwise AND (&)
                  0.. 1111 1111 ----
                  ------ this is the 255 bin

                 => 1000 0000

        */
        let b = (flags & u8::MAX as u16) as u8;

        /*
        hex:
            0x8180
        bin:
            1    0000      0    0      1      1   0000   000
            QR   Opcode    AA   TC     RD     RA  RCODE  ???
        */

        /*
            bin:
                ---- this is the 80 (a) in binary
                1000 0001 -----
                                --- bitwise AND (&)
                     0..1 -----
                    --- this is 1 in binary
                => 1
        */

        self.recursion_desired = (a & 1) > 0;

        /*
            bin:
                ---- this is the 80 (a) in binary
                1000 0001 -----
                                --- bitwise AND (&)
                    0..10 -----
                    --- this is 2 in binary

                => 00
        */
        self.truncated_message = (a & 2) > 0;

        /*
            bin:
                ---- this is the 80 (a) in binary
                1000 0001 -----
                                --- bitwise AND (&)
                   0..100 -----
                   --- this is 4 in binary

                => 000
        */
        self.authoritative_answer = (a & 4) > 0;

        /*
        bin:
            ---- this is the 80 (a) in binary
            1000 0001 >> 3 => 0001 0000

            0001 0000 --------
                                ---- bitwise AND (&)
             0.. 1111 --------
            this is 15 (0xF) in binary
            => 0000

        */
        self.opcode = (a >> 3) & 0x0F;

        /*
            bin:
                ---- this is the 80 (a) in binary
                1000 0001 -----
                                --- bitwise AND (&)
                1000 0000 -----
                ---- this is 128 in binary

                => 1000 0000
        */
        self.response = (a & 128) > 0;

        /*
            bin:
                ---- this is the 81 (b) in binary
                1000 0000 -----
                                --- bitwise AND (&)
                 0.. 1111 -----
                ---- this is 15 (0x0F) in binary

                => 0000 => NOERROR
        */

        self.rescode = ResultCode::from(b & 0x0F);

        /*
            bin:
                ---- this is the 81 (b) in binary
                1000 0000 -----
                                --- bitwise AND (&)
                0..1 0000 -----
                ---- this is 16 in binary

                => 0 0000
        */
        self.checking_disabled = (b & 16) > 0;

        /*
            bin:
                ---- this is the 81 (b) in binary
                1000 0000 -----
                                --- bitwise AND (&)
                0010 0000 -----
                ---- this is 32 in binary

                => 00 0000
        */
        self.authed_data = (b & 32) > 0;

        /*
            bin:
                ---- this is the 81 (b) in binary
                1000 0000 -----
                                --- bitwise AND (&)
                0100 0000 -----
                ---- this is 64 in binary

                => 000 0000
        */
        self.z = (b & 64) > 0;

        /*
            bin:
                ---- this is the 81 (b) in binary
                1000 0000 -----
                                --- bitwise AND (&)
                1000 0000 -----
                ---- this is 128 in binary

                => 1000 0000
        */
        self.recursion_available = (b & 128) > 0;

        //let dbg_current_val =
        //    |offset: usize, buffer: &BytePacketBuffer| buffer.get(buffer.pos() + offset).unwrap();

        //dbg!(format!(
        //    "{:02X} {:02X}",
        //    dbg_current_val(0, buffer),
        //    dbg_current_val(1, buffer)
        //));

        self.questions = buffer.read_u16()?;

        //dbg!(format!(
        //    "{:02X} {:02X}",
        //    dbg_current_val(0, buffer),
        //    dbg_current_val(1, buffer)
        //));

        self.answers = buffer.read_u16()?;

        //dbg!(format!(
        //    "{:02X} {:02X}",
        //    dbg_current_val(0, buffer),
        //    dbg_current_val(1, buffer)
        //));

        self.authoritative_entries = buffer.read_u16()?;

        //dbg!(format!(
        //    "{:02X} {:02X}",
        //    dbg_current_val(0, buffer),
        //    dbg_current_val(1, buffer)
        //));

        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write_to_buffer(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            // it construct them, by shifting them to the right possition depending on how much it
            // originaly allocates
            //
            // for example
            //
            // the recursion_desired is a one bit in the begening, so we put it as is
            //
            // right after that is the truncated_message message, which is after the recursion_desired by one bit
            //
            // and so on
            //
            // after a proper construction of the bits
            //
            // we do a bit or (|) to combine them all into one 8bit to write it at once
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),

    A, // 1
    NS,
    CNAME,
    MX,
    AAAA,
}

impl Default for QueryType {
    fn default() -> Self {
        Self::UNKNOWN(0)
    }
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            Self::UNKNOWN(x) => x,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::MX => 15,
            Self::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::UNKNOWN(num),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write_to_buffer(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let type_name = self.qtype.to_num();
        buffer.write_u16(type_name)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // class

        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    // converts a raw to an ip and mask it to 255
                    //
                    // Our raw 32-bit number for 192.168.1.1
                    // let raw_addr: u32 = 0xC0A80101;
                    //
                    // // Extract the first octet: shift right 24 bits to move the highest 8 bits to the lowest position
                    // // which we put it in the last 2 bytes
                    // // 0xC0A80101 => 0x000000C0
                    // // masking it with 255 would remove the zeros, lefting with 0XC0
                    //
                    //  ((raw_addr >> 24) & 0xFF) as u8; // (0xC0A80101 >> 24) -> 0xC0 -> 192

                    // // Extract the second octet: shift right 16 bits
                    // // put it in the last 4 bytes
                    // // 0xC0A80101 => 0x0000C0A8; and masked to 255 removes the zeros => 0xC0A8
                    // ((raw_addr >> 16) & 0xFF) as u8; // (0xC0A80101 >> 16) -> 0xC0A8 >> 16 -> 0xA8 -> 168

                    // // Extract the third octet: shift right 8 bits
                    // // put it in the last 6 bytes
                    // // 0xC0A80101 => 0x00C0A801; and masked to 255 removes the zeros => 0xC0A801
                    // ((raw_addr >> 8) & 0xFF) as u8;  // (0xC0A80101 >> 8) -> 0xC0A801 >> 8 -> 0x01 -> 1
                    //

                    // // Extract the fourth octet: no shift needed (shift by 0)
                    // // hex:
                    //      0xC0A80101
                    // // bin:
                    //      11000000 10101000 00000001 00000001    --
                    //                                               -- & bitwise (both have to be 1)
                    //                             0.. 11111111    --
                    //                             -- this is 255 in binary
                    //
                    //      so we get only the first, which is `1`
                    //
                    //  ((raw_addr >> 0) & 0xFF) as u8;  // (0xC0A80101) & 0xFF -> 0x01 -> 1
                    ((raw_addr >> 24) & u8::MAX as u32) as u8,
                    ((raw_addr >> 16) & u8::MAX as u32) as u8,
                    ((raw_addr >> 8) & u8::MAX as u32) as u8,
                    (raw_addr & u8::MAX as u32) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & u16::MAX as u32) as u16,
                    (raw_addr1 & u16::MAX as u32) as u16,
                    ((raw_addr2 >> 16) & u16::MAX as u32) as u16,
                    (raw_addr2 & u16::MAX as u32) as u16,
                    ((raw_addr3 >> 16) & u16::MAX as u32) as u16,
                    (raw_addr3 & u16::MAX as u32) as u16,
                    ((raw_addr4 >> 16) & u16::MAX as u32) as u16,
                    (raw_addr4 & u16::MAX as u32) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write_to_buffer(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            Self::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;

                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octet = addr.octets();

                for o in octet {
                    buffer.write_u8(o)?;
                }
            }

            Self::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }

            Self::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }

            Self::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }

            Self::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            Self::UNKNOWN { .. } => {
                println!("nothing for now ")
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Default, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(|record| match record {
            DnsRecord::NS { domain, host, .. } if qname.ends_with(&**domain) => {
                Some((domain.as_str(), host.as_str()))
            }
            _ => None,
        })
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .copied()
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = Self::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::default();
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write_to_buffer(buffer)?;

        for question in &self.questions {
            question.write_to_buffer(buffer)?;
        }

        for rec in &self.answers {
            rec.write_to_buffer(buffer)?;
        }

        for rec in &self.authorities {
            rec.write_to_buffer(buffer)?;
        }

        for rec in &self.resources {
            rec.write_to_buffer(buffer)?;
        }

        Ok(())
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43201)).unwrap_or_else(|err| {
        panic!("something went wrong with binding a udp socker, error: {err}")
    });

    let mut packet = DnsPacket::new();

    packet.header.id = 5656;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();

    packet.write(&mut req_buffer)?;
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos()], server)
        .unwrap_or_else(|err| panic!("Failed to send the request to the server, error: {err}"));

    let mut res_buffer = BytePacketBuffer::new();
    socket
        .recv_from(&mut res_buffer.buf)
        .unwrap_or_else(|err| panic!("Failed to recive the request from the server, error: {err}"));

    DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // For now we're always starting with *a.root-servers.net*.
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    // Since it might take an arbitrary number of steps, we enter an unbounded loop.
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        // The next step is to send the query to the active server.
        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // If there are entries in the answer section, and no errors, we are done!
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // We might also get a `NXDOMAIN` reply, which is the authoritative name servers
        // way of telling us that the name doesn't exist.
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
        // record in the additional section. If this succeeds, we can switch name server
        // and retry the loop.
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        // If not, we'll have to resolve the ip of a NS record. If no NS records exist,
        // we'll go with what the last server told us.
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // Here we go down the rabbit hole by starting _another_ lookup sequence in the
        // midst of our current one. Hopefully, this will give us the IP of an appropriate
        // name server.
        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;

        // Finally, we pick a random ip from the result, and restart the loop. If no such
        // record is available, we again return the last result we got.
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

/// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<()> {
    // With a socket ready, we can go ahead and read a packet. This will
    // block until one is received.
    let mut req_buffer = BytePacketBuffer::new();

    // The `recv_from` function will write the data into the provided buffer,
    // and return the length of the data read as well as the source address.
    // We're not interested in the length, but we need to keep track of the
    // source in order to send our reply later on.
    let (_, src) = socket
        .recv_from(&mut req_buffer.buf)
        .unwrap_or_else(|err| panic!("Failed to recive from the buffer, error: {err}"));

    // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
    // a `DnsPacket`.
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create and initialize the response packet
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to the
        // target server. There's always the possibility that the query will
        // fail, in which case the `SERVFAIL` response code is set to indicate
        // as much to the client. If rather everything goes as planned, the
        // question and response records as copied into our response packet.
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }
    // Being mindful of how unreliable input data from arbitrary senders can be, we
    // need make sure that a question is actually present. If not, we return `FORMERR`
    // to indicate that the sender made something wrong.
    else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    // The only thing remaining is to encode our response and send it off!
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket
        .send_to(data, src)
        .unwrap_or_else(|err| panic!("Failed to send the data to the address, error: {err}"));

    Ok(())
}

#[allow(dead_code)]
fn from_file() {
    let mut f = File::open("response_packet.txt").unwrap();
    let mut buffer = BytePacketBuffer::new();

    #[allow(clippy::unused_io_amount)]
    f.read(&mut buffer.buf).unwrap();

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();
    println!("{packet:#?}");

    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }
}

#[allow(dead_code)]
fn from_qname() {
    let qname = "ww.yahoo.com";
    let qtype = QueryType::A;

    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43201)).unwrap();

    let mut packet = DnsPacket::new();

    packet.header.id = 67;

    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos()], server)
        .unwrap();

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();

    println!("{res_packet:#?}");
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 5333))
        .unwrap_or_else(|err| panic!("Failed to bind a new udp socket, error: {err}"));

    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {:#?}", e),
        }
    }
}
