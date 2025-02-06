# Packet Structure and Parsing Approach

## What is a Packet?

A **packet** is essentially a **list of bytes** representing network data.  
For example:

```rust
let packet: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* other bytes */];
```

It is preferable to **reference** the packet (`&[u8]`) rather than copying it to avoid unnecessary memory usage and improve performance.

## Layered Structure

Once parsed, a packet is structured into **four layers**, following the OSI model:

1. **Data Link Layer** (mandatory) - e.g., MAC addresses, EtherType.
2. **Network Layer** (optional) - e.g., IPv4, IPv6.
3. **Transport Layer** (optional) - e.g., TCP, UDP.
4. **Application Layer** (optional) - e.g., HTTP, DNS.

The **Data Link Layer** is always present, while the others depend on the packet type.

### `ParsedPacket` Structure

```rust
pub struct ParsedPacket {
    /// Data Link Layer information (e.g., MAC addresses, EtherType).
    data_link: DataLink,

    /// Network Layer information (e.g., IPv4, IPv6).
    network: Option<Network>,

    /// Transport Layer information (e.g., TCP, UDP).
    transport: Option<Transport>,

    /// Application Layer information (e.g., HTTP, DNS).
    application: Option<Application>,

    /// Total size of the packet in bytes.
    pub size: usize,
}
```

## Independent Layer Parsing

Each layer must be **parsed independently** from the others.  
We do **not** use information from one layer to infer details about another.  

### **Why?**
- **Security:** Attackers can manipulate packet fields (e.g., changing port numbers).
- **Flexibility:** Some protocols do not strictly follow conventional port assignments.
- **Reliability:** Parsing should be based on raw data, not assumptions.

For example, **we do not parse an application-layer protocol based on the transport-layer port number**.  
Just because a packet has **port 80** does not mean it contains **HTTP**—it could be anything.
