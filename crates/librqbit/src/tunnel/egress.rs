// ── Egress policy enforcement ───────────────────────────────────────────────
///
/// Runtime egress policy that authorizes tunneled destinations before
/// establishing connections or UDP associations.  Hostname rules are applied
/// before DNS resolution; IP/CIDR rules after resolution.
///
/// Tracks open TCP streams and UDP associations per authenticated client key.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::ip_ranges::IpRanges;

use super::frame::{TunnelDestination, TunnelPublicKey};
use super::options;

// ── Transport kind ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressTransport {
    Tcp,
    Udp,
}

// ── Resolved destination ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ResolvedDestination {
    pub requested: TunnelDestination,
    pub selected: SocketAddr,
}

// ── Egress error ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("destination denied by policy")]
    DestinationDenied,

    #[error("DNS resolution failed: {0}")]
    Resolve(#[from] anyhow::Error),

    #[error("connection failed: {0}")]
    Connect(#[from] std::io::Error),

    #[error("operation timed out")]
    TimedOut,
}

// ── Conversion to TunnelErrorCode ───────────────────────────────────────────

impl EgressError {
    pub fn to_error_code(&self) -> super::frame::TunnelErrorCode {
        match self {
            EgressError::DestinationDenied => super::frame::TunnelErrorCode::DestinationDenied,
            EgressError::Resolve(_) => super::frame::TunnelErrorCode::HostUnreachable,
            EgressError::Connect(_) => super::frame::TunnelErrorCode::ConnectionRefused,
            EgressError::TimedOut => super::frame::TunnelErrorCode::TimedOut,
        }
    }
}

// ── Egress policy ───────────────────────────────────────────────────────────

/// Runtime egress policy that governs which destinations tunneled traffic
/// may reach.
///
/// Constructed from [`options::EgressPolicy`] configuration (Task 1) and
/// extended with per-client stream limits.
#[derive(Clone, Debug)]
pub struct EgressPolicy {
    /// Allowed TCP destination port ranges.  Only checked for TCP.
    pub allowed_tcp_ports: Vec<std::ops::RangeInclusive<u16>>,
    /// Allowed UDP destination port ranges.  Only checked for UDP.
    pub allowed_udp_ports: Vec<std::ops::RangeInclusive<u16>>,
    /// IP networks denied after DNS resolution.
    pub denied_networks: IpRanges,
    /// Maximum concurrent TCP streams per authenticated client.
    pub max_tcp_streams_per_client: usize,
    /// Maximum concurrent UDP associations per authenticated client.
    pub max_udp_associations_per_client: usize,
    /// Idle timeout for TCP streams and UDP associations.
    pub idle_timeout: Duration,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_tcp_ports: vec![1..=65535],
            allowed_udp_ports: vec![1..=65535],
            denied_networks: IpRanges::default(),
            max_tcp_streams_per_client: 256,
            max_udp_associations_per_client: 64,
            idle_timeout: Duration::from_secs(300),
        }
    }
}

impl EgressPolicy {
    /// Build a policy that blocks private, loopback, link-local, and multicast
    /// destinations (the safe default for public-internet-only tunnels).
    pub fn public_internet_only() -> Self {
        let (v4, v6) = restricted_subnets();
        Self {
            allowed_tcp_ports: vec![1..=65535],
            allowed_udp_ports: vec![1..=65535],
            denied_networks: IpRanges::new(v4, v6),
            max_tcp_streams_per_client: 256,
            max_udp_associations_per_client: 64,
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Derive runtime policy from server configuration flags.
    pub fn from_config(config: &options::EgressPolicy) -> Self {
        let mut v4_ranges: Vec<std::ops::Range<Ipv4Addr>> = Vec::new();
        let mut v6_ranges: Vec<std::ops::Range<Ipv6Addr>> = Vec::new();

        if !config.allow_loopback {
            v4_ranges.push(subnet_v4([127, 0, 0, 0], 8));
            v6_ranges.push(single_v6(Ipv6Addr::LOCALHOST));
        }
        if !config.allow_private {
            v4_ranges.push(subnet_v4([10, 0, 0, 0], 8));
            v4_ranges.push(subnet_v4([172, 16, 0, 0], 12));
            v4_ranges.push(subnet_v4([192, 168, 0, 0], 16));
            // fc00::/7 — Unique Local Addresses (ULA)
            v6_ranges.push(subnet_v6(
                [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                8,
            ));
        }
        if !config.allow_link_local {
            v4_ranges.push(subnet_v4([169, 254, 0, 0], 16));
            v6_ranges.push(subnet_v6(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                10,
            ));
        }
        if !config.allow_multicast {
            v4_ranges.push(subnet_v4([224, 0, 0, 0], 4));
            v6_ranges.push(subnet_v6(
                [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                8,
            ));
        }

        Self {
            allowed_tcp_ports: vec![1..=65535],
            allowed_udp_ports: vec![1..=65535],
            denied_networks: IpRanges::new(v4_ranges, v6_ranges),
            max_tcp_streams_per_client: 256,
            max_udp_associations_per_client: 64,
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Check whether the resolved IP address is permitted.
    pub fn check_resolved(&self, _host: &str, addr: IpAddr, _port: u16) -> Result<(), EgressError> {
        if self.denied_networks.has(addr) {
            return Err(EgressError::DestinationDenied);
        }
        Ok(())
    }

    /// Check a hostname rule before DNS resolution.
    /// Currently just ensures the port is within allowed ranges.
    pub fn check_hostname(
        &self,
        _host: &str,
        port: u16,
        transport: EgressTransport,
    ) -> Result<(), EgressError> {
        let allowed = match transport {
            EgressTransport::Tcp => &self.allowed_tcp_ports,
            EgressTransport::Udp => &self.allowed_udp_ports,
        };

        let port_allowed = allowed.iter().any(|r| r.contains(&port));
        if !port_allowed {
            return Err(EgressError::DestinationDenied);
        }
        Ok(())
    }

    /// Full authorization: check hostname, resolve, then check resolved IP.
    pub async fn authorize(
        &self,
        destination: &TunnelDestination,
        transport: EgressTransport,
    ) -> Result<ResolvedDestination, EgressError> {
        match destination {
            TunnelDestination::Domain(host, port) => {
                self.check_hostname(host, *port, transport)?;

                // Resolve on server side
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
                    .await
                    .map_err(|e| EgressError::Resolve(anyhow::anyhow!(e)))?
                    .collect();

                for addr in addrs {
                    self.check_resolved(host, addr.ip(), *port)?;
                    return Ok(ResolvedDestination {
                        requested: destination.clone(),
                        selected: addr,
                    });
                }
                Err(EgressError::DestinationDenied)
            }
            TunnelDestination::Ip(addr) => {
                self.check_resolved("", addr.ip(), addr.port())?;

                let port = addr.port();
                let allowed = match transport {
                    EgressTransport::Tcp => &self.allowed_tcp_ports,
                    EgressTransport::Udp => &self.allowed_udp_ports,
                };
                if !allowed.iter().any(|r| r.contains(&port)) {
                    return Err(EgressError::DestinationDenied);
                }

                Ok(ResolvedDestination {
                    requested: destination.clone(),
                    selected: *addr,
                })
            }
        }
    }
}

// ── CIDR helpers ───────────────────────────────────────────────────────────

fn subnet_v4(octets: [u8; 4], prefix: u8) -> std::ops::Range<Ipv4Addr> {
    let base = Ipv4Addr::from(octets);
    let shift = 32u32.saturating_sub(prefix as u32);
    let mask = if shift == 0 { 0 } else { u32::MAX << shift };
    let start_bits = u32::from_be_bytes(base.octets()) & mask;
    let end_bits = start_bits | !mask;
    Ipv4Addr::from_bits(start_bits)..Ipv4Addr::from_bits(end_bits.saturating_add(1))
}

fn subnet_v6(octets: [u8; 16], prefix: u8) -> std::ops::Range<Ipv6Addr> {
    let base = Ipv6Addr::from(octets);
    let shift = 128u32.saturating_sub(prefix as u32);
    let mask = if shift == 0 { 0 } else { u128::MAX << shift };
    let start_bits = u128::from_be_bytes(base.octets()) & mask;
    let end_bits = start_bits | !mask;
    Ipv6Addr::from_bits(start_bits)..Ipv6Addr::from_bits(end_bits.saturating_add(1))
}

fn single_v6(addr: Ipv6Addr) -> std::ops::Range<Ipv6Addr> {
    let bits = u128::from_be_bytes(addr.octets());
    Ipv6Addr::from_bits(bits)..Ipv6Addr::from_bits(bits.saturating_add(1))
}

fn restricted_subnets() -> (
    Vec<std::ops::Range<Ipv4Addr>>,
    Vec<std::ops::Range<Ipv6Addr>>,
) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    // Loopback
    v4.push(subnet_v4([127, 0, 0, 0], 8));
    v6.push(single_v6(Ipv6Addr::LOCALHOST));

    // Private (RFC 1918)
    v4.push(subnet_v4([10, 0, 0, 0], 8));
    v4.push(subnet_v4([172, 16, 0, 0], 12));
    v4.push(subnet_v4([192, 168, 0, 0], 16));

    // ULA (fc00::/7)
    v6.push(subnet_v6(
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        8,
    ));

    // Link-local
    v4.push(subnet_v4([169, 254, 0, 0], 16));
    v6.push(subnet_v6(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        10,
    ));

    // Multicast
    v4.push(subnet_v4([224, 0, 0, 0], 4));
    v6.push(subnet_v6(
        [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        8,
    ));

    (v4, v6)
}

// ── Egress tracking ─────────────────────────────────────────────────────────

/// A tracked TCP stream for a specific authenticated client.
#[derive(Debug)]
pub(crate) struct EgressTcp {
    pub stream_id: u64,
    pub client_key: TunnelPublicKey,
    pub destination: SocketAddr,
}

/// A tracked UDP association for a specific authenticated client.
#[derive(Debug)]
pub(crate) struct EgressUdpAssociation {
    pub association_id: u64,
    pub client_key: TunnelPublicKey,
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn private_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn public_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    }

    #[test]
    fn egress_policy_denies_resolved_private_address() {
        let policy = EgressPolicy::public_internet_only();
        assert!(matches!(
            policy.check_resolved("example.test", private_ip(), 443),
            Err(EgressError::DestinationDenied)
        ));
    }

    #[test]
    fn egress_policy_allows_resolved_public_address() {
        let policy = EgressPolicy::public_internet_only();
        assert!(
            policy
                .check_resolved("example.test", public_ip(), 443)
                .is_ok()
        );
    }

    #[test]
    fn egress_policy_denies_resolved_loopback() {
        let policy = EgressPolicy::public_internet_only();
        assert!(matches!(
            policy.check_resolved("localhost", IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            Err(EgressError::DestinationDenied)
        ));
    }

    #[test]
    fn egress_policy_denies_resolved_ipv6_loopback() {
        let policy = EgressPolicy::public_internet_only();
        assert!(matches!(
            policy.check_resolved("localhost", IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
            Err(EgressError::DestinationDenied)
        ));
    }

    #[test]
    fn egress_policy_denies_link_local() {
        let policy = EgressPolicy::public_internet_only();
        assert!(matches!(
            policy.check_resolved(
                "link-local.test",
                IpAddr::V4(Ipv4Addr::new(169, 254, 10, 5)),
                80
            ),
            Err(EgressError::DestinationDenied)
        ));
    }

    #[test]
    fn egress_policy_denies_multicast() {
        let policy = EgressPolicy::public_internet_only();
        assert!(matches!(
            policy.check_resolved("mcast.test", IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 9999),
            Err(EgressError::DestinationDenied)
        ));
    }

    #[test]
    fn egress_policy_denies_disallowed_port() {
        let mut policy = EgressPolicy::public_internet_only();
        policy.allowed_tcp_ports = vec![80..=80, 443..=443]; // only 80 and 443

        assert!(matches!(
            policy.check_hostname("example.test", 22, EgressTransport::Tcp),
            Err(EgressError::DestinationDenied)
        ));
        assert!(
            policy
                .check_hostname("example.test", 80, EgressTransport::Tcp)
                .is_ok()
        );
        assert!(
            policy
                .check_hostname("example.test", 443, EgressTransport::Tcp)
                .is_ok()
        );
    }

    #[test]
    fn egress_error_maps_to_tunnel_error_codes() {
        use super::super::frame::TunnelErrorCode;

        assert_eq!(
            EgressError::DestinationDenied.to_error_code(),
            TunnelErrorCode::DestinationDenied
        );
        assert_eq!(
            EgressError::Resolve(anyhow::anyhow!("test")).to_error_code(),
            TunnelErrorCode::HostUnreachable
        );
        assert_eq!(
            EgressError::Connect(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                .to_error_code(),
            TunnelErrorCode::ConnectionRefused
        );
        assert_eq!(
            EgressError::TimedOut.to_error_code(),
            TunnelErrorCode::TimedOut
        );
    }

    #[test]
    fn egress_policy_from_config_respects_flags() {
        let config = options::EgressPolicy {
            allow_private: true,
            allow_loopback: true,
            allow_link_local: true,
            allow_multicast: true,
        };
        let policy = EgressPolicy::from_config(&config);
        // With all allowed, the denied_networks should be empty, so
        // private and loopback addresses should pass
        assert!(policy.check_resolved("test", private_ip(), 443).is_ok());
        assert!(
            policy
                .check_resolved("test", IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
                .is_ok()
        );
    }
}
