use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::config::TcpAoAlgorithm;
use crate::config::TcpAoKeyConfig;

/// The TCP-AO state of a connection, from `getsockopt(TCP_AO_INFO)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpAoStatus {
    /// SendID of the key that signs outgoing segments.
    pub current_key: u8,
    /// RecvID this side asks the peer to sign with.
    pub rnext_key: u8,
    /// Segments that verified.
    pub pkt_good: u64,
    /// Segments that failed verification.
    pub pkt_bad: u64,
    /// Segments whose KeyID matched no installed key.
    pub pkt_key_not_found: u64,
    /// Segments dropped for carrying no TCP-AO option.
    pub pkt_ao_required: u64,
}

/// RFC 5926 s3.2: both MAC algorithms are truncated to 96 bits.
#[cfg(target_os = "linux")]
const TCP_AO_MAC_LEN: u8 = 12;

/// The kernel name of `algorithm`. `cmac(aes128)` is not a crypto API name:
/// the kernel takes it as RFC 5926 AES-128-CMAC-96 and derives the 16-byte
/// traffic key itself (KDF_AES_128_CMAC), so any secret length works.
#[cfg(target_os = "linux")]
fn tcp_ao_alg_name(algorithm: TcpAoAlgorithm) -> &'static str {
    match algorithm {
        TcpAoAlgorithm::HmacSha1_96 => "hmac(sha1)",
        TcpAoAlgorithm::Aes128Cmac96 => "cmac(aes128)",
    }
}

/// Writes `peer_addr` into the address field of a kernel key struct.
#[cfg(target_os = "linux")]
fn write_peer_addr(
    storage: &mut linux_raw_sys::net::__kernel_sockaddr_storage,
    peer_addr: &SocketAddr,
) {
    use libc::{sa_family_t, AF_INET, AF_INET6};

    let storage = storage as *mut _ as *mut u8;
    match peer_addr {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: AF_INET as sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*addr.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: a sockaddr_storage is larger than a sockaddr_in.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
        }
        SocketAddr::V6(addr) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: AF_INET6 as sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: a sockaddr_storage is larger than a sockaddr_in6.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const _ as *const u8,
                    storage,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn set_tcp_option<T>(socket_fd: i32, option: u32, value: &T) -> std::io::Result<()> {
    // SAFETY: `value` is a live `T` and the length passed is its size.
    let ret = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::IPPROTO_TCP,
            option as libc::c_int,
            value as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Names the kernel requirement when the kernel has no TCP-AO at all.
#[cfg(target_os = "linux")]
fn tcp_ao_error(action: &str, error: std::io::Error) -> anyhow::Error {
    if error.raw_os_error() == Some(libc::ENOPROTOOPT) {
        anyhow::anyhow!(
            "failed to {action}: {error} (TCP-AO needs Linux 6.7+ built with CONFIG_TCP_AO)"
        )
    } else {
        anyhow::anyhow!("failed to {action}: {error}")
    }
}

/// Set TCP-MD5 signature on a socket for BGP authentication (RFC 2385)
#[cfg(target_os = "linux")]
pub fn set_tcp_md5_signature(socket_fd: i32, peer_addr: &SocketAddr, password: &str) -> Result<()> {
    use linux_raw_sys::net::{tcp_md5sig, TCP_MD5SIG, TCP_MD5SIG_MAXKEYLEN};

    let password = password.as_bytes();
    if password.len() > TCP_MD5SIG_MAXKEYLEN as usize {
        anyhow::bail!("password too long (max {} bytes)", TCP_MD5SIG_MAXKEYLEN);
    }
    // SAFETY: tcp_md5sig is plain old data, for which all zeroes is valid.
    let mut md5sig: tcp_md5sig = unsafe { std::mem::zeroed() };
    write_peer_addr(&mut md5sig.tcpm_addr, peer_addr);
    md5sig.tcpm_keylen = password.len() as u16;
    md5sig.tcpm_key[..password.len()].copy_from_slice(password);

    set_tcp_option(socket_fd, TCP_MD5SIG, &md5sig)
        .map_err(|err| anyhow::anyhow!("failed to set TCP_MD5SIG: {}", err))
}

/// Stub implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_md5_signature(
    _socket_fd: i32,
    _peer_addr: &SocketAddr,
    _password: &str,
) -> Result<()> {
    anyhow::bail!("TCP-MD5 authentication is only supported on Linux (RFC 2385)")
}

/// Adds one TCP-AO master key tuple for `peer_addr` (RFC 5925). Only the IP
/// of `peer_addr` is used: Linux matches TCP-AO keys by address only, and
/// rejects a key address that carries a port. `make_current` signs with this
/// key and requests it from the peer; it is only valid before the handshake,
/// and never on a listening socket.
#[cfg(target_os = "linux")]
pub fn add_tcp_ao_key(
    socket_fd: i32,
    peer_addr: &SocketAddr,
    key: &TcpAoKeyConfig,
    make_current: bool,
) -> Result<()> {
    use linux_raw_sys::net::{tcp_ao_add, TCP_AO_ADD_KEY, TCP_AO_MAXKEYLEN};

    let secret = key.secret.as_bytes();
    if secret.is_empty() || secret.len() > TCP_AO_MAXKEYLEN as usize {
        anyhow::bail!("TCP-AO secret must be 1-{} bytes", TCP_AO_MAXKEYLEN);
    }
    // SAFETY: tcp_ao_add is plain old data, for which all zeroes is valid.
    let mut add: tcp_ao_add = unsafe { std::mem::zeroed() };
    write_peer_addr(&mut add.addr, &SocketAddr::new(peer_addr.ip(), 0));
    for (dst, src) in add
        .alg_name
        .iter_mut()
        .zip(tcp_ao_alg_name(key.algorithm).bytes())
    {
        *dst = src as _;
    }
    // A v4-mapped address on an AF_INET6 socket is keyed as IPv4.
    add.prefix = match peer_addr.ip().to_canonical() {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    add.sndid = key.send_id;
    add.rcvid = key.recv_id;
    add.maclen = TCP_AO_MAC_LEN;
    add.keylen = secret.len() as u8;
    add.key[..secret.len()].copy_from_slice(secret);
    if make_current {
        add.set_set_current(1);
        add.set_set_rnext(1);
    }

    set_tcp_option(socket_fd, TCP_AO_ADD_KEY, &add).map_err(|err| {
        tcp_ao_error(
            &format!(
                "add TCP-AO key (send_id {}, recv_id {})",
                key.send_id, key.recv_id
            ),
            err,
        )
    })
}

#[cfg(not(target_os = "linux"))]
pub fn add_tcp_ao_key(
    _socket_fd: i32,
    _peer_addr: &SocketAddr,
    _key: &TcpAoKeyConfig,
    _make_current: bool,
) -> Result<()> {
    anyhow::bail!("TCP-AO authentication is only supported on Linux (RFC 5925)")
}

/// Makes the socket drop every segment without TCP-AO, also from addresses
/// that match no key. Never set this on a listener shared with peers that do
/// not use TCP-AO.
#[cfg(target_os = "linux")]
pub fn require_tcp_ao(socket_fd: i32) -> Result<()> {
    use linux_raw_sys::net::{tcp_ao_info_opt, TCP_AO_INFO};

    // SAFETY: tcp_ao_info_opt is plain old data, for which all zeroes is valid.
    let mut info: tcp_ao_info_opt = unsafe { std::mem::zeroed() };
    info.set_ao_required(1);
    set_tcp_option(socket_fd, TCP_AO_INFO, &info).map_err(|err| tcp_ao_error("require TCP-AO", err))
}

#[cfg(not(target_os = "linux"))]
pub fn require_tcp_ao(_socket_fd: i32) -> Result<()> {
    anyhow::bail!("TCP-AO authentication is only supported on Linux (RFC 5925)")
}

#[cfg(target_os = "linux")]
fn get_tcp_ao_info(socket_fd: i32) -> std::io::Result<linux_raw_sys::net::tcp_ao_info_opt> {
    use linux_raw_sys::net::{tcp_ao_info_opt, TCP_AO_INFO};

    // SAFETY: tcp_ao_info_opt is plain old data, for which all zeroes is
    // valid; the kernel rejects a request whose reserved fields are not zero.
    let mut info: tcp_ao_info_opt = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<tcp_ao_info_opt>() as libc::socklen_t;
    // SAFETY: `info` and `len` are live and `len` is the size of `info`.
    let ret = unsafe {
        libc::getsockopt(
            socket_fd,
            libc::IPPROTO_TCP,
            TCP_AO_INFO as libc::c_int,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info)
}

/// The socket's TCP-AO state, or `None` if it carries no TCP-AO keys.
#[cfg(target_os = "linux")]
pub fn tcp_ao_status(socket_fd: i32) -> Result<Option<TcpAoStatus>> {
    match get_tcp_ao_info(socket_fd) {
        Ok(info) => Ok(Some(TcpAoStatus {
            current_key: info.current_key,
            rnext_key: info.rnext,
            pkt_good: info.pkt_good,
            pkt_bad: info.pkt_bad,
            pkt_key_not_found: info.pkt_key_not_found,
            pkt_ao_required: info.pkt_ao_required,
        })),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(err) => Err(tcp_ao_error("read TCP_AO_INFO", err)),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn tcp_ao_status(_socket_fd: i32) -> Result<Option<TcpAoStatus>> {
    anyhow::bail!("TCP-AO authentication is only supported on Linux (RFC 5925)")
}

/// Whether the running kernel implements TCP-AO (Linux 6.7+ built with
/// `CONFIG_TCP_AO`).
#[cfg(target_os = "linux")]
pub fn tcp_ao_supported() -> bool {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: plain socket(2); the descriptor is owned and closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // A kernel with TCP-AO reports that this keyless socket has no AO state;
    // one without it does not know the option.
    match get_tcp_ao_info(socket.as_raw_fd()) {
        Ok(_) => true,
        Err(err) => err.raw_os_error() == Some(libc::ENOENT),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn tcp_ao_supported() -> bool {
    false
}

/// Extension trait to set TCP-MD5 or TCP-AO on tokio TcpSocket
pub trait TcpSocketExt {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()>;

    /// Installs `keys` for `peer_addr` and makes the socket refuse segments
    /// without TCP-AO (RFC 5925). Has to happen before `connect()`, so the SYN
    /// is signed. The key marked `current`, else the first, signs.
    fn set_tcp_ao_keys(&self, peer_addr: &SocketAddr, keys: &[TcpAoKeyConfig]) -> Result<()>;
}

impl TcpSocketExt for tokio::net::TcpSocket {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()> {
        let fd = self.as_raw_fd();
        set_tcp_md5_signature(fd, peer_addr, password)
    }

    fn set_tcp_ao_keys(&self, peer_addr: &SocketAddr, keys: &[TcpAoKeyConfig]) -> Result<()> {
        let fd = self.as_raw_fd();
        let current = keys.iter().position(|key| key.current).unwrap_or(0);
        for (index, key) in keys.iter().enumerate() {
            add_tcp_ao_key(fd, peer_addr, key, index == current)?;
        }
        require_tcp_ao(fd)
    }
}

/// Extension trait for TCP-MD5 and TCP-AO on tokio TcpStream
pub trait TcpStreamExt {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()>;

    /// The connection's TCP-AO state, or `None` if it is not TCP-AO protected.
    fn tcp_ao_status(&self) -> Result<Option<TcpAoStatus>>;
}

impl TcpStreamExt for tokio::net::TcpStream {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()> {
        let fd = self.as_raw_fd();
        set_tcp_md5_signature(fd, peer_addr, password)
    }

    fn tcp_ao_status(&self) -> Result<Option<TcpAoStatus>> {
        tcp_ao_status(self.as_raw_fd())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;

    use super::*;
    use crate::config::TcpAoAlgorithm;

    fn key(send_id: u8, recv_id: u8, algorithm: TcpAoAlgorithm) -> TcpAoKeyConfig {
        TcpAoKeyConfig {
            send_id,
            recv_id,
            algorithm,
            secret: "focl-tcp-ao-unit".to_string(),
            current: false,
        }
    }

    /// A dual-stack listener sees IPv4 peers as v4-mapped addresses, so their
    /// keys go in that form; the kernel files them as IPv4 keys with a /32.
    #[test]
    fn dual_stack_listener_accepts_v4_mapped_keys() {
        if !tcp_ao_supported() {
            eprintln!("skipping: kernel has no TCP-AO");
            return;
        }
        let listener = std::net::TcpListener::bind("[::]:0").expect("bind [::]:0");
        let fd = listener.as_raw_fd();
        let mapped = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().into(), 179);
        let native = "[2001:db8::1]:179".parse().unwrap();
        for (peer, algorithm) in [
            (mapped, TcpAoAlgorithm::HmacSha1_96),
            (native, TcpAoAlgorithm::Aes128Cmac96),
        ] {
            add_tcp_ao_key(fd, &peer, &key(1, 1, algorithm), false)
                .unwrap_or_else(|error| panic!("key for {peer}: {error}"));
        }
        let md5_peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).to_ipv6_mapped().into(), 179);
        set_tcp_md5_signature(fd, &md5_peer, "md5").expect("v4-mapped MD5 key");
    }

    #[test]
    fn keyless_socket_reports_no_tcp_ao() {
        if !tcp_ao_supported() {
            eprintln!("skipping: kernel has no TCP-AO");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        assert_eq!(tcp_ao_status(listener.as_raw_fd()).unwrap(), None);
    }

    /// The kernel refuses a second MKT with the same KeyID for one peer,
    /// which is why config validation insists on unique ids.
    #[test]
    fn kernel_rejects_duplicate_key_ids_for_one_peer() {
        if !tcp_ao_supported() {
            eprintln!("skipping: kernel has no TCP-AO");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let peer = "192.0.2.1:179".parse().unwrap();
        let first = key(7, 7, TcpAoAlgorithm::HmacSha1_96);
        add_tcp_ao_key(listener.as_raw_fd(), &peer, &first, false).expect("first key");
        assert!(add_tcp_ao_key(listener.as_raw_fd(), &peer, &first, false).is_err());
    }
}
