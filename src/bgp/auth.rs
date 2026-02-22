use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use anyhow::Result;

/// Set TCP-MD5 signature on a socket for BGP authentication (RFC 2385)
///
/// # Safety
/// This uses libc directly and is marked unsafe due to raw pointer operations.
#[cfg(target_os = "linux")]
pub fn set_tcp_md5_signature(socket_fd: i32, peer_addr: &SocketAddr, password: &str) -> Result<()> {
    use libc::{setsockopt, socklen_t, AF_INET, AF_INET6, IPPROTO_TCP, TCP_MD5SIG};
    use std::os::raw::c_void;

    // TCP_MD5SIG requires a tcp_md5sig struct
    // struct tcp_md5sig {
    //     struct sockaddr_storage tcpm_addr;
    //     __u8 tcpm_flags;
    //     __u8 tcpm_prefixlen;
    //     __u16 tcpm_keylen;
    //     __u32 tcpm_ifindex;
    //     __u8 tcpm_key[TCP_MD5SIG_MAXKEYLEN];
    // };

    const TCP_MD5SIG_MAXKEYLEN: usize = 80;

    #[repr(C)]
    struct TcpMd5Sig {
        tcpm_addr: libc::sockaddr_storage,
        tcpm_flags: u8,
        tcpm_prefixlen: u8,
        tcpm_keylen: u16,
        tcpm_ifindex: u32,
        tcpm_key: [u8; TCP_MD5SIG_MAXKEYLEN],
    }

    let mut md5sig = TcpMd5Sig {
        tcpm_addr: unsafe { std::mem::zeroed() },
        tcpm_flags: 0,
        tcpm_prefixlen: 0,
        tcpm_keylen: 0,
        tcpm_ifindex: 0,
        tcpm_key: [0; TCP_MD5SIG_MAXKEYLEN],
    };

    // Set up address
    match peer_addr {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*addr.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    &mut md5sig.tcpm_addr as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            md5sig.tcpm_addr.ss_family = AF_INET as u16;
        }
        SocketAddr::V6(addr) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const _ as *const u8,
                    &mut md5sig.tcpm_addr as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            md5sig.tcpm_addr.ss_family = AF_INET6 as u16;
        }
    }

    // Set the password
    let password_bytes = password.as_bytes();
    if password_bytes.len() > TCP_MD5SIG_MAXKEYLEN {
        anyhow::bail!("password too long (max {} bytes)", TCP_MD5SIG_MAXKEYLEN);
    }
    md5sig.tcpm_keylen = password_bytes.len() as u16;
    md5sig.tcpm_key[..password_bytes.len()].copy_from_slice(password_bytes);

    let ret = unsafe {
        setsockopt(
            socket_fd,
            IPPROTO_TCP,
            TCP_MD5SIG,
            &md5sig as *const _ as *const c_void,
            std::mem::size_of::<TcpMd5Sig>() as socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("failed to set TCP_MD5SIG: {}", err);
    }

    Ok(())
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

/// Extension trait to set TCP-MD5 on tokio TcpSocket
pub trait TcpSocketExt {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()>;
}

impl TcpSocketExt for tokio::net::TcpSocket {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()> {
        let fd = self.as_raw_fd();
        set_tcp_md5_signature(fd, peer_addr, password)
    }
}

/// Extension trait to set TCP-MD5 on tokio TcpStream  
pub trait TcpStreamExt {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()>;
}

impl TcpStreamExt for tokio::net::TcpStream {
    fn set_md5_signature(&self, peer_addr: &SocketAddr, password: &str) -> Result<()> {
        let fd = self.as_raw_fd();
        set_tcp_md5_signature(fd, peer_addr, password)
    }
}
