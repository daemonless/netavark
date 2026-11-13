//! The raw socket underneath [`super::netlink::Socket`].
//!
//! On Linux this is the `netlink-sys` crate. FreeBSD speaks the same
//! rtnetlink protocol, but `netlink-sys` does not build there because the
//! `libc` crate has no FreeBSD netlink definitions, so FreeBSD gets a
//! minimal socket with the same interface here.

#[cfg(target_os = "linux")]
pub use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

#[cfg(target_os = "freebsd")]
pub use self::freebsd::{Socket, SocketAddr, NETLINK_ROUTE};

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::io;
    use std::mem;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

    // From <sys/socket.h> and <netlink/netlink.h>.
    const AF_NETLINK: libc::c_int = 38;
    pub const NETLINK_ROUTE: isize = 0;

    #[repr(C)]
    struct sockaddr_nl {
        nl_len: u8,
        nl_family: libc::sa_family_t,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    /// A netlink address: the port id and multicast group mask.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SocketAddr {
        pid: u32,
        groups: u32,
    }

    impl SocketAddr {
        pub fn new(pid: u32, groups: u32) -> Self {
            Self { pid, groups }
        }

        fn as_raw(&self) -> sockaddr_nl {
            sockaddr_nl {
                nl_len: mem::size_of::<sockaddr_nl>() as u8,
                nl_family: AF_NETLINK as libc::sa_family_t,
                nl_pad: 0,
                nl_pid: self.pid,
                nl_groups: self.groups,
            }
        }
    }

    /// A blocking netlink socket.
    #[derive(Debug)]
    pub struct Socket(OwnedFd);

    impl Socket {
        pub fn new(protocol: isize) -> io::Result<Self> {
            let fd = unsafe {
                libc::socket(
                    AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    protocol as libc::c_int,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        pub fn bind(&mut self, addr: &SocketAddr) -> io::Result<()> {
            let raw = addr.as_raw();
            let res = unsafe {
                libc::bind(
                    self.0.as_raw_fd(),
                    &raw as *const sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<sockaddr_nl>() as libc::socklen_t,
                )
            };
            check_int(res)
        }

        /// Connect to the kernel. FreeBSD marks a netlink socket connected
        /// as soon as it is bound, so EISCONN here means it already is.
        pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
            let raw = addr.as_raw();
            let res = unsafe {
                libc::connect(
                    self.0.as_raw_fd(),
                    &raw as *const sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<sockaddr_nl>() as libc::socklen_t,
                )
            };
            match check_int(res) {
                Err(e) if e.raw_os_error() == Some(libc::EISCONN) => Ok(()),
                other => other,
            }
        }

        pub fn send(&self, buf: &[u8], flags: libc::c_int) -> io::Result<usize> {
            let res = unsafe {
                libc::send(
                    self.0.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    flags,
                )
            };
            check_len(res)
        }

        /// Read one datagram into `buf` and return its length.
        pub fn recv(&self, buf: &mut &mut [u8], flags: libc::c_int) -> io::Result<usize> {
            let res = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    flags,
                )
            };
            check_len(res)
        }
    }

    fn check_int(res: libc::c_int) -> io::Result<()> {
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn check_len(res: libc::ssize_t) -> io::Result<usize> {
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    impl From<Socket> for OwnedFd {
        fn from(s: Socket) -> OwnedFd {
            s.0
        }
    }

    impl AsRawFd for Socket {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    impl AsFd for Socket {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl FromRawFd for Socket {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Self(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}
