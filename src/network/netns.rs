//! Container network namespaces.
//!
//! On Linux a namespace is a file (`/proc/<pid>/ns/net` or a bind mount) and
//! the process enters it with setns and comes back the same way.
//!
//! On FreeBSD it is a VNET jail named by the netns path. A process cannot
//! leave a jail, so work inside it runs in a forked child, and a netlink
//! socket for the jail is created in such a child and passed back over a
//! socketpair: the kernel handles netlink requests in the vnet the socket
//! was created in.

#[cfg(target_os = "freebsd")]
pub use self::freebsd::*;
#[cfg(target_os = "linux")]
pub use self::linux::*;

/// Borrow a namespace handle for [`super::driver::DriverInfo`].
pub trait NetnsExt {
    fn netns_ref(&self) -> NetnsRef<'_>;
}

#[cfg(target_os = "linux")]
mod linux {
    use super::NetnsExt;
    use std::fs::File;
    use std::os::fd::{AsFd, BorrowedFd};

    /// An open netns file.
    pub type Netns = File;
    pub type NetnsRef<'a> = BorrowedFd<'a>;

    impl NetnsExt for File {
        fn netns_ref(&self) -> NetnsRef<'_> {
            self.as_fd()
        }
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use super::NetnsExt;
    use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
    use crate::network::netlink::{NetlinkFamily, Socket};
    use crate::network::netlink_socket::Socket as RawSocket;
    use nix::sys::socket::{
        recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
        SockFlag, SockType, UnixAddr,
    };
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

    /// A VNET jail. A negative jid stands for the jail netavark itself runs
    /// in, which is the host side of every network.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Netns {
        jid: libc::c_int,
    }

    pub type NetnsRef<'a> = &'a Netns;

    impl NetnsExt for Netns {
        fn netns_ref(&self) -> NetnsRef<'_> {
            self
        }
    }

    impl Netns {
        pub fn host() -> Self {
            Self { jid: -1 }
        }

        pub(crate) fn jid(&self) -> libc::c_int {
            self.jid
        }

        /// Look a jail up by name. A missing jail is `NotFound`, like a
        /// missing netns file on Linux.
        pub fn open(name: &str) -> io::Result<Self> {
            let key = CString::new("name")?;
            let value = CString::new(name)?;
            let jid_key = CString::new("jid")?;
            let mut jid: libc::c_int = 0;
            let mut iov = [
                iovec(key.as_ptr() as *mut _, key.as_bytes_with_nul().len()),
                iovec(value.as_ptr() as *mut _, value.as_bytes_with_nul().len()),
                iovec(
                    jid_key.as_ptr() as *mut _,
                    jid_key.as_bytes_with_nul().len(),
                ),
                iovec(&mut jid as *mut _ as *mut _, mem::size_of::<libc::c_int>()),
            ];
            let res = unsafe { libc::jail_get(iov.as_mut_ptr(), iov.len() as libc::c_uint, 0) };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { jid: res })
        }

        /// Run `f` inside the jail. It runs in a forked child, so it can only
        /// report success or an error message back.
        pub fn run(&self, f: impl FnOnce() -> NetavarkResult<()>) -> NetavarkResult<()> {
            in_jail(self.jid, || f().map(|()| None).map_err(|e| e.to_string())).map(drop)
        }

        /// Open a netlink socket that acts in the jail's vnet.
        pub fn netlink_socket<P: NetlinkFamily>(&self) -> NetavarkResult<Socket<P>> {
            if self.jid < 0 {
                return Socket::new();
            }
            let fd = in_jail(self.jid, || {
                RawSocket::new(P::PROTOCOL)
                    .map(|s| Some(OwnedFd::from(s)))
                    .map_err(|e| format!("open netlink socket: {e}"))
            })?
            .ok_or_else(|| NetavarkError::msg("no netlink socket received from the jail"))?;
            let raw = unsafe { RawSocket::from_raw_fd(fd.into_raw_fd()) };
            Socket::from_raw(raw).wrap("init netlink socket")
        }
    }

    fn iovec(base: *mut libc::c_void, len: usize) -> libc::iovec {
        libc::iovec {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Fork, attach the child to the jail and run `child` there. The child
    /// sends back one datagram: a status byte, then either the error text
    /// or an SCM_RIGHTS fd. netavark is single threaded when this runs.
    fn in_jail(
        jid: libc::c_int,
        child: impl FnOnce() -> Result<Option<OwnedFd>, String>,
    ) -> NetavarkResult<Option<OwnedFd>> {
        let (parent_sock, child_sock) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(|e| NetavarkError::msg(format!("socketpair: {e}")))?;

        match unsafe { fork() }.map_err(|e| NetavarkError::msg(format!("fork: {e}")))? {
            ForkResult::Child => {
                drop(parent_sock);
                let outcome = if jid >= 0 && unsafe { libc::jail_attach(jid) } != 0 {
                    Err(format!(
                        "jail_attach({jid}): {}",
                        io::Error::last_os_error()
                    ))
                } else {
                    child()
                };
                let (payload, fd) = match outcome {
                    Ok(fd) => (vec![b'0'], fd),
                    Err(msg) => {
                        let mut payload = vec![b'1'];
                        payload.extend_from_slice(msg.as_bytes());
                        (payload, None)
                    }
                };
                let fds: Vec<RawFd> = fd.iter().map(|f| f.as_raw_fd()).collect();
                let cmsgs = if fds.is_empty() {
                    Vec::new()
                } else {
                    vec![ControlMessage::ScmRights(&fds)]
                };
                let _ = sendmsg::<UnixAddr>(
                    child_sock.as_raw_fd(),
                    &[IoSlice::new(&payload)],
                    &cmsgs,
                    MsgFlags::empty(),
                    None,
                );
                unsafe { libc::_exit(0) }
            }
            ForkResult::Parent { child: pid } => {
                drop(child_sock);
                let mut buf = [0u8; 4096];
                let mut cmsg = nix::cmsg_space!([RawFd; 1]);
                let (len, fd) = {
                    let mut iov = [IoSliceMut::new(&mut buf)];
                    let msg = recvmsg::<UnixAddr>(
                        parent_sock.as_raw_fd(),
                        &mut iov,
                        Some(&mut cmsg),
                        MsgFlags::empty(),
                    );
                    let status = waitpid(pid, None);
                    let msg = msg.map_err(|e| NetavarkError::msg(format!("recvmsg: {e}")))?;
                    let mut fd = None;
                    for c in msg
                        .cmsgs()
                        .map_err(|e| NetavarkError::msg(format!("cmsgs: {e}")))?
                    {
                        if let ControlMessageOwned::ScmRights(fds) = c {
                            fd = fds.first().map(|&f| unsafe { OwnedFd::from_raw_fd(f) });
                        }
                    }
                    if msg.bytes == 0 {
                        return Err(NetavarkError::msg(format!(
                            "jail child exited without a reply: {status:?}"
                        )));
                    }
                    if let Ok(WaitStatus::Signaled(_, sig, _)) = status {
                        return Err(NetavarkError::msg(format!(
                            "jail child killed by signal {sig}"
                        )));
                    }
                    (msg.bytes, fd)
                };
                if buf[0] == b'0' {
                    Ok(fd)
                } else {
                    Err(NetavarkError::msg(
                        String::from_utf8_lossy(&buf[1..len]).into_owned(),
                    ))
                }
            }
        }
    }
}
