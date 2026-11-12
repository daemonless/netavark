//! Interface ioctls for FreeBSD.
//!
//! FreeBSD's netlink creates a cloned interface only under its cloner name
//! (`bridge0`, `epair0a`), cannot rename one, cannot move one into a jail
//! and does not manage bridge members. Those four operations are ioctls,
//! the same ones ifconfig(8) uses. Everything else (addresses, routes,
//! flags, MTU, MAC, dumps) stays on netlink.

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const IFNAMSIZ: usize = libc::IFNAMSIZ;

// <sys/ioccom.h>
const IOC_IN: libc::c_ulong = 0x8000_0000;
const IOC_OUT: libc::c_ulong = 0x4000_0000;
const IOCPARM_MASK: libc::c_ulong = 0x1fff;

const fn ioc(inout: libc::c_ulong, num: libc::c_ulong, len: usize) -> libc::c_ulong {
    inout | ((len as libc::c_ulong & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | num
}

// <sys/sockio.h>
const SIOCSIFNAME: libc::c_ulong = ioc(IOC_IN, 40, mem::size_of::<libc::ifreq>());
const SIOCSIFVNET: libc::c_ulong = ioc(IOC_IN | IOC_OUT, 90, mem::size_of::<libc::ifreq>());
const SIOCIFDESTROY: libc::c_ulong = ioc(IOC_IN, 121, mem::size_of::<libc::ifreq>());
const SIOCSDRVSPEC: libc::c_ulong = ioc(IOC_IN, 123, mem::size_of::<libc::ifdrv>());
const SIOCIFCREATE2: libc::c_ulong = ioc(IOC_IN | IOC_OUT, 124, mem::size_of::<libc::ifreq>());

// <net/if_bridgevar.h>
const BRDGADD: libc::c_ulong = 0;

/// `struct ifbreq`. BRDGADD reads only the member name; the rest of the
/// 80 bytes are STP and port fields the kernel fills on get requests,
/// kept as u32 for the C struct's alignment.
#[repr(C)]
struct ifbreq {
    ifbr_ifsname: [libc::c_char; IFNAMSIZ],
    rest: [u32; 16],
}

/// Create an interface from cloner `kind` ("bridge", "epair") and return
/// the name the kernel gave it.
pub fn create_interface(kind: &str) -> io::Result<String> {
    let mut req = ifreq(kind)?;
    ioctl(SIOCIFCREATE2, &mut req as *mut _ as *mut libc::c_void)?;
    Ok(name_from(&req.ifr_name))
}

pub fn destroy_interface(name: &str) -> io::Result<()> {
    let mut req = ifreq(name)?;
    ioctl(SIOCIFDESTROY, &mut req as *mut _ as *mut libc::c_void)
}

pub fn rename_interface(name: &str, new_name: &str) -> io::Result<()> {
    check_name(new_name)?;
    let new_name = CString::new(new_name)?;
    let mut req = ifreq(name)?;
    req.ifr_ifru.ifru_data = new_name.as_ptr() as *mut libc::c_char;
    ioctl(SIOCSIFNAME, &mut req as *mut _ as *mut libc::c_void)
}

/// Move an interface into the vnet of jail `jid`. Its addresses are gone
/// afterwards; its MAC and MTU survive.
pub fn move_to_jail(name: &str, jid: libc::c_int) -> io::Result<()> {
    let mut req = ifreq(name)?;
    req.ifr_ifru.ifru_jid = jid;
    ioctl(SIOCSIFVNET, &mut req as *mut _ as *mut libc::c_void)
}

pub fn bridge_add_member(bridge: &str, member: &str) -> io::Result<()> {
    let mut breq = ifbreq {
        ifbr_ifsname: [0; IFNAMSIZ],
        rest: [0; 16],
    };
    set_name(&mut breq.ifbr_ifsname, member)?;
    let mut drv: libc::ifdrv = unsafe { mem::zeroed() };
    set_name(&mut drv.ifd_name, bridge)?;
    drv.ifd_cmd = BRDGADD;
    drv.ifd_len = mem::size_of::<ifbreq>();
    drv.ifd_data = &mut breq as *mut _ as *mut libc::c_void;
    ioctl(SIOCSDRVSPEC, &mut drv as *mut _ as *mut libc::c_void)
}

/// The name of the interface with `index` in the current vnet.
pub fn interface_name(index: u32) -> io::Result<String> {
    let mut buf = [0 as libc::c_char; IFNAMSIZ];
    let res = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if res.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(name_from(&buf))
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    let mut req: libc::ifreq = unsafe { mem::zeroed() };
    set_name(&mut req.ifr_name, name)?;
    Ok(req)
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() >= IFNAMSIZ || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad interface name {name:?}"),
        ));
    }
    Ok(())
}

fn set_name(dst: &mut [libc::c_char; IFNAMSIZ], name: &str) -> io::Result<()> {
    check_name(name)?;
    for (d, s) in dst.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    Ok(())
}

fn name_from(buf: &[libc::c_char; IFNAMSIZ]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn ioctl(request: libc::c_ulong, arg: *mut libc::c_void) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values printed by a C program from the system headers.
    #[test]
    fn ioctl_numbers_match_the_headers() {
        assert_eq!(SIOCSIFNAME, 0x8020_6928);
        assert_eq!(SIOCSIFVNET, 0xc020_695a);
        assert_eq!(SIOCSDRVSPEC, 0x8028_697b);
        assert_eq!(SIOCIFCREATE2, 0xc020_697c);
        assert_eq!(SIOCIFDESTROY, 0x8020_6979);
        assert_eq!(mem::size_of::<ifbreq>(), 80);
        assert_eq!(mem::align_of::<ifbreq>(), 4);
    }

    #[test]
    fn names_are_checked_before_the_kernel_sees_them() {
        for bad in ["", "a\0b", "x".repeat(IFNAMSIZ).as_str()] {
            assert_eq!(
                check_name(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(check_name("epair0a").is_ok());
    }
}
