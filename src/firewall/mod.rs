use crate::error::{NetavarkError, NetavarkResult};
use crate::network::internal_types::{
    PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};
use log::{debug, info};
#[cfg(target_os = "linux")]
use zbus::blocking::Connection;

#[cfg(target_os = "linux")]
pub mod firewalld;
pub mod fwnone;
#[cfg(target_os = "linux")]
pub mod nft;
pub mod state;

/// Max length of the network hash used in firewall object names.
pub const MAX_HASH_SIZE: usize = 13;

const FIREWALLD: &str = "firewalld";
const NFTABLES: &str = "nftables";
const NONE: &str = "none";

/// Firewall drivers have the ability to set up per-network firewall forwarding
/// and port mappings.
pub trait FirewallDriver {
    /// Set up firewall rules for the given network,
    fn setup_network(
        &self,
        network_setup: SetupNetwork,
        dbus_con: &Option<zbus::blocking::Connection>,
    ) -> NetavarkResult<()>;
    /// Tear down firewall rules for the given network.
    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()>;

    /// Set up port-forwarding firewall rules for a given container.
    fn setup_port_forward(
        &self,
        setup_pw: PortForwardConfig,
        dbus_con: &Option<zbus::blocking::Connection>,
    ) -> NetavarkResult<()>;
    /// Tear down port-forwarding firewall rules for a single container.
    fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()>;

    /// Return the name of the driver.
    fn driver_name(&self) -> &str;
}

/// Types of firewall backend
enum FirewallImpl {
    #[cfg(target_os = "linux")]
    Firewalld(Connection),
    #[cfg(target_os = "linux")]
    Nftables,
    Fwnone,
}

/// What firewall implementations does this system support?
fn get_firewall_impl(driver_name: Option<String>) -> NetavarkResult<FirewallImpl> {
    // It respects "firewalld", "nftables", "none".
    if let Some(driver) = driver_name {
        debug!("Forcibly using firewall driver {driver}");
        match driver.to_lowercase().as_str() {
            #[cfg(target_os = "linux")]
            FIREWALLD => {
                let conn = match Connection::system() {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(NetavarkError::wrap(
                            "Error retrieving dbus connection for requested firewall backend",
                            e.into(),
                        ))
                    }
                };
                return Ok(FirewallImpl::Firewalld(conn));
            }
            #[cfg(target_os = "linux")]
            NFTABLES => return Ok(FirewallImpl::Nftables),
            #[cfg(not(target_os = "linux"))]
            FIREWALLD | NFTABLES => {
                return Err(NetavarkError::Message(format!(
                    "firewall driver {driver} is only supported on Linux"
                )))
            }
            NONE => return Ok(FirewallImpl::Fwnone),
            any => {
                return Err(NetavarkError::Message(format!(
                    "Must provide a valid firewall backend, got {any}"
                )))
            }
        }
    }

    get_default_fw_impl()

    // Is firewalld running?
    // let conn = match Connection::system() {
    //     Ok(conn) => conn,
    //     Err(_) => return FirewallImpl::Nftables,
    // };
    // match conn.call_method(
    //     Some("org.freedesktop.DBus"),
    //     "/org/freedesktop/DBus",
    //     Some("org.freedesktop.DBus"),
    //     "GetNameOwner",
    //     &"org.fedoraproject.FirewallD1",
    // ) {
    //     Ok(_) => FirewallImpl::Firewalld(conn),
    //     Err(_) => FirewallImpl::Nftables,
    // }
}

#[cfg(default_fw = "nftables")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Nftables)
}

#[cfg(default_fw = "none")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Fwnone)
}

/// Get the preferred firewall implementation for the current system
/// configuration.
pub fn get_supported_firewall_driver(
    driver_name: Option<String>,
) -> NetavarkResult<Box<dyn FirewallDriver>> {
    match get_firewall_impl(driver_name) {
        Ok(fw) => match fw {
            #[cfg(target_os = "linux")]
            FirewallImpl::Firewalld(conn) => {
                info!("Using firewalld firewall driver");
                firewalld::new(conn)
            }
            #[cfg(target_os = "linux")]
            FirewallImpl::Nftables => {
                info!("Using nftables firewall driver");
                nft::new()
            }
            FirewallImpl::Fwnone => {
                info!("Not using firewall");
                fwnone::new()
            }
        },
        Err(e) => Err(e),
    }
}
