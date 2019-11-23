use std::io::{Error, ErrorKind};
use std::os::unix::io::FromRawFd;
use std::process;

use libc::c_char;
use netlink_packet_route::constants::{RTM_NEWADDR, RTM_NEWLINK};
use netlink_packet_route::rtnl::address::nlas::Nla;
use netlink_packet_route::rtnl::{
    AddressHeader, LinkHeader, RtnlMessage, AF_INET, AF_UNSPEC, IFF_UP, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST, RT_SCOPE_HOST,
};
use netlink_packet_route::traits::Emitable;
use netlink_packet_route::{
    AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_sys::constants::IFA_F_PERMANENT;
use netlink_sys::{Socket, SocketAddr};

use crate::util;

const LOOPBACK_NAME: *const c_char = b"lo\x00".as_ptr() as *const c_char;

pub fn setup_loopback_device() -> Result<(), Error> {
    let if_loopback = match unsafe { libc::if_nametoindex(LOOPBACK_NAME) } {
        index if index > 0 => index,
        _ => return Err(Error::last_os_error()),
    };

    let src_addr = SocketAddr::new(process::id(), 0);
    let dest_addr = SocketAddr::new(process::id(), 0);
    let mut socket = create_netlink_route_socket()?;
    socket.bind(&src_addr)?;

    {
        let mut buf = [0u8; 1024];
        let addr_msg = create_new_address_message(if_loopback);
        addr_msg.emit(&mut buf);
        socket.send_to(&buf, &dest_addr, 0)?;

        let mut buf = [0u8; 1024];
        socket.recv(&mut buf, 0)?;
        let returned = NetlinkMessage::<RtnlMessage>::deserialize(&buf)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;

        assert_eq!(addr_msg, returned);
    }

    {
        let mut buf = [0u8; 1024];
        let link_msg = create_new_link_message(if_loopback);
        link_msg.emit(&mut buf);
        socket.send_to(&buf, &dest_addr, 0)?;

        let mut buf = [0u8; 1024];
        socket.recv(&mut buf, 0)?;
        let returned = NetlinkMessage::<RtnlMessage>::deserialize(&buf)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;

        assert_eq!(link_msg, returned);
    }

    Ok(())
}

fn create_netlink_route_socket() -> Result<Socket, Error> {
    unsafe {
        util::catch_io_error(libc::socket(
            libc::PF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        ))
        .map(|fd| Socket::from_raw_fd(fd))
    }
}

fn create_new_address_message(index: u32) -> NetlinkMessage<RtnlMessage> {
    let (len, payload) = {
        let message = AddressMessage {
            header: AddressHeader {
                family: AF_INET as u8,
                prefix_len: 8,
                flags: IFA_F_PERMANENT as u8,
                scope: RT_SCOPE_HOST,
                index,
            },
            nlas: vec![
                Nla::Local(vec![127, 0, 0, 1]),
                Nla::Address(vec![127, 0, 0, 1]),
            ],
        };
        let len = message.buffer_len() as u32;
        (len, NetlinkPayload::from(RtnlMessage::NewAddress(message)))
    };

    let header =
        unsafe { create_netlink_header(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, len) };

    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    message
}

fn create_new_link_message(index: u32) -> NetlinkMessage<RtnlMessage> {
    let (len, payload) = {
        let message = LinkMessage {
            header: LinkHeader {
                interface_family: AF_UNSPEC as u8,
                link_layer_type: 0,
                index,
                flags: IFF_UP,
                change_mask: IFF_UP,
            },
            nlas: Vec::new(),
        };
        let len = message.buffer_len() as u32;
        (len, NetlinkPayload::from(RtnlMessage::NewLink(message)))
    };

    let header = unsafe { create_netlink_header(RTM_NEWLINK, NLM_F_ACK, len) };

    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    message
}

unsafe fn create_netlink_header(message_type: u16, flags: u16, length: u32) -> NetlinkHeader {
    static mut COUNTER: u32 = 0;

    let sequence_number = COUNTER;
    COUNTER = COUNTER.wrapping_add(1);

    NetlinkHeader {
        length,
        message_type,
        flags: flags | NLM_F_REQUEST,
        sequence_number,
        port_number: process::id(),
    }
}
