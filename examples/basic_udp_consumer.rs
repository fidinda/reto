use std::{
    net::{IpAddr, UdpSocket},
    time::Duration,
};

use reto::{
    face::{
        buffered::{default_buffered_receiver, BufferedFaceReceiver, BufferedRecvError},
        local::default_local_face,
    },
    forwarder::ForwarderError,
    hash::Hasher,
    name::{Name, NameComponent},
    packet::{Data, Interest},
    platform::{sha::Sha256Hasher, udp::udp_face, DefaultForwarder},
    tlv::{Encode, TlvEncode},
};

// This is the analogue of and can be used in place of
//  https://github.com/named-data-iot/ndn-iot-package-over-posix/blob/master/examples/udp-basic-consumer.c
fn main() -> std::io::Result<()> {
    let own_port = std::env::args().nth(1).unwrap();
    let remote_address = std::env::args().nth(2).unwrap();
    let remote_address: IpAddr = remote_address.parse().unwrap();
    let remote_port = std::env::args().nth(3).unwrap();
    let remote_port = remote_port.parse().unwrap();
    let name_prefix_string = std::env::args().nth(4).unwrap();

    let name_prefix = Name::new();
    let name_prefix =
        name_prefix.adding_component(NameComponent::new_generic(name_prefix_string.as_bytes()));
    //for comp in name_prefix_string.split('/') {
    //    name_prefix = name_prefix.adding_component(NameComponent::new_generic(comp.as_bytes()))
    //}

    let addr = format!("127.0.0.1:{own_port}");
    println!("Connecting UDP to {addr}");
    let socket = UdpSocket::bind(addr)?;

    let mut forwarder = DefaultForwarder::default();

    let (udp_sender, udp_receiver) = udp_face(socket, remote_address, remote_port)?;
    let udp_face = forwarder.add_face(udp_sender, udp_receiver).unwrap();
    forwarder.register_name_prefix_for_forwarding(name_prefix, udp_face, 0);

    let (fs1, face1receiver) = default_local_face();
    let (mut face1sender, fr1) = default_local_face();

    let mut face1receiver = default_buffered_receiver(face1receiver);
    let _local_face = forwarder.add_face(fs1, fr1).unwrap();

    let interest = Interest::new(name_prefix, false, [1, 2, 3, 4]);
    interest.encode(&mut face1sender).unwrap();

    loop {
        match face1receiver.try_recv() {
            Ok(tlv) => {
                if tlv.typ.get() == Data::TLV_TYPE {
                    let data = Data::try_decode(tlv.val).unwrap();

                    println!(
                        "Got data with {} components",
                        interest.name.component_count()
                    );

                    let mut hasher = Sha256Hasher::new();
                    data.hash_signed_portion(&mut hasher);
                    let digest = hasher.finalize_reset();

                    if data.signature_value.bytes != digest.0 {
                        println!("Signature incorrect!");
                    }

                    println!(
                        "The message is {}",
                        String::from_utf8(data.content.unwrap().bytes.to_vec()).unwrap()
                    );
                    break;
                }
            }
            Err(BufferedRecvError::NothingReceived) => {}
            _ => panic!(),
        }

        match forwarder.forward(Some(Duration::from_millis(1))) {
            Ok(face) => {
                println!("Received on face {:?}", face);
            }
            Err(ForwarderError::NothingToForward) => {}
            Err(ForwarderError::FaceDisconnected(f)) => {
                println!("Face disconnected {:?}", f);
                break;
            }
            Err(ForwarderError::FaceUnrecoverableError(f, e)) => {
                println!("Forwarder error face {:?}, {:?}", f, e);
                break;
            }
            _ => panic!(),
        }
    }

    Ok(())
}
