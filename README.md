reto
=========

Reto is a Rust implementation of the Named Data Networking (NDN) protocols.

## Named Data Networking

In NDN the notion of _talking to someone_ is replaced with _talking about something_. So, rather than using IP addresses and ports to route the traffic we use __names__, which are hierarchical similarly to URLs.

At a high level the NDN network works like this:
- A peer *expresses an __interest__* by specifying a _name_ of the data they want retreived (or possibly a prefix of the name).
- The _network_ routes the interest to another peer that may be able to provide data for this name.
- A peer who receives the interest may *respond with a __data__* packet that has the name, the payload, and a (typically cryptographic) signature that binds these two together. Note that the data packet is fully self-contained and we are agnostic about the actual place it came from (which, among other things, enables in-network caching).

The network itself is implemented as a collection of interconnected __forwarders__, whcih are responsible for delivering the interest and data to the corresponding parties. The forwarder itself can be rather opaque, the most important part of each forwarder are the __faces__, i.e. the connections to other forwarders. Each face can be used to send or receive interests and data and is conceptually broadcast, event if many actual faces are point-to-point.

The forwarding then works as follows:
- An application can be running an embedded simple forwarder or be talking to a remote one via one of the faces. The forwarder does not care if a face belongs to a local application or a remote forwarder, the interfaces are all the same.
- The only piece of information the forwarder needs besides the faces are the _name prefixes_ on which to forward. We want to tell the forwarder "if you see an interest with name prefix N please send it over to face F since that face knows where to get the data for this prefix".
- Then, when a forwarder receives an interest it first checks if the data is stored in forwarder's cache already (since the data is self-contained we can just respond ourselves). If not, we check if we know of any faces that could respond to this interest (from their prefix registrations). If there are, we store a "breadcrumb" with information about the interest (the name and where it came from) and forward the interest to those faces. Otherwise the interest is dropped.
- On the return path the data packets collect all of the breadcrumbs to ensure that only the faces that expressed an interest in this data will receive it, thus enabling balanced flow of packets. When the forwarder receives the data packet it first checks if there are any breadcrumbs for this packet's name, if so we send the data to all the faces that have previously expressed the interest in this data, delete all the breadcrumbs, and optionally cache the data packet to satisfy future interests with the same name. If there are no breadcrumbs the data packet is dropped, which is one way to mitigate denial of service attacks.

The faces themselves can be nearly anything, from raw Ethernet/802.11/Bluetooth frames all the way to high-level protocols like TCP or WebSocket that use IP routing underneath. 

## Features

Reto provides a Rust implementation of the following:
- The type-length-value encoding that is used pervasively in all NDN protocols.
- The typed zero-allocation implementation of most of the concepts defined in v0.3 specification, particularly of interest and data packets.
- The traits for faces, as well as the implementations of the most useful ones including TCP/UDP/Socket and in-process channel-like faces.
- The implementation of a simple single-threaded forwarder useful for embedding within applications. When used in a native application on Unix or Windows there is also a forwarder that exploits non-blocking networking I/O and should be comparable in speed to async without the need for a runtime.

One possibly desirable aspect that is not covered is _routing_, which can roughly be thought of as using some global information about network topology and advertised prefixes to define the forwarding strategy to be used. Since all the routing is ultimately expressed in updating prefixes and costs on the forwarder, it is possible to have any router running together with the forwarder and periodically sending the updates.

Many of the aspects need for the actual applications, such as name space construction, signature verification, encryption, etc, can be built _on top_ of Reto. In this sense NDN is a network layer (c.f. IP) and can support many different transport layers (c.f. TCP).

## Example

The following example takes a local port, remote IP+port, and a name prefix as arguments.

It then creates a forwarder and two faces: 
- UDP based on the port and IP information above
- Local face that is based on two pairs of "channels": one side is given to the forwarder and one side remains in the application.

The local face is then registered for name prefix that was given as an argument. This means that if the forwarder receives an interest with this name prefix it will forward it to the local face.
Finally, we launch the forwarding loop and check if we have received an interest on the local face. If so, we create a simple data packet with the same name as the interest and the "Reto Data" payload. We then "sign" the packet using SHA256 and respond back to the forwarder.

If the interest with the same name arrives at the forwarder within 10 seconds (and adjustable parameter), it will be satisfied directly from the forwarder's cache without the need to send the interest to the local face.

More information is in the examples folder.

```rust
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

    let addr = format!("127.0.0.1:{own_port}");
    let socket = UdpSocket::bind(addr)?;

    let mut forwarder = DefaultForwarder::default();

    let (udp_sender, udp_receiver) = udp_face(socket, remote_address, remote_port)?;
    let _udp_face = forwarder.add_face(udp_sender, udp_receiver).unwrap();

    let (fs1, face1receiver) = default_local_face();
    let (mut face1sender, fr1) = default_local_face();

    let mut face1receiver = default_buffered_receiver(face1receiver);
    let local_face = forwarder.add_face(fs1, fr1).unwrap();
    forwarder.register_name_prefix_for_forwarding(name_prefix, local_face, 0);

    loop {
        match face1receiver.try_recv() {
            Ok(tlv) => {
                if tlv.typ.get() == Interest::TLV_TYPE {
                    let interest = Interest::try_decode(tlv.val).unwrap();

                    let payload = b"Reto Data";
                    let signature_info = SignatureInfo::new_digest_sha256();
                    let mut data = Data::new_unsigned(interest.name, payload, signature_info);

                    let mut hasher = Sha256Hasher::new();
                    data.hash_signed_portion(&mut hasher);
                    let digest = hasher.finalize_reset();
                    data.signature_value = SignatureValue {
                        bytes: digest.0.as_slice(),
                    };

                    data.encode(&mut face1sender).unwrap();
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
```

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
