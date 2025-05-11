use std::{future::Future, rc::Rc};

use async_channel::{Receiver, Sender};
use reto::*;
use smol::{block_on, LocalExecutor};


struct DummyCS {

}

impl ContentStore for DummyCS {
    type Error = ();

    fn insert<'a, 'b>(
     &'b self, 
     _name: Name<'a>, 
     _digest: [u8;32], 
     _freshness_deadline: Timestamp,
     _packet: &'a [u8]
     ) -> impl Future<Output = Result<(), Self::Error>> {
          async {
               Ok(())
          }
     }

     fn get<'a, 'b>(
          &'b self, _name: Name<'a>, _can_be_prefix: bool, _freshness_requirement: Option<Timestamp>
     ) -> impl futures_util::Future<Output = Result<Option<&'b [u8]>, Self::Error>> {
          async {
               Ok(None)
          }
     }
}


use sha2::{Sha256, Digest};

struct Sha256Hasher {
     hasher: Sha256
}

impl Hasher<32> for Sha256Hasher {
     fn update(&mut self, input: &[u8]) {
          self.hasher.update(input)
     }

     fn finalize(self) -> [u8; 32] {
          self.hasher.finalize().into()
     }
}

struct SmolPlatform {
     inner : Rc<smol::LocalExecutor<'static>>
}

impl Platform for SmolPlatform {
    type Task<T> = smol::Task<T>;

    fn spawn<T>(&self, future: impl futures_util::Future<Output = T> + 'static) -> Self::Task<T> where T: 'static {
        self.inner.spawn(future)
    }
    
    fn now() -> Timestamp {
       let ms128 = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
       Timestamp { ms_since_1970: ms128 as u64 }
    }
    
    fn sha256hasher() -> impl Hasher<32> {
        Sha256Hasher { hasher: Sha256::new() }
    }
}



enum DummyMSG {
     Channel(ChannelFaceSender, ChannelFaceReceiver)
}

impl ControlMessage for DummyMSG {
     fn apply_to_forwarder<CS, P, const MAX_PACKET_SIZE: usize, const MAX_FACE_COUNT: usize>(self, forwarder: &mut Forwarder<CS, P, MAX_PACKET_SIZE, MAX_FACE_COUNT>)
     where CS : ContentStore, P : Platform {
          println!("APPLY APPLY");
          match self {
               DummyMSG::Channel(sender, receiver) => {
                    let _ = forwarder.add_face(sender, receiver);
               },
          }
    }
}


struct ChannelFaceSender {
     sender: Sender<Vec<u8>>,
}

struct ChannelFaceReceiver {
     receiver: Receiver<Vec<u8>>,
     current_bytes: Vec<u8>
}


impl FaceSender for ChannelFaceSender {
     fn send(&mut self, bytes: &[u8]) -> impl core::future::Future<Output = Result<(), FaceError>> {
          async {
               self.sender.send(bytes.to_vec()).await.map_err(|_| FaceError::Disconnected)
          }
     }
}


impl FaceReceiver for ChannelFaceReceiver {
     fn recv(&mut self) -> impl core::future::Future<Output = Result<& [u8], FaceError>> {
          async {
               self.receiver.recv().await.map(|x| {
                    self.current_bytes = x;
                    self.current_bytes.as_slice()
               }).map_err(|_| FaceError::Disconnected)
          }    
     }
}




fn main() {

     println!("HELLO HELLO");

     let cs = DummyCS {};
     let platform = SmolPlatform { inner: Rc::new(LocalExecutor::new()) };

     let (control_sender, control_receiver) = async_channel::unbounded::<DummyMSG>();

     let (to_face_sender, to_face_receiver) = async_channel::unbounded();
     let (to_us_sender, _to_us_receiver) = async_channel::unbounded();

     let (_to_face2_sender, to_face2_receiver) = async_channel::unbounded();
     let (to_us2_sender, to_us2_receiver) = async_channel::unbounded();



     match control_sender.send_blocking(DummyMSG::Channel(
          ChannelFaceSender { sender: to_us_sender }, 
          ChannelFaceReceiver { receiver: to_face_receiver, current_bytes: Default::default() })
     ) {
        Ok(_) => { },
        Err(e) => println!("ERROR ERROR {:?}", e),
     }

     match control_sender.send_blocking(DummyMSG::Channel(
          ChannelFaceSender { sender: to_us2_sender }, 
          ChannelFaceReceiver { receiver: to_face2_receiver, current_bytes: Default::default() })
     ) {
        Ok(_) => { },
        Err(e) => println!("ERROR ERROR {:?}", e),
     }

     
     std::thread::spawn(move || {
          let _ = to_face_sender.send_blocking(vec![3,4,5]);
          let _ = to_face_sender.send_blocking(vec![6,7,8,9]);

          while let Ok(msg) = to_us2_receiver.recv_blocking() {
               println!("RECV RECV {:?}", msg);
          }
     });

     let executor = Rc::clone(&platform.inner);

     block_on(executor.run(Forwarder::<_,_,8192,256>::run(cs, control_receiver, platform)));

     println!("After block on");
}




