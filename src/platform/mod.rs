#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
mod native;

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub use native::*;

#[cfg(all(feature = "std", target_arch = "wasm32"))]
mod web;

#[cfg(all(feature = "std", target_arch = "wasm32"))]
pub use web::*;

#[cfg(feature = "sha2")]
pub mod sha {
    use sha2::{Digest, Sha256};

    use crate::hash::{Hasher, Sha256Digest};

    pub struct Sha256Hasher {
        inner: Sha256,
    }

    impl Sha256Hasher {
        pub fn new() -> Self {
            Self {
                inner: Sha256::new(),
            }
        }
    }

    impl Hasher for Sha256Hasher {
        type Digest = Sha256Digest;

        fn reset(&mut self) {
            self.inner.reset();
        }

        fn update(&mut self, input: &[u8]) {
            self.inner.update(input);
        }

        fn finalize_reset(&mut self) -> Self::Digest {
            Sha256Digest(self.inner.finalize_reset().into())
        }
    }
}
