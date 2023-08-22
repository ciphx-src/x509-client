use crate::api::X509Iterator;
use bytes::Bytes;
use std::convert::Infallible;
use std::iter;

#[derive(Clone, Debug)]
pub struct DebugX509Iterator(Bytes);

impl From<Bytes> for DebugX509Iterator {
    fn from(bytes: Bytes) -> Self {
        Self(bytes)
    }
}

impl From<DebugX509Iterator> for Bytes {
    fn from(src: DebugX509Iterator) -> Self {
        src.0
    }
}
impl IntoIterator for DebugX509Iterator {
    type Item = Bytes;
    type IntoIter = std::iter::Once<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(self.0)
    }
}

impl FromIterator<<Self as IntoIterator>::Item> for DebugX509Iterator {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self(iter.into_iter().next().unwrap_or(Bytes::new()))
    }
}

impl X509Iterator for DebugX509Iterator {
    type X509IteratorError = Infallible;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Bytes::copy_from_slice(src.as_ref())))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Bytes::copy_from_slice(src.as_ref())))
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Bytes::copy_from_slice(src.as_ref())))
    }
}
