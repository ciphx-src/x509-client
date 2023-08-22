use crate::api::X509Iterator;
use bytes::Bytes;
use std::convert::Infallible;
use std::vec;

#[derive(Clone, Debug)]
pub struct DebugX509Iterator(Option<Bytes>);

impl From<Bytes> for DebugX509Iterator {
    fn from(bytes: Bytes) -> Self {
        Self(Some(bytes))
    }
}

impl From<DebugX509Iterator> for Bytes {
    fn from(src: DebugX509Iterator) -> Self {
        src.0.unwrap_or_else(Bytes::new)
    }
}
impl IntoIterator for DebugX509Iterator {
    type Item = Bytes;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .map_or_else(std::vec::Vec::new, |b| vec![b])
            .into_iter()
    }
}

impl FromIterator<<Self as IntoIterator>::Item> for DebugX509Iterator {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self(iter.into_iter().next())
    }
}

impl X509Iterator for DebugX509Iterator {
    type X509IteratorError = Infallible;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(Bytes::copy_from_slice(src.as_ref()))))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(Bytes::copy_from_slice(src.as_ref()))))
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(Bytes::copy_from_slice(src.as_ref()))))
    }
}
