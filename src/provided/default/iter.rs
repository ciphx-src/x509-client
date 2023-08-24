use crate::api::X509Iterator;
use crate::provided::default::parser::DefaultX509Parser;
use crate::provided::default::{DefaultX509IteratorError, DefaultX509IteratorResult};
use cms::cert::x509::Certificate;
use std::vec;

pub struct DefaultX509Iterator(Vec<Certificate>);

impl IntoIterator for DefaultX509Iterator {
    type Item = Certificate;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<<Self as IntoIterator>::Item> for DefaultX509Iterator {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
impl X509Iterator for DefaultX509Iterator {
    type X509IteratorError = DefaultX509IteratorError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Self> {
        Ok(Self(DefaultX509Parser::from_cer(src)?))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Self> {
        Ok(Self(DefaultX509Parser::from_pem(src)?))
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Self> {
        Ok(Self(DefaultX509Parser::from_pkcs7(src)?))
    }
}
