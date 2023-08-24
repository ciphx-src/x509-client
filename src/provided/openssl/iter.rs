use crate::api::X509Iterator;
use crate::provided::openssl::parser::OpenSSLX509Parser;
use crate::provided::openssl::result::{OpenSSLX509IteratorError, OpenSSLX509IteratorResult};
use openssl::x509::X509;
use std::vec;

pub struct OpenSSLX509Iterator(Vec<X509>);

impl IntoIterator for OpenSSLX509Iterator {
    type Item = X509;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<<Self as IntoIterator>::Item> for OpenSSLX509Iterator {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl X509Iterator for OpenSSLX509Iterator {
    type X509IteratorError = OpenSSLX509IteratorError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Self> {
        Ok(Self(OpenSSLX509Parser::from_cer(src)?))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Self> {
        Ok(Self(OpenSSLX509Parser::from_pem(src)?))
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Self> {
        Ok(Self(OpenSSLX509Parser::from_pkcs7(src)?))
    }
}
