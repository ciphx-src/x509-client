use crate::api::X509Iterator;
use crate::X509ClientError;

pub struct TestX509Iterator;

pub const FAIL_ON_CER: u8 = 0u8;
pub const FAIL_ON_PEM: u8 = 1u8;
pub const FAIL_ON_PKCS7: u8 = 2u8;
pub const FAIL_NEVER: u8 = 3u8;
pub const FAIL_ON_ANY: u8 = 4u8;

impl IntoIterator for TestX509Iterator {
    type Item = ();
    type IntoIter = std::iter::Empty<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::empty()
    }
}

impl FromIterator<<Self as IntoIterator>::Item> for TestX509Iterator {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(_: T) -> Self {
        Self
    }
}

impl X509Iterator for TestX509Iterator {
    type X509IteratorError = X509ClientError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        if src.as_ref().contains(&FAIL_ON_CER) || src.as_ref().contains(&FAIL_ON_ANY) {
            return Err(Self::X509IteratorError::Error(
                "from_der failure".to_string(),
            ));
        }
        Ok(Self)
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        if src.as_ref().contains(&FAIL_ON_PEM) || src.as_ref().contains(&FAIL_ON_ANY) {
            return Err(Self::X509IteratorError::Error(
                "from_pem failure".to_string(),
            ));
        }
        Ok(Self)
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        if src.as_ref().contains(&FAIL_ON_PKCS7) || src.as_ref().contains(&FAIL_ON_ANY) {
            return Err(Self::X509IteratorError::Error(
                "from_pkcs7 failure".to_string(),
            ));
        }
        Ok(Self)
    }
}
