use crate::api::X509Iterator;
use crate::{X509ClientError, X509ClientResult};
use http::header::CONTENT_TYPE;
use http::HeaderMap;
use std::marker::PhantomData;
use std::path::Path;

#[derive(Clone, PartialEq, Debug)]
pub enum X509Type {
    Cer,
    Pkcs7,
    Pem,
    Unknown,
}

impl From<&Path> for X509Type {
    fn from(path: &Path) -> Self {
        match path.extension() {
            None => X509Type::Unknown,
            Some(extension) => match extension.to_string_lossy().to_lowercase().as_str() {
                "cer" => X509Type::Cer,
                "p7c" => X509Type::Pkcs7,
                "pem" => X509Type::Pem,
                _ => X509Type::Unknown,
            },
        }
    }
}

impl From<&HeaderMap> for X509Type {
    fn from(headers: &HeaderMap) -> Self {
        match headers.get(CONTENT_TYPE) {
            None => X509Type::Unknown,
            Some(header) => match header.to_str() {
                Ok(header) => match header.to_lowercase().as_str() {
                    "application/pkix-cert" => X509Type::Cer,
                    "application/pkcs7-mime" => X509Type::Pkcs7,
                    "application/pem-certificate-chain" => X509Type::Pem,
                    _ => X509Type::Unknown,
                },
                Err(_) => X509Type::Unknown,
            },
        }
    }
}

#[derive(Clone)]
pub struct X509Parse<X: X509Iterator> {
    strict: bool,
    x509_iterator: PhantomData<X>,
}

impl<X: X509Iterator> X509Parse<X>
where
    X509ClientError: From<X::X509IteratorError>,
{
    pub fn new(strict: bool) -> Self {
        Self {
            strict,
            x509_iterator: PhantomData,
        }
    }

    pub fn parse<T: AsRef<[u8]>>(&self, hint: &X509Type, src: T) -> X509ClientResult<X> {
        if self.strict {
            return Self::parse_strict(hint, src);
        }

        Self::parse_relaxed(hint, src)
    }

    fn parse_strict<T: AsRef<[u8]>>(expected: &X509Type, src: T) -> X509ClientResult<X> {
        let r = match expected {
            X509Type::Cer => X::from_cer(src)?,
            X509Type::Pkcs7 => X::from_pkcs7(src)?,
            X509Type::Pem => X::from_pem(src)?,
            X509Type::Unknown => {
                return Err(X509ClientError::Error(
                    "unknown type not permitted".to_string(),
                ))
            }
        };
        Ok(r)
    }

    fn parse_relaxed<T: AsRef<[u8]>>(hint: &X509Type, src: T) -> X509ClientResult<X> {
        // try hint first
        if let Ok(v) = Self::parse_strict(hint, src.as_ref()) {
            return Ok(v);
        }

        if hint != &X509Type::Cer {
            if let Ok(v) = X::from_cer(src.as_ref()) {
                return Ok(v);
            }
        }

        if hint != &X509Type::Pkcs7 {
            if let Ok(v) = X::from_pkcs7(src.as_ref()) {
                return Ok(v);
            }
        }

        if hint != &X509Type::Pem {
            if let Ok(v) = X::from_pem(src.as_ref()) {
                return Ok(v);
            }
        }

        Err(X509ClientError::Error("failed to parse".to_string()))
    }
}
