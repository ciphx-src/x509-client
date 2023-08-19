use crate::provided::openssl::result::OpenSSLX509IteratorResult;
use cms::cert::x509::der::asn1::SetOfVec;
use cms::cert::x509::der::{Decode, Encode};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use openssl::x509::X509;

pub struct OpenSSLX509Parser;

impl OpenSSLX509Parser {
    pub fn from_cer<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Vec<X509>> {
        Ok(vec![X509::from_der(src.as_ref())?])
    }

    pub fn from_pem<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Vec<X509>> {
        Ok(X509::stack_from_pem(src.as_ref())?)
    }

    pub fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> OpenSSLX509IteratorResult<Vec<X509>> {
        // Rust's OpenSSL bindings do not deserialize SignedData
        // using cms crate instead

        let ci = ContentInfo::from_der(src.as_ref())?;
        let bytes = ci.content.to_der()?;
        let sd = SignedData::from_der(bytes.as_slice())?;
        let certs: SetOfVec<CertificateChoices> = match sd.certificates {
            None => return Ok(vec![]),
            Some(v) => v,
        }
        .into();

        let mut data = vec![];
        for certificate in certs.into_vec() {
            if let CertificateChoices::Certificate(certificate) = certificate {
                data.push(X509::from_der(certificate.to_der()?.as_ref())?);
            }
        }

        Ok(data)
    }
}
