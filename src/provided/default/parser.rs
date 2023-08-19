use crate::provided::default::DefaultX509IteratorResult;
use cms::cert::x509::der::asn1::SetOfVec;
use cms::cert::x509::der::{Decode, Encode};
use cms::cert::x509::Certificate;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

pub struct DefaultX509Parser;

impl DefaultX509Parser {
    pub fn from_cer<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Vec<Certificate>> {
        Ok(vec![Certificate::from_der(src.as_ref())?])
    }

    pub fn from_pem<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Vec<Certificate>> {
        Ok(Certificate::load_pem_chain(src.as_ref())?)
    }

    pub fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> DefaultX509IteratorResult<Vec<Certificate>> {
        let ci = ContentInfo::from_der(src.as_ref())?;
        let sd = SignedData::from_der(ci.content.to_der()?.as_slice())?;

        match sd.certificates {
            None => Ok(vec![]),
            Some(certificates) => Ok(SetOfVec::from(certificates)
                .into_vec()
                .into_iter()
                .filter_map(|c| {
                    if let CertificateChoices::Certificate(c) = c {
                        return Some(c);
                    }
                    None
                })
                .collect::<Vec<Certificate>>()),
        }
    }
}
