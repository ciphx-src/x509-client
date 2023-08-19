use crate::parse::X509Type;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue};
use std::path::PathBuf;

#[test]
fn test_x509type() {
    assert_eq!(
        X509Type::Cer,
        X509Type::from(PathBuf::from("file.cer").as_path())
    );
    assert_eq!(
        X509Type::Pem,
        X509Type::from(PathBuf::from("file.pem").as_path())
    );
    assert_eq!(
        X509Type::Pkcs7,
        X509Type::from(PathBuf::from("file.p7c").as_path())
    );
    assert_eq!(
        X509Type::Unknown,
        X509Type::from(PathBuf::from("file.?").as_path())
    );

    let mut header = HeaderMap::new();
    header.insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/pkix-cert").unwrap(),
    );
    assert_eq!(X509Type::Cer, X509Type::from(&header));

    let mut header = HeaderMap::new();
    header.insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/pem-certificate-chain").unwrap(),
    );
    assert_eq!(X509Type::Pem, X509Type::from(&header));

    let mut header = HeaderMap::new();
    header.insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/pkcs7-mime").unwrap(),
    );
    assert_eq!(X509Type::Pkcs7, X509Type::from(&header));

    let mut header = HeaderMap::new();
    header.insert(CONTENT_TYPE, HeaderValue::from_str("?").unwrap());
    assert_eq!(X509Type::Unknown, X509Type::from(&header));
}
