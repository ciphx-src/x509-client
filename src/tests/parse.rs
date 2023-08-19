use crate::parse::{X509Parse, X509Type};
use crate::tests::iter::{
    TestX509Iterator, FAIL_NEVER, FAIL_ON_ANY, FAIL_ON_CER, FAIL_ON_PEM, FAIL_ON_PKCS7,
};

#[test]
fn test_x509parse_strict() {
    let parser: X509Parse<TestX509Iterator> = X509Parse::new(true);

    assert!(parser.parse(&X509Type::Unknown, vec![FAIL_NEVER]).is_err());

    assert!(parser.parse(&X509Type::Cer, vec![FAIL_NEVER]).is_ok());
    assert!(parser.parse(&X509Type::Cer, vec![FAIL_ON_CER]).is_err());
    assert!(parser.parse(&X509Type::Cer, vec![FAIL_ON_PEM]).is_ok());
    assert!(parser.parse(&X509Type::Cer, vec![FAIL_ON_PKCS7]).is_ok());
    assert!(parser.parse(&X509Type::Cer, vec![FAIL_ON_ANY]).is_err());

    assert!(parser.parse(&X509Type::Pem, vec![FAIL_NEVER]).is_ok());
    assert!(parser.parse(&X509Type::Pem, vec![FAIL_ON_CER]).is_ok());
    assert!(parser.parse(&X509Type::Pem, vec![FAIL_ON_PEM]).is_err());
    assert!(parser.parse(&X509Type::Pem, vec![FAIL_ON_PKCS7]).is_ok());
    assert!(parser.parse(&X509Type::Pem, vec![FAIL_ON_ANY]).is_err());

    assert!(parser.parse(&X509Type::Pkcs7, vec![FAIL_NEVER]).is_ok());
    assert!(parser.parse(&X509Type::Pkcs7, vec![FAIL_ON_CER]).is_ok());
    assert!(parser.parse(&X509Type::Pkcs7, vec![FAIL_ON_PEM]).is_ok());
    assert!(parser.parse(&X509Type::Pkcs7, vec![FAIL_ON_PKCS7]).is_err());
    assert!(parser.parse(&X509Type::Pkcs7, vec![FAIL_ON_ANY]).is_err());
}

#[test]
fn test_x509parse_relaxed() {
    let parser: X509Parse<TestX509Iterator> = X509Parse::new(false);
    assert!(parser.parse(&X509Type::Unknown, vec![FAIL_NEVER]).is_ok());
    assert!(parser
        .parse(&X509Type::Unknown, vec![FAIL_ON_CER, FAIL_ON_PEM])
        .is_ok());
    assert!(parser
        .parse(&X509Type::Unknown, vec![FAIL_ON_CER, FAIL_ON_PKCS7])
        .is_ok());
    assert!(parser
        .parse(
            &X509Type::Unknown,
            vec![FAIL_ON_CER, FAIL_ON_PKCS7, FAIL_ON_PEM]
        )
        .is_err());
    assert!(parser
        .parse(&X509Type::Unknown, vec![FAIL_ON_PEM, FAIL_ON_PKCS7])
        .is_ok());

    assert!(parser.parse(&X509Type::Unknown, vec![FAIL_ON_ANY]).is_err());
}
