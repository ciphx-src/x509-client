#![cfg(feature = "openssl")]

use openssl::x509::X509;
use std::io;
use std::path::Path;
use url::Url;
use x509_client::provided::openssl::OpenSSLX509Iterator;
use x509_client::X509Client;
use x509_client::X509ClientConfiguration;

mod reqwest;

#[tokio::test]
async fn get_cer() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();

    let url = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com.cer",
    )
    .unwrap();

    let certificates = client
        .get_all(&url)
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(1, certificates.len());
}

#[tokio::test]
async fn load_cer() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: true,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();
    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("pki-test-framework/identity/vandelaybank.com/kim@id.vandelaybank.com.cer");

    let certificates = client
        .get_all(&Url::from_file_path(&file).unwrap())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(1, certificates.len());
}

#[tokio::test]
async fn get_pkcs7() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();

    let url = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com.p7c",
    )
    .unwrap();

    let certificates = client
        .get_all(&url)
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(2, certificates.len());
}
#[tokio::test]
async fn load_pkcs7() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: true,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();

    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("pki-test-framework/identity/vandelaybank.com/kim@id.vandelaybank.com.p7c");

    let certificates = client
        .get_all(&Url::from_file_path(&file).unwrap())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(2, certificates.len());
}

#[tokio::test]
async fn get_pem() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();

    let url = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com.pem",
    )
    .unwrap();

    let certificates = client
        .get_all(&url)
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(1, certificates.len());
}

#[tokio::test]
async fn load_pem() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: true,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();
    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("pki-test-framework/identity/vandelaybank.com/kim@id.vandelaybank.com.pem");

    let certificates = client
        .get_all(&Url::from_file_path(&file).unwrap())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(1, certificates.len());
}

#[tokio::test]
async fn get_pemstack() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();

    let url = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com-fullchain.pem",
    )
    .unwrap();

    let certificates = client
        .get_all(&url)
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(2, certificates.len());
}

#[tokio::test]
async fn load_pemstack() {
    let client = build_client(X509ClientConfiguration {
        strict: true,
        files: true,
        limit: None,
        http_client: None,
    })
    .await
    .unwrap();
    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("pki-test-framework/identity/vandelaybank.com/kim@id.vandelaybank.com-fullchain.pem");

    let certificates = client
        .get_all(&Url::from_file_path(&file).unwrap())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<X509>>();

    assert_eq!(2, certificates.len());
}

async fn build_client(
    mut config: X509ClientConfiguration,
) -> io::Result<X509Client<OpenSSLX509Iterator>> {
    config.http_client = Some(reqwest::build_client().await?);
    Ok(X509Client::new(config))
}
