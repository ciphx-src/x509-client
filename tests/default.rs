use cms::cert::x509::Certificate;
use std::io;
use std::path::Path;
use url::Url;
use x509_client::provided::default::DefaultX509Iterator;
use x509_client::X509Client;
use x509_client::X509ClientConfiguration;

mod reqwest;

#[tokio::test]
async fn limit() {
    let limit_config = X509ClientConfiguration {
        strict: true,
        files: false,
        limit: Some(600),
        http_client: None,
    };
    let no_limit_config = X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    };

    let url_small = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com.cer",
    )
    .unwrap();

    let url_large = Url::parse(
        "https://identity.vandelaybank.com:4443/certificates/kim@id.vandelaybank.com-fullchain.pem",
    )
    .unwrap();

    let client = build_client(limit_config.clone()).await.unwrap();
    assert!(client.get_all(&url_small).await.is_ok());

    let client = build_client(no_limit_config).await.unwrap();
    assert!(client.get_all(&url_large).await.is_ok());

    let client = build_client(limit_config).await.unwrap();
    assert!(client.get_all(&url_large).await.is_err());
}

#[tokio::test]
async fn files() {
    let file_config = X509ClientConfiguration {
        strict: true,
        files: true,
        limit: None,
        http_client: None,
    };

    let no_file_config = X509ClientConfiguration {
        strict: true,
        files: false,
        limit: None,
        http_client: None,
    };

    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("pki-test-framework/identity/vandelaybank.com/kim@id.vandelaybank.com.cer");
    let file = Url::from_file_path(&file).unwrap();

    let client = build_client(file_config).await.unwrap();
    assert!(client.get_all(&file).await.is_ok());

    let client = build_client(no_file_config).await.unwrap();
    assert!(client.get_all(&file).await.is_err());
}

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

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
        .collect::<Vec<Certificate>>();

    assert_eq!(2, certificates.len());
}

async fn build_client(
    mut config: X509ClientConfiguration,
) -> io::Result<X509Client<DefaultX509Iterator>> {
    config.http_client = Some(reqwest::build_client().await?);
    Ok(X509Client::new(config))
}
