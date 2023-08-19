use crate::client::{TestClient, X509ClientConfiguration};
use crate::provided::debug::DebugX509Iterator;
use crate::X509Client;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue};
use std::fs;
use std::path::Path;
use url::Url;

#[tokio::test]
async fn test_client_file() {
    let certificate_file = Path::new(file!())
        .parent()
        .unwrap()
        .join("resource.resources.ciph.xxx.cer");
    let certificate_file = fs::canonicalize(&certificate_file).unwrap();

    let certificate_file = Url::from_file_path(&certificate_file).unwrap();

    let certificate_file_unknown = Path::new(file!())
        .parent()
        .unwrap()
        .join("resource.resources.ciph.xxx.?");
    let certificate_file_unknown = fs::canonicalize(&certificate_file_unknown).unwrap();

    let certificate_file_unknown = Url::from_file_path(&certificate_file_unknown).unwrap();

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: true,
        files: true,
        test_client: Default::default(),
    });

    assert!(client.get_all(&certificate_file).await.is_ok());
    assert!(client.get_all(&certificate_file_unknown).await.is_err());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: true,
        files: false,
        test_client: Default::default(),
    });

    assert!(client.get_all(&certificate_file).await.is_err());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: false,
        files: true,
        test_client: Default::default(),
    });

    assert!(client.get_all(&certificate_file_unknown).await.is_ok());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: false,
        files: false,
        test_client: Default::default(),
    });

    assert!(client.get_all(&certificate_file_unknown).await.is_err());
}

#[tokio::test]
async fn test_client_http() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/pkix-cert").unwrap(),
    );

    let mut headers_unknown_type = HeaderMap::new();
    headers_unknown_type.insert(CONTENT_TYPE, HeaderValue::from_str("?/?").unwrap());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: true,
        files: false,
        test_client: TestClient {
            headers: headers.clone(),
            bytes: Default::default(),
        },
    });

    assert!(client
        .get_all(&Url::parse("http://localhost").unwrap())
        .await
        .is_ok());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: true,
        files: false,
        test_client: TestClient {
            headers: headers_unknown_type.clone(),
            bytes: Default::default(),
        },
    });

    assert!(client
        .get_all(&Url::parse("http://localhost").unwrap())
        .await
        .is_err());

    let client = X509Client::<DebugX509Iterator>::new(X509ClientConfiguration {
        strict: false,
        files: false,
        test_client: TestClient {
            headers: headers_unknown_type.clone(),
            bytes: Default::default(),
        },
    });

    assert!(client
        .get_all(&Url::parse("http://localhost").unwrap())
        .await
        .is_ok());
}
