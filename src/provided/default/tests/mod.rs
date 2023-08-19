use crate::api::X509Iterator;
use crate::provided::default::DefaultX509Iterator;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn test_cer() {
    let certificate = load_certificate("resource.resources.ciph.xxx.cer").await;
    let iter = DefaultX509Iterator::from_cer(&certificate)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());
}

#[tokio::test]
async fn test_pem() {
    let certificate = load_certificate("resource.resources.ciph.xxx.pem").await;
    let iter = DefaultX509Iterator::from_pem(&certificate)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());
}

#[tokio::test]
async fn test_pkcs7() {
    let certificate = load_certificate("resource.resources.ciph.xxx.p7c").await;
    let iter = DefaultX509Iterator::from_pkcs7(&certificate)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());
}

#[tokio::test]
async fn test_pemstack() {
    let certificate = load_certificate("resource.resources.ciph.xxx-fullchain.pem").await;
    let iter = DefaultX509Iterator::from_pem(&certificate)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());
}

async fn load_certificate(certificate: &str) -> Vec<u8> {
    let path = Path::new(file!()).parent().unwrap().join(certificate);
    let mut file = File::open(path).await.unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).await.unwrap();
    data
}
