use reqwest::{Certificate, Client, ClientBuilder};
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub async fn build_client() -> io::Result<Client> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pki-test-framework/root.pem");
    let mut file = File::open(path).await?;
    let mut data = vec![];
    file.read_to_end(&mut data).await?;
    let client = ClientBuilder::new()
        .add_root_certificate(
            Certificate::from_pem(&data)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?,
        )
        .build()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
    Ok(client)
}
