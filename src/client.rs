use crate::api::X509Iterator;
use crate::parse::{X509Parse, X509Type};
use crate::{X509ClientError, X509ClientResult};
use log::debug;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use url::Url;
#[cfg(not(test))]
use {crate::reqwest::Client, bytes::BytesMut};

/// X509 Client Configuration
#[derive(Clone, Default)]
pub struct X509ClientConfiguration {
    /// If true, only attempt parse once.
    /// Use either filename extension or http header to determine type.
    /// If false, attempt to parse from all known formats before returning error.
    pub strict: bool,

    /// If true, allow `File` transport scheme.
    /// If false, transport attempts will fail for `File` scheme.
    pub files: bool,

    /// Limits max transfer size in bytes. If None, apply no limit.
    pub limit: Option<usize>,

    /// Optional Reqwest client.
    /// If None, a default Reqwest client will be instantiated.
    #[cfg(not(test))]
    pub http_client: Option<Client>,

    #[cfg(test)]
    pub test_client: TestClient,
}

// pub trait X509HttpClient {
//     fn get<U: IntoUrl>(
//         &self,
//         url: U,
//     ) -> X509ClientResult<impl Future<Output = Result<Response, crate::Error>>>;
// }

#[cfg(test)]
#[derive(Clone, Default)]
pub struct TestClient {
    pub headers: http::HeaderMap,
    pub bytes: bytes::Bytes,
}

/// X509 Transport and Deserialize client
#[derive(Clone)]
pub struct X509Client<X: X509Iterator> {
    parser: X509Parse<X>,
    #[cfg(not(test))]
    http_client: Client,
    #[cfg(test)]
    test_client: TestClient,
    files: bool,
    limit: Option<usize>,
}

impl<X: X509Iterator> X509Client<X>
where
    X509ClientError: From<X::X509IteratorError>,
{
    /// Instantiate X509 Client with supplied configuration
    pub fn new(config: X509ClientConfiguration) -> Self {
        X509Client {
            parser: X509Parse::new(config.strict),
            #[cfg(not(test))]
            http_client: config.http_client.unwrap_or_default(),
            #[cfg(test)]
            test_client: config.test_client,
            files: config.files,
            limit: config.limit,
        }
    }

    /// Transfer and deserialize certificates, returning the first one or error on empty.
    pub async fn get(&self, url: &Url) -> X509ClientResult<X::Item> {
        self.get_all(url)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| X509ClientError::Error("no certificates found".to_string()))
    }

    /// Transfer and deserialize certificates, returning all. May be empty, depending on the deserialization implementation.
    pub async fn get_all(&self, url: &Url) -> X509ClientResult<X> {
        debug!(target:"x509-client", "attempting certificate(s) download: {}", url);

        match url.scheme() {
            "file" => {
                if !self.files {
                    return Err(X509ClientError::Error(
                        "file scheme not permitted".to_string(),
                    ));
                }
                let path = url.to_file_path().map_err(|_| {
                    X509ClientError::Error(format!("cannot parse file url {}", url))
                })?;
                self.file_read_certificates(path.as_path()).await
            }
            _ => self.http_get_certificates(url).await,
        }
    }

    async fn file_read_certificates(&self, path: &Path) -> X509ClientResult<X> {
        let mut file = File::open(path).await?;
        let mut data = vec![];
        file.read_to_end(&mut data).await?;
        self.parser.parse(&path.into(), data)
    }

    async fn http_get_certificates(&self, origin_url: &Url) -> X509ClientResult<X> {
        #[cfg(not(test))]
        let (headers, bytes) = {
            let mut resp = self
                .http_client
                .get(origin_url.as_str())
                .send()
                .await?
                .error_for_status()?;

            let x509_type = X509Type::from(resp.headers());

            let buf = match self.limit {
                None => resp.bytes().await?,
                Some(limit) => {
                    let mut buf = BytesMut::new();
                    while let Some(b) = resp.chunk().await? {
                        buf.extend(b);
                        if buf.len() > limit {
                            return Err(X509ClientError::Error(
                                format!(
                                    "total transferred bytes {} exceeded limit {}",
                                    buf.len(),
                                    limit
                                )
                                .to_string(),
                            ));
                        }
                    }
                    buf.into()
                }
            };

            (x509_type, buf)
        };

        #[cfg(test)]
        let (headers, bytes) = {
            let _ = origin_url;
            let _ = self.limit;
            (
                X509Type::from(&self.test_client.headers),
                &self.test_client.bytes,
            )
        };

        self.parser.parse(&headers, bytes)
    }
}
impl<X: X509Iterator> Default for X509Client<X>
where
    X509ClientError: From<X::X509IteratorError>,
{
    /// Instantiate X509 Client with default configuration. Defaults are:
    /// ```
    /// use x509_client::X509ClientConfiguration;
    ///
    /// X509ClientConfiguration {
    ///         strict: false,
    ///         files: false,
    ///         limit: None,
    ///         http_client: None
    /// };
    /// ```
    fn default() -> Self {
        Self::new(X509ClientConfiguration::default())
    }
}
