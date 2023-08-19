# X509 Client

X509 Client is an async X509 certificate transport and deserializer for Rust.

![CI Status](https://github.com/merlincinematic/x509-client/actions/workflows/ci.yaml/badge.svg)

## Synopsis

Supported transports:

* HTTP/S
* File

Supported encoding formats:

* CER - single DER-encoded certificate
* PEM - stack of one or more PEM-encoded certificates
* PKCS7 - DER-encoded PKCS7 certificate bundle

## Usage

Enable the `openssl` feature to have access to the builtin OpenSSL-based [`OpenSSLX509Iterator`](crate::provided::openssl::OpenSSLX509Iterator) deserializer.

````text
[dependencies]
x509_client = { version = "1.0.2", features = ["openssl"] }
````

The X509 Client is X509 format agnostic. When constructing the client, use the turbofish expression to choose the deserializer implementation.

```` rust
use x509_client::{X509Client, X509ClientConfiguration};
use x509_client::provided::openssl::OpenSSLX509Iterator;

#[tokio::test]
async fn test() {    
    // default X509 Client with the builtin OpenSSLX509Iterator 
    let client = X509Client::<OpenSSLX509Iterator>::default();    
    assert!(client.get(&url::Url::parse("http://localhost")?).await.is_ok());
    
    // Configured X509 Client with the builtin OpenSSLX509Iterator
    let client = X509Client::<OpenSSLX509Iterator>::new(X509ClientConfiguration::default());
    assert!(client.get_all(&url::Url::parse("http://localhost")?)?.into_inter().len() >= 0);
}
````

### Example

Transfer and parse a single certificate and multiple certificates, using the builtin [`OpenSSLX509Iterator`](crate::provided::openssl::OpenSSLX509Iterator) implementation.

```` rust
use x509_client::{X509Client, X509ClientConfiguration, X509ClientResult};
use x509_client::provided::openssl::OpenSSLX509Iterator;
use x509_client::reqwest::ClientBuilder;


async fn get_first_certificate(url: &url::Url) -> X509ClientResult<openssl::x509::X509> {
    // default X509 Client with the builtin OpenSSLX509Iterator 
    let client = X509Client::<OpenSSLX509Iterator>::default();    
    Ok(client.get(&url).await?)    
}

async fn get_all_certificates(url: &url::Url) -> X509ClientResult<Vec<openssl::x509::X509>> {
    // configure reqwest
    let config = X509ClientConfiguration {
        strict: true,
        files: false,
        http_client: Some(
            ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()?,
        ),
    };
        
    // Configured X509 Client with the builtin OpenSSLX509Iterator
    let client = X509Client::<OpenSSLX509Iterator>::new(config);
            
    // HTTP GET and parse all certificates, returning all
    Ok(client.get_all(&url).await?.into_iter().collect())    
}
````

### Instantiation and Configuration

A default X509 Client can be instantiated with the [crate::X509Client::default](crate::X509Client::default) trait implementation.

```` text
let client = X509Client::<OpenSSLX509Iterator>::default();
````

The X509 Client can be configured by passing the [`X509ClientConfiguration`](crate::X509ClientConfiguration) to the client [crate::X509Client::new](crate::X509Client::new) constructor:

```` text
let client = X509Client::<OpenSSLX509Iterator>::new(config);
````

The  [`X509ClientConfiguration`](crate::X509ClientConfiguration) struct is defined as:

```` rust
// Default configuration
X509ClientConfiguration {
    strict: false,
    files: false,
    http_client: None
};

pub struct X509ClientConfiguration {
    /// If true, only attempt parse once. 
    /// Use either filename extension or http header to determine type.
    /// If false, attempt to parse from all known formats before returning error.
    pub strict: bool,

    /// If true, allow `File` transport scheme.
    /// If false, transport attempts will fail for `File` scheme.
    pub files: bool,

    /// Optional Reqwest client.
    /// If None, a default Reqwest client will be instantiated.
    pub http_client: Option<x509_client::reqwest::Client>,
}
````

### Transfer and Deserialize

The [`X509Client::get`](crate::X509Client::get) method transfers and parses the first certificate, returning an error on empty.

The [`X509Client::get_all`](crate::X509Client::get_all) method transfers and parses all certificates.

## Deserialization

The client will attempt to determine the encoding of the remote certificate before parsing.

If strict configuration is enabled, the client will only attempt to parse once. The client will return an error immediately if the encoding type cannot be determined.

If strict configuration is disabled (default), the client will attempt to parse all known formats (starting with its best guess) before returning an error.

Some deserialization implementations may return an empty iterator. The text encoding specification for PKIX (PEM) [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) states that:

> Parsers MUST handle non-conforming data gracefully.

And:

> Files MAY contain multiple textual encoding instances.  This is used,
for example, when a file contains several certificates.

Implying an "empty" PEM file is valid. For this reason, the X509 Client always attempts to parse PEM last when strict is disabled.

For HTTP transport, certificate type is determined by the `Content-Type` http header:
* application/pkix-cert : CER
* application/pem-certificate-chain : PEM
* application/pkcs7-mime : PKCS7

For `File` scheme, certificate type is determined by the filename extension (.ext):
* .cer : CER
* .pem : PEM
* .p7c : PKCS7

### API

X509 Client is X509 format agnostic - the [`X509Iterator`](crate::api::X509Iterator) trait is used to define the deserializer interface.

```` rust
use std::fmt::{Debug, Display};

/// X509 Deserializer API
pub trait X509Iterator: IntoIterator
where
    Self: Sized,
{
    /// Error type
    type X509IteratorError: X509IteratorError;

    /// Attempt to deserialize, assume input is a single DER-encoded certificate
    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
    /// Attempt to deserialize, assume input is a stack of zero or more PEM-encoded certificates
    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
    /// Attempt to deserialize, assume input is a DER-encoded PKCS7 certificate bundle
    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError>;
}

/// Error type bounds
pub trait X509IteratorError: Display + Debug {}
````

### Error Handling 

An [`X509Iterator`](crate::api::X509Iterator) implementation can return any error type defined by the [`X509Iterator::X509IteratorError`](crate::api::X509Iterator::X509IteratorError) associated type, bound by the [`X509IteratorError`](crate::api::X509IteratorError) trait. The [`X509IteratorError`](crate::api::X509IteratorError) trait itself is bound only by `Display + Debug`.

Iterator errors will be surfaced to the caller in the [`X509ClientError::X509IteratorError`](crate::X509ClientError::X509IteratorError) variant.

Error conversion is implemented as:
```` rust
use std::fmt::{Debug, Display, Formatter};
use x509_client::X509ClientError;
use x509_client::api::X509IteratorError;

#[derive(Debug)]
struct MyX509IteratorError;

impl Display for MyX509IteratorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl X509IteratorError for MyX509IteratorError {}

impl From<MyX509IteratorError> for X509ClientError {
    fn from(e: MyX509IteratorError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
````

### Implementations

#### OpenSSL

The OpenSSL-based implementation [`OpenSSLX509Iterator`](crate::provided::openssl::OpenSSLX509Iterator) is available if the `openssl` feature is enabled.

#### Debug

The debug implementation [`DebugX509Iterator`](crate::provided::debug::DebugX509Iterator) is always available. It copies the bytes returned by server into a `Once<bytes::Bytes>` iterator.

