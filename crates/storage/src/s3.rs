
use aws_sdk_s3::{Client, Config, Region, types::ByteStream};
use aws_smithy_types::timeout::TimeoutConfig;
use aws_types::credentials::{Credentials, SharedCredentialsProvider};

#[derive(Clone)]
pub struct S3Store {
    pub client: Client,
    pub bucket: String,
    pub public_base: String, // e.g. https://cdn.ubl.agency
}

impl S3Store {
    pub async fn new(endpoint: &str, region: &str, access_key: &str, secret_key: &str, bucket: &str, public_base: &str) -> anyhow::Result<Self> {
        let creds = Credentials::from_keys(access_key, secret_key, None);
        let cfg = aws_config::from_env()
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .region(Region::new(region.to_string()))
            .load()
            .await;
        let mut b = aws_sdk_s3::config::Builder::from(&cfg);
        if !endpoint.is_empty() {
            b = b.endpoint_url(endpoint);
        }
        let client = Client::from_conf(b.build());
        Ok(Self { client, bucket: bucket.to_string(), public_base: public_base.to_string() })
    }

    pub async fn put_json(&self, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes.to_vec()))
            .content_type("application/json")
            .send()
            .await?;
        Ok(format!("{}/{}", self.public_base.trim_end_matches('/'), key))
    }

    pub async fn put_zip(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<String> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .content_type("application/zip")
            .send()
            .await?;
        Ok(format!("{}/{}", self.public_base.trim_end_matches('/'), key))
    }
}
