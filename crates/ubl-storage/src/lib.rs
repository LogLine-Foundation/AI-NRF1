use anyhow::Result;
use aws_sdk_s3::{primitives::ByteStream, Client};

pub struct S3 {
    client: Client,
    bucket: String,
}

impl S3 {
    pub async fn new(bucket: String) -> Result<Self> {
        let conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&conf);
        Ok(Self { client, bucket })
    }

    pub async fn put_bytes(&self, key: &str, bytes: Vec<u8>) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .send()
            .await?;
        Ok(())
    }
}
