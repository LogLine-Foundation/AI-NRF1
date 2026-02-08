
// After persisting receipt bytes to DB:
//
// if let Some(s3) = state.s3.clone() {
//     let key = format!("receipts/{}.json", receipt_id);
//     let public_url = s3.put_json(&key, &canonical_bytes).await?;
//     // store public_url in DB row and use it in rich URL
// }
