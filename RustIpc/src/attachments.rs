//! Attachments: download, upload and delete for saved items.
//!
//! File contents never pass through the JSON dispatch (it is capped at 1 MB) and never touch a
//! temporary file. Uploads read the file the user picked; downloads decrypt in memory and write
//! only the final file the user chose. The SDK does the cryptography: each attachment gets its own
//! key, wrapped by the item key when the item has one.
use std::{io::{Read,Write},path::Path,time::Duration};
use bitwarden_api_base::AuthRequired;
use bitwarden_core::Client;
use bitwarden_vault::{AttachmentFileUploadType,AttachmentView,CreateAttachmentRequest,VaultClientExt};
use zeroize::Zeroizing;
use crate::{account::{Error,Result},store::Cache,vault::{self,cipher_id,find,write_error}};

/// The size limit Bitwarden applies to one attachment, checked against the plain file.
pub const MAX_BYTES:u64=500*1024*1024;
/// Encrypted files are a little larger than their contents.
const MAX_ENCRYPTED_BYTES:u64=MAX_BYTES+64*1024;

fn absolute(path:&str)->Result<&Path>{
 let path=Path::new(path);
 if path.is_absolute()&&path.file_name().is_some(){Ok(path)}else{Err(Error::new("invalidInput","Invalid file location."))}
}
fn read_source(path:&str)->Result<(String,Zeroizing<Vec<u8>>)>{
 let path=absolute(path)?;
 let unreadable=|_|Error::new("invalidInput","That file could not be read.");
 let file=std::fs::File::open(path).map_err(unreadable)?;
 let meta=file.metadata().map_err(unreadable)?;
 if !meta.is_file(){return Err(Error::new("invalidInput","Choose a file, not a folder."))}
 if meta.len()>MAX_BYTES{return Err(Error::new("tooLarge","Attachments can be at most 500 MB."))}
 let mut data=Zeroizing::new(Vec::with_capacity(meta.len() as usize));
 file.take(MAX_BYTES+1).read_to_end(&mut data).map_err(unreadable)?;
 if data.len() as u64>MAX_BYTES{return Err(Error::new("tooLarge","Attachments can be at most 500 MB."))}
 let name=path.file_name().map(|n|n.to_string_lossy().into_owned()).unwrap_or_default();
 Ok((name,data))
}
fn loopback(host:&str)->bool{matches!(host,"localhost"|"127.0.0.1"|"[::1]"|"::1")}
/// Download and upload URLs come from the server. Only HTTPS (or loopback HTTP) is followed, and
/// the account's access token is never sent to them.
fn transfer_url(url:&str,api:&str)->Result<url::Url>{
 let bad=||Error::new("invalidResponse","The server returned an invalid attachment address.");
 let parsed=match url::Url::parse(url) {
  Ok(parsed)=>parsed,
  Err(url::ParseError::RelativeUrlWithoutBase)=>url::Url::parse(api).map_err(|_|bad())?.join(url).map_err(|_|bad())?,
  Err(_)=>return Err(bad()),
 };
 let host=parsed.host_str().ok_or_else(bad)?;
 let ok=parsed.username().is_empty()&&parsed.password().is_none()&&(parsed.scheme()=="https"||(parsed.scheme()=="http"&&loopback(host)));
 if ok{Ok(parsed)}else{Err(bad())}
}
fn transfer_client()->Result<reqwest::Client>{
 bitwarden_api_base::new_http_client_builder().redirect(reqwest::redirect::Policy::none())
  .timeout(Duration::from_secs(1800)).build().map_err(|_|Error::new("networkUnavailable","Cannot initialize secure network client."))
}
async fn fetch(url:&str,api:&str)->Result<Vec<u8>>{
 let url=transfer_url(url,api)?;
 let unavailable=|_|Error::new("networkUnavailable","The attachment could not be downloaded.");
 let mut response=transfer_client()?.get(url).send().await.map_err(unavailable)?;
 if !response.status().is_success(){return Err(Error::new("networkUnavailable","The attachment could not be downloaded."))}
 let mut data=Vec::new();
 while let Some(chunk)=response.chunk().await.map_err(unavailable)? {
  if data.len() as u64+chunk.len() as u64>MAX_ENCRYPTED_BYTES{return Err(Error::new("tooLarge","The attachment is larger than the supported size."))}
  data.extend_from_slice(&chunk);
 }
 Ok(data)
}

/// Decrypts an attachment and writes it to `destination`, the file the user picked.
pub async fn download(client:&Client,cache:&Cache,id:&str,attachment_id:&str,destination:&str)->Result<()>{
 let destination=absolute(destination)?;
 let view=vault::view(client,cache,id).await?;
 let attachment=view.attachments.iter().flatten().find(|a|a.id.as_deref()==Some(attachment_id)).cloned()
  .ok_or_else(||Error::new("notFound","Attachment not found. Sync and try again."))?;
 let cipher=find(cache,id)?.clone();
 let attachments=client.vault().attachments();
 let url=attachments.get_attachment_download_url(cipher_id(id)?,attachment_id.to_owned(),None).await
  .map_err(|e|{crate::account::log("Attachment address",&e);Error::new("networkUnavailable","The attachment could not be downloaded.")})?;
 let encrypted=fetch(&url,&cache.api).await?;
 let plain=Zeroizing::new(attachments.decrypt_buffer(cipher,attachment,&encrypted)
  .map_err(|e|{crate::account::log("Attachment decrypt",&e);Error::new("invalidResponse","The attachment could not be decrypted.")})?);
 drop(encrypted);
 let failed=|_|Error::new("storageUnavailable","The file could not be saved there.");
 let mut file=std::fs::File::create(destination).map_err(failed)?;
 file.write_all(&plain).and_then(|_|file.sync_all()).map_err(failed)
}

/// Encrypts the file at `path` and attaches it to a saved item.
pub async fn upload(client:&Client,cache:&Cache,id:&str,path:&str)->Result<()>{
 let (name,data)=read_source(path)?;
 let view=vault::view(client,cache,id).await?;
 if view.deleted_date.is_some(){return Err(Error::new("invalidInput","Restore this item from the trash before editing it."))}
 if !view.edit||view.partial{return Err(Error::new("readOnly","You don't have permission to edit this item."))}
 let cipher=find(cache,id)?.clone();
 let revision=cipher.revision_date;
 let cid=cipher_id(id)?;
 let attachments=client.vault().attachments();
 let blank=AttachmentView{id:None,url:None,size:None,size_name:None,file_name:Some(name),key:None};
 let encrypted=attachments.encrypt_buffer(cipher,blank,&data)
  .map_err(|e|{crate::account::log("Attachment encrypt",&e);Error::new("invalidInput","The file could not be encrypted.")})?;
 drop(data);
 let missing=||Error::new("invalidResponse","The file could not be encrypted.");
 let request=CreateAttachmentRequest{
  key:encrypted.attachment.key.ok_or_else(missing)?,file_name:encrypted.attachment.file_name.ok_or_else(missing)?,
  file_size:encrypted.contents.len() as u64,last_known_revision_date:revision,as_admin:false,
 };
 let created=attachments.create_attachment(cid,request).await.map_err(|e|write_error("Create attachment",e))?;
 if let Err(error)=send(client,cid,&created.attachment_id,&created.upload_url,created.file_upload_type,encrypted.contents,&cache.api).await {
  // Drop the empty slot the server reserved, as the official clients do.
  if let Err(rollback)=attachments.delete_attachment(cid,created.attachment_id.clone()).await{crate::account::log("Attachment rollback",&rollback)}
  return Err(error);
 }
 refresh(client,cid,id).await;
 Ok(())
}

async fn send(client:&Client,cipher:bitwarden_vault::CipherId,attachment_id:&str,url:&str,kind:AttachmentFileUploadType,body:Vec<u8>,api:&str)->Result<()>{
 let failed=||Error::new("networkUnavailable","The file could not be uploaded. Nothing was attached.");
 match kind {
  AttachmentFileUploadType::Azure=>{
   let response=transfer_client()?.put(transfer_url(url,api)?).header("x-ms-blob-type","BlockBlob").header("x-ms-version","2021-08-06")
    .body(body).send().await.map_err(|_|failed())?;
   if response.status().is_success(){Ok(())}else{Err(failed())}
  },
  AttachmentFileUploadType::Direct=>{
   let configurations=client.internal.get_api_configurations();
   let target=format!("{}/ciphers/{}/attachment/{}",configurations.api_config.base_path,bitwarden_api_base::urlencode(cipher.to_string()),bitwarden_api_base::urlencode(attachment_id));
   let part=reqwest::multipart::Part::bytes(body).file_name("data").mime_str("application/octet-stream").map_err(|_|failed())?;
   let request=configurations.api_config.client.post(target).with_extension(AuthRequired::Bearer).with_extension(crate::api::LongTransfer)
    .multipart(reqwest::multipart::Form::new().part("data",part));
   bitwarden_api_base::process_with_empty_response(request).await.map_err(|e|{crate::account::log("Attachment upload",&e);failed()})
  },
 }
}

/// After an upload the server bumps the item's revision date. Editing with a stale one would be
/// rejected, so take the current revision and attachment list into the local copy.
async fn refresh(client:&Client,cipher:bitwarden_vault::CipherId,id:&str){
 let result:std::result::Result<(),String>=async{
  let uuid:uuid::Uuid=id.parse().map_err(|_|"id".to_string())?;
  let response=client.internal.get_api_configurations().api_client.ciphers_api().get(uuid).await.map_err(|e|format!("{e:?}"))?;
  let repository=client.platform().state().get::<bitwarden_vault::Cipher>().map_err(|e|format!("{e:?}"))?;
  let mut stored=repository.get(cipher).await.map_err(|e|format!("{e:?}"))?.ok_or("missing")?;
  if let Some(date)=response.revision_date.as_deref().and_then(|d|d.parse().ok()){stored.revision_date=date}
  if let Some(list)=response.attachments {
   stored.attachments=Some(list.into_iter().map(|a|a.try_into()).collect::<std::result::Result<Vec<bitwarden_vault::Attachment>,_>>().map_err(|e|format!("{e:?}"))?);
  }
  repository.set(cipher,stored).await.map_err(|e|format!("{e:?}"))
 }.await;
 if let Err(error)=result{crate::account::log("Refresh after upload",&error)}
}

/// Removes one attachment from a saved item.
pub async fn delete(client:&Client,cache:&Cache,id:&str,attachment_id:&str)->Result<()>{
 let view=vault::view(client,cache,id).await?;
 if view.deleted_date.is_some(){return Err(Error::new("invalidInput","Restore this item from the trash before editing it."))}
 if !view.edit||view.partial{return Err(Error::new("readOnly","You don't have permission to edit this item."))}
 if !view.attachments.iter().flatten().any(|a|a.id.as_deref()==Some(attachment_id)){return Err(Error::new("notFound","Attachment not found. Sync and try again."))}
 client.vault().attachments().delete_attachment(cipher_id(id)?,attachment_id.to_owned()).await.map_err(|e|write_error("Delete attachment",e))?;
 Ok(())
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn transfer_urls_are_https_or_loopback() {
  let api="http://127.0.0.1:18090/api";
  assert!(transfer_url("https://attachments.example.com/a?token=x",api).is_ok());
  assert!(transfer_url("http://127.0.0.1:18090/attachments/a/b?token=x",api).is_ok());
  assert_eq!(transfer_url("/attachments/a/b",api).unwrap().as_str(),"http://127.0.0.1:18090/attachments/a/b");
  for bad in ["http://example.com/a","ftp://example.com/a","https://user:pw@example.com/a","file:///etc/passwd"] {
   assert!(transfer_url(bad,api).is_err(),"{bad}");
  }
 }
 #[test]
 fn source_files_are_validated() {
  assert!(read_source("relative.txt").is_err());
  assert!(read_source("/nonexistent/keywarden-test").is_err());
  assert!(read_source(std::env::temp_dir().to_str().unwrap()).is_err());
  let path=std::env::temp_dir().join(format!("keywarden-attach-{}.txt",std::process::id()));
  std::fs::write(&path,b"hello").unwrap();
  let (name,data)=read_source(path.to_str().unwrap()).unwrap();
  assert_eq!(&data[..],b"hello");
  assert!(name.starts_with("keywarden-attach-"));
  std::fs::remove_file(&path).unwrap();
 }
}
