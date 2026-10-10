//! Exporting the individual vault as a Bitwarden file. Reading such files is in `import.rs`.
//!
//! Contents never pass through the JSON dispatch (it is capped at 1 MB). An export is built in a
//! zeroizing buffer and written once, to the file the user chose in the save panel: no temporary
//! file. Formats: Bitwarden `.json`, `.csv`, and `.json (Encrypted)` in both variants. The SDK's
//! exporter writes the plain formats and the password-protected one. "Account restricted" is the
//! same JSON with every text value encrypted under the account key, as Bitwarden Desktop writes it.
use std::{io::Write,path::Path};
use bitwarden_core::Client;
use bitwarden_crypto::{KeyEncryptable,SymmetricCryptoKey};
use bitwarden_encoding::B64;
use bitwarden_exporters::{ExportFormat,ExporterClientExt};
use bitwarden_vault::{Cipher,Folder};
use serde_json::{Value,json};
use zeroize::Zeroizing;
use crate::account::{Error,Result};

pub(crate) const VALIDATION_FIELD:&str="encKeyValidation_DO_NOT_EDIT";

pub(crate) fn absolute(path:&str)->Result<&Path>{
 let path=Path::new(path);
 if path.is_absolute()&&path.file_name().is_some(){Ok(path)}else{Err(Error::new("invalidInput","Invalid file location."))}
}

// MARK: Export

/// What was written: item and folder counts, and how many vault items the format cannot hold.
pub struct Exported{pub items:usize,pub folders:usize,pub omitted:usize}
impl Exported{pub fn json(&self)->Value{json!({"items":self.items,"folders":self.folders,"omitted":self.omitted})}}

pub async fn export(client:&Client,cache:&crate::store::Cache,format:&str,file_password:Option<String>,path:&str)->Result<Exported>{
 let path=absolute(path)?;
 if !path.parent().is_some_and(|parent|parent.is_dir()){return Err(Error::new("invalidInput","The folder to save in does not exist."))}
 if !matches!(format,"json"|"csv"|"jsonEncryptedPassword"|"jsonEncryptedAccount"){return Err(Error::new("invalidInput","Unknown export format."))}
 if format=="jsonEncryptedPassword"&&file_password.as_deref().is_none_or(str::is_empty){return Err(Error::new("invalidInput","Enter a file password."))}
 // Only the individual vault: no organization items, and nothing from the trash.
 let ciphers:Vec<Cipher>=cache.ciphers.iter().filter(|c|c.organization_id.is_none()&&c.deleted_date.is_none()).cloned().collect();
 let folders:Vec<Folder>=cache.folders.clone();
 let selected=ciphers.len();
 let exporters=client.exporters();
 let fail=|context:&str|{let context=context.to_owned();move|e:bitwarden_exporters::ExportError|crate::account::log_error(&context,e,Error::new("exportFailed","The vault could not be exported."))};
 let (text,items,folder_count)=match format {
  "csv"=>{
   let text=Zeroizing::new(exporters.export_vault(folders,ciphers,ExportFormat::Csv).await.map_err(fail("CSV export"))?);
   let rows=csv::Reader::from_reader(text.as_bytes()).records().count();
   (text,rows,0)
  },
  "json"=>{
   let text=Zeroizing::new(exporters.export_vault(folders,ciphers,ExportFormat::Json).await.map_err(fail("JSON export"))?);
   let (items,folder_count)=json_counts(&text);
   (text,items,folder_count)
  },
  "jsonEncryptedPassword"=>{
   // A plain pass only to count what will be written; the SDK then writes the protected file.
   let plain=Zeroizing::new(exporters.export_vault(folders.clone(),ciphers.clone(),ExportFormat::Json).await.map_err(fail("JSON export"))?);
   let (items,folder_count)=json_counts(&plain);
   drop(plain);
   let password=file_password.unwrap_or_default();
   let text=Zeroizing::new(exporters.export_vault(folders,ciphers,ExportFormat::EncryptedJson{password}).await.map_err(fail("Encrypted export"))?);
   (text,items,folder_count)
  },
  _=>{
   let plain=Zeroizing::new(exporters.export_vault(folders,ciphers,ExportFormat::Json).await.map_err(fail("JSON export"))?);
   let (items,folder_count)=json_counts(&plain);
   let key=user_key(client).await?;
   (Zeroizing::new(seal_for_account(&plain,&key)?),items,folder_count)
  },
 };
 write_file(path,text.as_bytes())?;
 Ok(Exported{items,folders:folder_count,omitted:selected.saturating_sub(items)})
}
fn json_counts(text:&str)->(usize,usize){
 let value:Value=serde_json::from_str(text).unwrap_or(Value::Null);
 let count=|key:&str|value.get(key).and_then(Value::as_array).map_or(0,Vec::len);
 (count("items"),count("folders"))
}
pub(crate) async fn user_key(client:&Client)->Result<SymmetricCryptoKey>{
 let locked=||Error::new("locked","Account key unavailable.");
 let encoded:B64=client.crypto().get_user_encryption_key().await.map_err(|_|locked())?;
 SymmetricCryptoKey::try_from(encoded).map_err(|_|locked())
}
fn write_file(path:&Path,bytes:&[u8])->Result<()>{
 use std::os::unix::fs::OpenOptionsExt;
 let unwritable=|_|Error::new("writeFailed","The file could not be saved there.");
 let mut file=std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(unwritable)?;
 if let Err(error)=file.write_all(bytes).and_then(|_|file.sync_all()) {
  drop(file);
  // Never leave half a vault behind.
  let _=std::fs::remove_file(path);
  return Err(unwritable(error));
 }
 Ok(())
}

/// The text values Bitwarden encrypts in an account-restricted export, by place in an item.
const ITEM_TEXT:&[&str]=&["name","notes"];
const LOGIN_TEXT:&[&str]=&["username","password","totp"];
const CARD_TEXT:&[&str]=&["cardholderName","expMonth","expYear","code","brand","number"];
const IDENTITY_TEXT:&[&str]=&["title","firstName","middleName","lastName","address1","address2","address3","city","state","postalCode","country","company","email","phone","ssn","username","passportNumber","licenseNumber"];
const SSH_TEXT:&[&str]=&["privateKey","publicKey","keyFingerprint"];
const PASSKEY_TEXT:&[&str]=&["credentialId","keyType","keyAlgorithm","keyCurve","keyValue","rpId","userHandle","userName","counter","rpName","userDisplayName","discoverable"];

/// Applies `change` to every text value an account-restricted file encrypts, in one item.
pub(crate) fn map_item_text(item:&mut Value,change:&mut dyn FnMut(&str)->Result<String>)->Result<()>{
 fn strings(object:&mut Value,keys:&[&str],change:&mut dyn FnMut(&str)->Result<String>)->Result<()>{
  for key in keys {
   if let Some(Value::String(text))=object.get_mut(*key){*text=change(text)?}
  }
  Ok(())
 }
 fn each(parent:&mut Value,key:&str,keys:&[&str],change:&mut dyn FnMut(&str)->Result<String>)->Result<()>{
  if let Some(Value::Array(list))=parent.get_mut(key){for entry in list{strings(entry,keys,change)?}}
  Ok(())
 }
 strings(item,ITEM_TEXT,change)?;
 for (part,keys) in [("card",CARD_TEXT),("identity",IDENTITY_TEXT),("sshKey",SSH_TEXT)] {
  if let Some(object)=item.get_mut(part){strings(object,keys,change)?}
 }
 if let Some(login)=item.get_mut("login") {
  strings(login,LOGIN_TEXT,change)?;
  each(login,"uris",&["uri"],change)?;
  each(login,"fido2Credentials",PASSKEY_TEXT,change)?;
 }
 each(item,"fields",&["name","value"],change)?;
 each(item,"passwordHistory",&["password"],change)
}

pub(crate) fn seal_for_account(plain:&str,key:&SymmetricCryptoKey)->Result<String>{
 fn sealed<E>(_:E)->Error{Error::new("exportFailed","The vault could not be exported.")}
 let mut document:Value=serde_json::from_str(plain).map_err(sealed)?;
 let mut encrypt=|text:&str|->Result<String>{text.to_owned().encrypt_with_key(key).map(|enc|enc.to_string()).map_err(sealed)};
 for folder in document.get_mut("folders").and_then(Value::as_array_mut).into_iter().flatten() {
  if let Some(Value::String(name))=folder.get_mut("name"){*name=encrypt(name)?}
 }
 for item in document.get_mut("items").and_then(Value::as_array_mut).into_iter().flatten(){map_item_text(item,&mut encrypt)?}
 let validation=uuid::Uuid::new_v4().to_string().encrypt_with_key(key).map_err(sealed)?.to_string();
 let object=document.as_object_mut().ok_or_else(||sealed(()))?;
 object.insert("encrypted".into(),Value::Bool(true));
 object.insert(VALIDATION_FIELD.into(),Value::String(validation));
 serde_json::to_string_pretty(&document).map_err(sealed)
}

#[cfg(test)]
mod tests {
 use super::*;
 use bitwarden_crypto::{EncString,KeyDecryptable,SymmetricKeyAlgorithm};

 const PLAIN:&str=r#"{"encrypted":false,"folders":[{"id":"f1","name":"Work"}],"items":[
  {"id":"a","folderId":"f1","type":1,"name":"Mail","notes":"n","favorite":true,"reprompt":1,
   "login":{"username":"me","password":"pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://mail.example","match":1}],"fido2Credentials":[]},
   "fields":[{"name":"PIN","value":"1","type":1}],
   "passwordHistory":[{"password":"old","lastUsedDate":"2024-01-02T03:04:05.000Z"}],
   "revisionDate":"2024-01-30T17:55:36.150Z"},
  {"id":"b","folderId":null,"type":3,"name":"Visa","card":{"cardholderName":"A","number":"4111111111111111","expMonth":"1","expYear":"2031","code":"123","brand":"Visa"}}]}"#;

 #[test]
 fn account_restricted_files_encrypt_every_text_value_and_keep_the_structure() {
  let key=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  let sealed=seal_for_account(PLAIN,&key).unwrap();
  assert!(!sealed.contains("4111111111111111")&&!sealed.contains("JBSWY3DP")&&!sealed.contains("\"Work\"")&&!sealed.contains("mail.example")&&!sealed.contains("\"old\""),"values are encrypted");
  let mut document:Value=serde_json::from_str(&sealed).unwrap();
  assert_eq!(document["encrypted"],true);
  assert!(document.get("passwordProtected").is_none());
  assert_eq!(document["items"][0]["type"],1,"structure stays readable");
  assert_eq!(document["items"][0]["favorite"],true);
  assert_eq!(document["items"][0]["login"]["uris"][0]["match"],1);
  // Everything decrypts with the same key, and only with it.
  let validation:EncString=document[VALIDATION_FIELD].as_str().unwrap().parse().unwrap();
  let _:String=validation.decrypt_with_key(&key).unwrap();
  let other=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  assert!(KeyDecryptable::<SymmetricCryptoKey,String>::decrypt_with_key(&validation,&other).is_err());
  let mut open=|text:&str|->Result<String>{let enc:EncString=text.parse().unwrap();Ok(enc.decrypt_with_key(&key).unwrap())};
  for item in document["items"].as_array_mut().unwrap(){map_item_text(item,&mut open).unwrap()}
  assert_eq!(document["items"][0]["name"],"Mail");
  assert_eq!(document["items"][0]["login"]["password"],"pw");
  assert_eq!(document["items"][0]["login"]["uris"][0]["uri"],"https://mail.example");
  assert_eq!(document["items"][0]["fields"][0]["value"],"1");
  assert_eq!(document["items"][0]["passwordHistory"][0]["password"],"old");
  assert_eq!(document["items"][1]["card"]["number"],"4111111111111111");
 }

 #[test]
 fn export_paths_must_be_absolute() {
  assert!(absolute("relative.json").is_err());
  assert!(absolute("/").is_err());
  assert!(absolute("/tmp/x.json").is_ok());
 }

 #[test]
 fn writing_replaces_the_file_and_keeps_it_private() {
  use std::os::unix::fs::PermissionsExt;
  let dir=std::env::temp_dir().join(format!("kw-write-{}",uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&dir).unwrap();
  let file=dir.join("out.json");
  write_file(&file,b"first version, longer").unwrap();
  write_file(&file,b"second").unwrap();
  assert_eq!(std::fs::read(&file).unwrap(),b"second");
  assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode()&0o777,0o600);
  assert_eq!(std::fs::read_dir(&dir).unwrap().count(),1,"no temporary files");
  let _=std::fs::remove_dir_all(dir);
 }
}
