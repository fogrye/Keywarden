//! Reading Bitwarden export files (.json, .csv, encrypted .json) and importing them into the
//! individual vault. See `transfer.rs` for the file formats and the export side.
//!
//! The parsed items are held in memory only, cleared when the vault locks, until the user
//! confirms the counts; then they are encrypted and submitted to `POST /ciphers/import`.
use std::{collections::HashMap,io::Read,sync::{LazyLock,Mutex}};
use bitwarden_api_api::models::{CipherRequestModel,FolderWithIdRequestModel,ImportCiphersRequestModel,Int32Int32KeyValuePair};
use bitwarden_core::{Client,UserId,key_management::KeySlotIds};
use bitwarden_crypto::{BitwardenLegacyKeyBytes,CompositeEncryptable,EncString,IdentifyKey,Kdf,KeyDecryptable,KeyStoreContext,PinKey,SymmetricCryptoKey};
use bitwarden_exporters::{Card,CipherType,Fido2Credential,Field,Identity,ImportingCipher,Login,LoginUri,SecureNote,SecureNoteType,SshKey};
use bitwarden_vault::{CipherRepromptType,CipherView,EncryptMode,EncryptionContext,Folder,FolderView,PasswordHistoryView,should_use_blob_encryption};
use chrono::{DateTime,Utc};
use serde_json::{Value,json};
use zeroize::Zeroizing;
use crate::{account::{Error,Result},transfer::{VALIDATION_FIELD,absolute,map_item_text,user_key}};

/// Import files larger than this are refused before they are read.
const MAX_IMPORT_BYTES:u64=64*1024*1024;
/// Bitwarden's servers refuse imports beyond these sizes.
const MAX_IMPORT_ITEMS:usize=7000;
const MAX_IMPORT_FOLDERS:usize=1000;


/// One item read from a file, before encryption.
pub struct Entry{cipher:ImportingCipher,history:Vec<PasswordHistoryView>,folder:Option<usize>}
/// Everything a file holds, decrypted, waiting for the user's confirmation.
pub struct Parsed{entries:Vec<Entry>,folders:Vec<String>,skipped:usize}
impl Parsed{
 pub fn summary(&self)->Value{
  let mut types=[0usize;9];
  for entry in &self.entries{types[type_number(&entry.cipher.r#type)]+=1}
  json!({"items":self.entries.len(),"folders":self.folders.len(),"skipped":self.skipped,
   "types":types.iter().enumerate().filter(|(_,n)|**n>0).map(|(t,n)|json!({"type":t,"count":n})).collect::<Vec<_>>()})
 }
}
fn type_number(kind:&CipherType)->usize{
 match kind {CipherType::Login(_)=>1,CipherType::SecureNote(_)=>2,CipherType::Card(_)=>3,CipherType::Identity(_)=>4,CipherType::SshKey(_)=>5,CipherType::BankAccount=>6,CipherType::DriversLicense=>7,CipherType::Passport=>8}
}

/// Reads and, if needed, decrypts the file at `path`. `client` is the unlocked account, needed for
/// account-restricted files.
pub async fn read(client:&Client,path:&str,file_password:Option<String>)->Result<Parsed>{
 let path=absolute(path)?;
 let unreadable=|_|Error::new("invalidInput","That file could not be read.");
 let file=std::fs::File::open(path).map_err(unreadable)?;
 let meta=file.metadata().map_err(unreadable)?;
 if !meta.is_file(){return Err(Error::new("invalidInput","Choose a file, not a folder."))}
 if meta.len()>MAX_IMPORT_BYTES{return Err(Error::new("tooLarge","That file is too large to import (limit 64 MB)."))}
 let mut bytes=Zeroizing::new(Vec::with_capacity(meta.len() as usize));
 file.take(MAX_IMPORT_BYTES+1).read_to_end(&mut bytes).map_err(unreadable)?;
 let text=std::str::from_utf8(&bytes).map_err(|_|Error::new("unrecognizedFile","That file is not a Bitwarden export."))?;
 let text=text.strip_prefix('\u{feff}').unwrap_or(text);
 let key=if looks_encrypted_for_account(text){Some(user_key(client).await?)}else{None};
 parse(text,file_password.as_deref(),key.as_ref())
}
fn looks_encrypted_for_account(text:&str)->bool{
 text.trim_start().starts_with('{')&&serde_json::from_str::<Value>(text).ok().is_some_and(|value|value.get("encrypted")==Some(&Value::Bool(true))&&value.get("passwordProtected")!=Some(&Value::Bool(true)))
}

/// Chooses the parser: JSON (plain or encrypted) when the file starts with `{`, else Bitwarden CSV.
pub fn parse(text:&str,file_password:Option<&str>,account_key:Option<&SymmetricCryptoKey>)->Result<Parsed>{
 let parsed=if text.trim_start().starts_with('{') {
  let mut document:Value=serde_json::from_str(text).map_err(|_|Error::new("unrecognizedFile","That file is not a Bitwarden export."))?;
  if document.get("encrypted")==Some(&Value::Bool(true)) {
   if document.get("passwordProtected")==Some(&Value::Bool(true)) {
    let plain=Zeroizing::new(open_password_protected(&document,file_password)?);
    document=serde_json::from_str(&plain).map_err(|_|Error::new("unrecognizedFile","The decrypted file is not a Bitwarden export."))?;
   } else {
    let key=account_key.ok_or_else(||Error::new("locked","Account key unavailable."))?;
    open_account_restricted(&mut document,key)?;
   }
  }
  parse_json(&document)?
 } else {
  parse_csv(text)?
 };
 if parsed.entries.len()>MAX_IMPORT_ITEMS{return Err(Error::new("tooLarge","Bitwarden imports are limited to 7,000 items at a time. Split the file and import it in parts."))}
 if parsed.folders.len()>MAX_IMPORT_FOLDERS{return Err(Error::new("tooLarge","Bitwarden imports are limited to 1,000 folders at a time."))}
 Ok(parsed)
}

fn kdf_of(document:&Value)->Result<Kdf>{
 let bad=||Error::new("unrecognizedFile","The file's encryption settings are not valid.");
 let number=|key:&str|document.get(key).and_then(Value::as_u64).and_then(|n|u32::try_from(n).ok()).and_then(std::num::NonZeroU32::new);
 let kdf=match document.get("kdfType").and_then(Value::as_u64) {
  Some(0)=>Kdf::PBKDF2{iterations:number("kdfIterations").ok_or_else(bad)?},
  Some(1)=>Kdf::Argon2id{iterations:number("kdfIterations").ok_or_else(bad)?,memory:number("kdfMemory").ok_or_else(bad)?,parallelism:number("kdfParallelism").ok_or_else(bad)?},
  _=>return Err(bad()),
 };
 // A crafted file must not be able to demand gigabytes of memory or hours of CPU.
 crate::api::validate_kdf(&kdf).map_err(|_|Error::new("unrecognizedFile","The file's encryption settings are outside the supported limits."))?;
 Ok(kdf)
}
fn open_password_protected(document:&Value,password:Option<&str>)->Result<String>{
 let password=password.filter(|p|!p.is_empty()).ok_or_else(||Error::new("passwordRequired","This file is protected with a password."))?;
 let bad=||Error::new("unrecognizedFile","That file is not a valid encrypted Bitwarden export.");
 let kdf=kdf_of(document)?;
 let salt=document.get("salt").and_then(Value::as_str).ok_or_else(bad)?;
 let validation:EncString=document.get(VALIDATION_FIELD).and_then(Value::as_str).ok_or_else(bad)?.parse().map_err(|_|bad())?;
 let data:EncString=document.get("data").and_then(Value::as_str).ok_or_else(bad)?.parse().map_err(|_|bad())?;
 // The key derivation uses the base64 salt text itself, as the exporter does.
 let key=PinKey::derive(password.as_bytes(),salt.as_bytes(),&kdf).map_err(|_|bad())?;
 let wrong=|_|Error::new("invalidFilePassword","That file password is incorrect.");
 let _:String=validation.decrypt_with_key(&key).map_err(wrong)?;
 data.decrypt_with_key(&key).map_err(|_|bad())
}
/// Bitwarden clients wrap each item's own key with the account key and encrypt the item's values
/// under it. Files may or may not carry that `key`.
fn item_key(item:&Value,account:&SymmetricCryptoKey)->Result<Option<SymmetricCryptoKey>>{
 let bad=||Error::new("unreadableItem","Some items in this file could not be decrypted.");
 let Some(Value::String(wrapped))=item.get("key") else {return Ok(None)};
 let wrapped:EncString=wrapped.parse().map_err(|_|bad())?;
 let bytes:Vec<u8>=wrapped.decrypt_with_key(account).map_err(|_|bad())?;
 SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes)).map(Some).map_err(|_|bad())
}
fn open_account_restricted(document:&mut Value,key:&SymmetricCryptoKey)->Result<()>{
 let foreign=|_|Error::new("wrongAccount","This file was encrypted for a different account. Ask for a password-protected export instead.");
 let unreadable=|_|Error::new("unreadableItem","Some items in this file could not be decrypted.");
 let validation:EncString=document.get(VALIDATION_FIELD).and_then(Value::as_str).ok_or_else(||Error::new("unrecognizedFile","That file is not a valid encrypted Bitwarden export."))?.parse().map_err(foreign)?;
 let _:String=validation.decrypt_with_key(key).map_err(foreign)?;
 let decrypt=|text:&str|->Result<String>{
  let enc:EncString=text.parse().map_err(unreadable)?;
  enc.decrypt_with_key(key).map_err(unreadable)
 };
 for folder in document.get_mut("folders").and_then(Value::as_array_mut).into_iter().flatten() {
  if let Some(Value::String(name))=folder.get_mut("name"){*name=decrypt(name)?}
 }
 for item in document.get_mut("items").and_then(Value::as_array_mut).into_iter().flatten() {
  // Items sealed as one blob, a newer format, have no readable fields here.
  if item.get("data").is_some_and(Value::is_string){return Err(Error::new("unreadableItem","This file holds items in a newer encrypted format that this version can't read."))}
  let own=item_key(item,key)?;
  let item_key=own.as_ref().unwrap_or(key);
  let mut open=|text:&str|->Result<String>{
   let enc:EncString=text.parse().map_err(unreadable)?;
   enc.decrypt_with_key(item_key).map_err(unreadable)
  };
  map_item_text(item,&mut open)?;
  if let Some(object)=item.as_object_mut(){object.remove("key");}
 }
 Ok(())
}

// Lenient readers: files come from several versions of several clients.
fn text(value:&Value,key:&str)->Option<String>{
 match value.get(key)? {Value::String(s)=>Some(s.clone()),Value::Number(n)=>Some(n.to_string()),Value::Bool(b)=>Some(b.to_string()),_=>None}
}
fn int(value:&Value,key:&str)->Option<u64>{
 match value.get(key)? {Value::Number(n)=>n.as_u64(),Value::String(s)=>s.trim().parse().ok(),_=>None}
}
fn flag(value:&Value,key:&str)->bool{
 match value.get(key) {Some(Value::Bool(b))=>*b,Some(Value::Number(n))=>n.as_u64()==Some(1),Some(Value::String(s))=>matches!(s.trim().to_lowercase().as_str(),"1"|"true"),_=>false}
}
fn date(value:&Value,key:&str)->DateTime<Utc>{
 text(value,key).and_then(|t|DateTime::parse_from_rfc3339(&t).ok()).map_or_else(Utc::now,|d|d.with_timezone(&Utc))
}
fn items(list:&Value)->&[Value]{list.as_array().map_or(&[],Vec::as_slice)}

fn parse_json(document:&Value)->Result<Parsed>{
 if !document.is_object()||(document.get("items").is_none()&&document.get("folders").is_none()){
  return Err(Error::new("unrecognizedFile","That file is not a Bitwarden export."))
 }
 let mut folders=Vec::new();
 let mut by_id=HashMap::new();
 for folder in items(document.get("folders").unwrap_or(&Value::Null)) {
  let Some(name)=text(folder,"name").map(|n|n.trim().to_owned()).filter(|n|!n.is_empty()) else {continue};
  if let Some(id)=text(folder,"id"){by_id.insert(id,folders.len());}
  folders.push(name);
 }
 let mut entries=Vec::new();
 let mut skipped=0;
 for item in items(document.get("items").unwrap_or(&Value::Null)) {
  match json_entry(item,&by_id) {Some(entry)=>entries.push(entry),None=>skipped+=1}
 }
 Ok(Parsed{entries,folders,skipped})
}
fn json_entry(item:&Value,folders:&HashMap<String,usize>)->Option<Entry>{
 // Trashed items stay in the trash of the account they came from.
 if item.get("deletedDate").is_some_and(|d|!d.is_null()){return None}
 let empty=Value::Null;
 let kind=match int(item,"type")? {
  1=>{
   let login=item.get("login").unwrap_or(&empty);
   let uris=items(login.get("uris").unwrap_or(&empty)).iter().filter_map(|u|text(u,"uri").filter(|uri|!uri.is_empty()).map(|uri|LoginUri{uri:Some(uri),r#match:int(u,"match").and_then(|m|u8::try_from(m).ok())})).collect();
   let passkeys:Vec<Fido2Credential>=items(login.get("fido2Credentials").unwrap_or(&empty)).iter().filter_map(passkey).collect();
   CipherType::Login(Box::new(Login{username:text(login,"username"),password:text(login,"password"),login_uris:uris,totp:text(login,"totp"),fido2_credentials:(!passkeys.is_empty()).then_some(passkeys)}))
  },
  2=>CipherType::SecureNote(Box::new(SecureNote{r#type:SecureNoteType::Generic})),
  3=>{
   let card=item.get("card").unwrap_or(&empty);
   CipherType::Card(Box::new(Card{cardholder_name:text(card,"cardholderName"),exp_month:text(card,"expMonth"),exp_year:text(card,"expYear"),code:text(card,"code"),brand:text(card,"brand"),number:text(card,"number")}))
  },
  4=>{
   let id=item.get("identity").unwrap_or(&empty);
   CipherType::Identity(Box::new(Identity{title:text(id,"title"),first_name:text(id,"firstName"),middle_name:text(id,"middleName"),last_name:text(id,"lastName"),address1:text(id,"address1"),address2:text(id,"address2"),address3:text(id,"address3"),city:text(id,"city"),state:text(id,"state"),postal_code:text(id,"postalCode"),country:text(id,"country"),company:text(id,"company"),email:text(id,"email"),phone:text(id,"phone"),ssn:text(id,"ssn"),username:text(id,"username"),passport_number:text(id,"passportNumber"),license_number:text(id,"licenseNumber")}))
  },
  5=>{
   let key=item.get("sshKey").unwrap_or(&empty);
   CipherType::SshKey(Box::new(SshKey{private_key:text(key,"privateKey")?,public_key:text(key,"publicKey").unwrap_or_default(),fingerprint:text(key,"keyFingerprint").or_else(||text(key,"fingerprint")).unwrap_or_default()}))
  },
  // Bank accounts, licenses and passports have no interchange format yet.
  _=>return None,
 };
 let fields=items(item.get("fields").unwrap_or(&empty)).iter().map(|f|Field{name:text(f,"name"),value:text(f,"value"),r#type:int(f,"type").and_then(|t|u8::try_from(t).ok()).filter(|t|*t<=3).unwrap_or(0),linked_id:int(f,"linkedId").and_then(|l|u32::try_from(l).ok())}).collect();
 let history=items(item.get("passwordHistory").unwrap_or(&empty)).iter().filter_map(|h|Some(PasswordHistoryView{password:text(h,"password")?,last_used_date:date(h,"lastUsedDate")})).collect();
 Some(Entry{
  cipher:ImportingCipher{folder_id:None,name:text(item,"name").filter(|n|!n.trim().is_empty()).unwrap_or_else(||"--".into()),notes:text(item,"notes").filter(|n|!n.is_empty()),r#type:kind,favorite:flag(item,"favorite"),
   reprompt:u8::from(int(item,"reprompt")==Some(1)),fields,revision_date:date(item,"revisionDate"),creation_date:date(item,"creationDate"),deleted_date:None},
  history,folder:text(item,"folderId").and_then(|id|folders.get(&id).copied()),
 })
}
fn passkey(value:&Value)->Option<Fido2Credential>{
 Some(Fido2Credential{credential_id:text(value,"credentialId")?,key_type:text(value,"keyType")?,key_algorithm:text(value,"keyAlgorithm")?,key_curve:text(value,"keyCurve")?,key_value:text(value,"keyValue")?,rp_id:text(value,"rpId")?,
  user_handle:text(value,"userHandle"),user_name:text(value,"userName"),counter:int(value,"counter").and_then(|c|u32::try_from(c).ok()).unwrap_or(0),rp_name:text(value,"rpName"),user_display_name:text(value,"userDisplayName"),
  discoverable:text(value,"discoverable").unwrap_or_else(||"false".into()),creation_date:date(value,"creationDate")})
}

/// Bitwarden's CSV: `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`.
fn parse_csv(source:&str)->Result<Parsed>{
 let unrecognized=||Error::new("unrecognizedFile","That file is not a Bitwarden CSV export.");
 let mut reader=csv::ReaderBuilder::new().flexible(true).from_reader(source.as_bytes());
 let headers:Vec<String>=reader.headers().map_err(|_|unrecognized())?.iter().map(|h|h.trim().to_lowercase()).collect();
 if !headers.iter().any(|h|h=="name")||!headers.iter().any(|h|h.starts_with("login_")||h=="type"||h=="folder"){return Err(unrecognized())}
 let column=|row:&csv::StringRecord,name:&str|->String{headers.iter().position(|h|h==name).and_then(|i|row.get(i)).unwrap_or("").to_owned()};
 let mut folders:Vec<String>=Vec::new();
 let mut entries=Vec::new();
 for row in reader.records() {
  let row=row.map_err(|_|unrecognized())?;
  if row.iter().all(|cell|cell.trim().is_empty()){continue}
  let folder=column(&row,"folder");
  let folder=(!folder.trim().is_empty()).then(||{
   let name=folder.trim().to_owned();
   folders.iter().position(|f|*f==name).unwrap_or_else(||{folders.push(name);folders.len()-1})
  });
  let note=matches!(column(&row,"type").trim().to_lowercase().as_str(),"note"|"securenote"|"secure note");
  let non_empty=|s:String|(!s.is_empty()).then_some(s);
  let kind=if note{CipherType::SecureNote(Box::new(SecureNote{r#type:SecureNoteType::Generic}))}else{
   CipherType::Login(Box::new(Login{username:non_empty(column(&row,"login_username")),password:non_empty(column(&row,"login_password")),
    login_uris:split_uris(&column(&row,"login_uri")).into_iter().map(|uri|LoginUri{uri:Some(uri),r#match:None}).collect(),totp:non_empty(column(&row,"login_totp")),fido2_credentials:None}))
  };
  let fields=column(&row,"fields").lines().filter(|l|!l.trim().is_empty()).map(|line|{
   let (name,value)=line.split_once(": ").map_or((line,""),|(n,v)|(n,v));
   Field{name:Some(name.to_owned()),value:Some(value.to_owned()),r#type:0,linked_id:None}
  }).collect();
  let name=column(&row,"name");
  let now=Utc::now();
  entries.push(Entry{
   cipher:ImportingCipher{folder_id:None,name:if name.trim().is_empty(){"--".into()}else{name},notes:non_empty(column(&row,"notes")),r#type:kind,
    favorite:matches!(column(&row,"favorite").trim().to_lowercase().as_str(),"1"|"true"),reprompt:u8::from(column(&row,"reprompt").trim()=="1"),fields,revision_date:now,creation_date:now,deleted_date:None},
   history:Vec::new(),folder,
  });
 }
 Ok(Parsed{entries,folders,skipped:0})
}
/// Bitwarden's exporters join a login's websites with a newline or a comma.
fn split_uris(cell:&str)->Vec<String>{
 let mut uris:Vec<String>=Vec::new();
 for line in cell.lines().map(str::trim).filter(|l|!l.is_empty()) {
  let mut first=true;
  for piece in line.split(',') {
   let scheme=piece.find("://").is_some_and(|at|at>0&&piece[..at].chars().all(|c|c.is_ascii_alphanumeric()||"+.-".contains(c)));
   match uris.last_mut() {
    Some(last)if !first&&!scheme=>{last.push(',');last.push_str(piece)},
    _=>uris.push(piece.to_owned()),
   }
   first=false;
  }
 }
 uris
}

// MARK: Import: pending state and submission

struct Pending{generation:u64,parsed:Parsed}
static PENDING:LazyLock<Mutex<Option<Pending>>>=LazyLock::new(||Mutex::new(None));
/// Holds the confirmed-to-be items until `commit`. Cleared when the vault locks.
pub fn hold(generation:u64,parsed:Parsed){if let Ok(mut pending)=PENDING.lock(){*pending=Some(Pending{generation,parsed})}}
pub fn discard(){if let Ok(mut pending)=PENDING.lock(){*pending=None}}
fn take(generation:u64)->Result<Parsed>{
 let pending=PENDING.lock().map_err(|_|Error::new("storageUnavailable","Import state unavailable."))?.take();
 match pending {Some(p)if p.generation==generation=>Ok(p.parsed),_=>Err(Error::new("notFound","There is nothing to import. Choose the file again."))}
}

/// Mirrors the SDK's `encrypt_import`, but keeps the re-prompt flag and password history, which the
/// SDK's interchange model drops.
fn encrypt_entry(ctx:&mut KeyStoreContext<KeySlotIds>,entry:Entry,user_id:UserId)->Result<CipherRequestModel>{
 let encrypt_failed=|e:&dyn std::fmt::Debug|crate::account::log_error("Import encryption",e,Error::new("importFailed","The items could not be encrypted."));
 let passkeys=match &entry.cipher.r#type {CipherType::Login(login)=>login.fido2_credentials.clone(),_=>None};
 let mut view:CipherView=entry.cipher.clone().into();
 view.reprompt=if entry.cipher.reprompt==1{CipherRepromptType::Password}else{CipherRepromptType::None};
 view.password_history=(!entry.history.is_empty()).then_some(entry.history);
 if let Some(passkeys)=passkeys {view.set_new_fido2_credentials(passkeys.into_iter().map(Into::into).collect()).map_err(|e|encrypt_failed(&e))?}
 let key=view.key_identifier();
 let encrypted_by_key_id=ctx.get_symmetric_key_id(key).map(|id|id.to_string());
 let mode=if should_use_blob_encryption(ctx,None){EncryptMode::Blob(view)}else{EncryptMode::Legacy(view)};
 let cipher=mode.encrypt_composite(ctx,key).map_err(|e|encrypt_failed(&e))?;
 Ok(EncryptionContext{cipher,encrypted_for:user_id,encrypted_by_key_id}.into())
}

pub struct Imported{pub items:usize,pub folders:usize}
/// Encrypts the held items and submits them in one request, to the individual vault.
pub async fn commit(client:&Client,generation:u64)->Result<Imported>{
 let parsed=take(generation)?;
 let user_id=client.internal.get_user_id().ok_or_else(||Error::new("locked","Sign in first."))?;
 let (model,imported)={
  // The key store context must not live across the await below.
  let key_store=client.internal.get_key_store();
  let mut ctx=key_store.context();
  let (item_count,folder_count)=(parsed.entries.len(),parsed.folders.len());
  let mut relationships=Vec::new();
  let mut ciphers=Vec::with_capacity(item_count);
  for (index,entry) in parsed.entries.into_iter().enumerate() {
   if let Some(folder)=entry.folder{relationships.push(Int32Int32KeyValuePair{key:Some(index as i32),value:Some(folder as i32)})}
   ciphers.push(encrypt_entry(&mut ctx,entry,user_id)?);
  }
  let now=Utc::now();
  let mut folders=Vec::with_capacity(folder_count);
  for name in parsed.folders {
   let view=FolderView{id:None,name,revision_date:now};
   let folder:Folder=view.encrypt_composite(&mut ctx,view.key_identifier()).map_err(|e|crate::account::log_error("Import folder encryption",e,Error::new("importFailed","The items could not be encrypted.")))?;
   folders.push(FolderWithIdRequestModel::from(&folder));
  }
  (ImportCiphersRequestModel{folders:Some(folders),ciphers:Some(ciphers),folder_relationships:Some(relationships)},Imported{items:item_count,folders:folder_count})
 };
 client.internal.get_api_configurations().api_client.import_ciphers_api().post_import(Some(model)).await
  .map_err(|e|crate::vault::write_error("Import",e))?;
 Ok(imported)
}

#[cfg(test)]
mod tests {
 use super::*;
 use bitwarden_crypto::{KeyEncryptable,SymmetricKeyAlgorithm};
 use crate::transfer::seal_for_account;

 fn login_names(parsed:&Parsed)->Vec<String>{parsed.entries.iter().map(|e|e.cipher.name.clone()).collect()}

 const PLAIN:&str=r#"{"encrypted":false,"folders":[{"id":"f1","name":"Work"},{"id":"f2","name":" "}],"items":[
  {"id":"a","folderId":"f1","type":1,"name":"Mail","notes":"n","favorite":true,"reprompt":1,
   "login":{"username":"me","password":"pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://mail.example","match":1},{"uri":"","match":null}]},
   "fields":[{"name":"PIN","value":"1","type":1},{"name":"Flag","value":"true","type":2}],
   "passwordHistory":[{"password":"old","lastUsedDate":"2024-01-02T03:04:05.000Z"}],
   "revisionDate":"2024-01-30T17:55:36.150Z","creationDate":"2024-01-01T00:00:00.000Z"},
  {"id":"b","folderId":null,"type":3,"name":"Visa","card":{"cardholderName":"A","number":"4111111111111111","expMonth":"1","expYear":2031,"code":"123","brand":"Visa"}},
  {"id":"c","type":2,"name":"","secureNote":{"type":0}},
  {"id":"d","type":4,"name":"Me","identity":{"firstName":"Alex","lastName":"Example"}},
  {"id":"e","type":1,"name":"Trashed","deletedDate":"2024-02-01T00:00:00.000Z","login":{}},
  {"id":"g","type":6,"name":"Bank"},
  {"id":"h","type":5,"name":"Key","sshKey":{"privateKey":"p","publicKey":"q","keyFingerprint":"SHA256:x"}}]}"#;

 #[test]
 fn plain_json_reads_every_supported_type_and_keeps_flags() {
  let parsed=parse(PLAIN,None,None).unwrap();
  assert_eq!(login_names(&parsed),["Mail","Visa","--","Me","Key"]);
  assert_eq!(parsed.folders,["Work"]);
  assert_eq!(parsed.skipped,2,"the trashed item and the bank account");
  let mail=&parsed.entries[0];
  assert_eq!((mail.folder,mail.cipher.favorite,mail.cipher.reprompt),(Some(0),true,1));
  assert_eq!(mail.history.len(),1);
  assert_eq!(mail.cipher.fields.len(),2);
  let CipherType::Login(login)=&mail.cipher.r#type else {panic!("login")};
  assert_eq!(login.login_uris.len(),1,"empty websites are dropped");
  assert_eq!(login.login_uris[0].r#match,Some(1));
  let CipherType::Card(card)=&parsed.entries[1].cipher.r#type else {panic!("card")};
  assert_eq!(card.exp_year.as_deref(),Some("2031"),"numbers are accepted where text is expected");
  let summary=parsed.summary();
  assert_eq!(summary["items"],5);
  assert_eq!(summary["folders"],1);
 }

 #[test]
 fn json_that_is_not_an_export_is_refused() {
  for input in ["{}","[]","{\"hello\":1}","not json at all\nnor csv"] {
   assert!(parse(input,None,None).is_err(),"{input}");
  }
 }

 #[test]
 fn csv_inverts_the_exporters_writer() {
  let csv="folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
   Work,1,login,Mail,\"two\nlines\",\"PIN: 1\nRegion: EU: west\",1,\"https://a.example,https://b.example/x,y\",me,\"p,w\",\n\
   ,,note,Wi-Fi,secret note,,0,,,,\n,,,,,,,,,,\n";
  let parsed=parse(csv,None,None).unwrap();
  assert_eq!(login_names(&parsed),["Mail","Wi-Fi"]);
  assert_eq!(parsed.folders,["Work"]);
  let mail=&parsed.entries[0];
  assert_eq!((mail.folder,mail.cipher.favorite,mail.cipher.reprompt),(Some(0),true,1));
  assert_eq!(mail.cipher.notes.as_deref(),Some("two\nlines"));
  assert_eq!(mail.cipher.fields[1].value.as_deref(),Some("EU: west"));
  let CipherType::Login(login)=&mail.cipher.r#type else {panic!("login")};
  let uris:Vec<_>=login.login_uris.iter().filter_map(|u|u.uri.clone()).collect();
  assert_eq!(uris,["https://a.example","https://b.example/x,y"]);
  assert_eq!(login.password.as_deref(),Some("p,w"));
  assert!(matches!(parsed.entries[1].cipher.r#type,CipherType::SecureNote(_)));
  assert!(parse("a,b\n1,2\n",None,None).is_err());
 }

 fn kdf_document()->Value{json!({"encrypted":true,"passwordProtected":true,"salt":"c2FsdHNhbHRzYWx0c2FsdA==","kdfType":0,"kdfIterations":5000})}

 #[test]
 fn password_protected_files_need_the_right_password_and_sane_kdf_settings() {
  let mut document=kdf_document();
  let kdf=kdf_of(&document).unwrap();
  let salt=document["salt"].as_str().unwrap().to_owned();
  let key=PinKey::derive(b"correct horse",salt.as_bytes(),&kdf).unwrap();
  document[VALIDATION_FIELD]=json!(uuid::Uuid::new_v4().to_string().encrypt_with_key(&key).unwrap().to_string());
  document["data"]=json!(PLAIN.to_owned().encrypt_with_key(&key).unwrap().to_string());
  let text=document.to_string();
  assert_eq!(parse(&text,None,None).err().unwrap().code,"passwordRequired");
  assert_eq!(parse(&text,Some("wrong"),None).err().unwrap().code,"invalidFilePassword");
  assert_eq!(parse(&text,Some("correct horse"),None).unwrap().entries.len(),5);
  for bad in [json!({"kdfType":1,"kdfIterations":3,"kdfMemory":4096,"kdfParallelism":4}),json!({"kdfType":0,"kdfIterations":1}),json!({"kdfType":0,"kdfIterations":50_000_000}),json!({"kdfType":7,"kdfIterations":5000})] {
   let mut crafted=document.clone();
   for (k,v) in bad.as_object().unwrap(){crafted[k]=v.clone()}
   assert!(parse(&crafted.to_string(),Some("correct horse"),None).is_err(),"{bad}");
  }
 }

 #[test]
 fn account_restricted_files_round_trip_and_reject_other_keys() {
  let key=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  let sealed=seal_for_account(PLAIN,&key).unwrap();
  assert!(!sealed.contains("4111111111111111")&&!sealed.contains("JBSWY3DP")&&!sealed.contains("\"Work\"")&&!sealed.contains("mail.example"),"values are encrypted");
  let document:Value=serde_json::from_str(&sealed).unwrap();
  assert_eq!(document["encrypted"],true);
  assert_eq!(document["items"][0]["type"],1,"structure stays readable");
  assert!(looks_encrypted_for_account(&sealed));
  let parsed=parse(&sealed,None,Some(&key)).unwrap();
  assert_eq!(login_names(&parsed),["Mail","Visa","--","Me","Key"]);
  assert_eq!(parsed.folders,["Work"]);
  let CipherType::Login(login)=&parsed.entries[0].cipher.r#type else {panic!("login")};
  assert_eq!(login.password.as_deref(),Some("pw"));
  assert_eq!(parsed.entries[0].history[0].password,"old");
  let other=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  assert_eq!(parse(&sealed,None,Some(&other)).err().unwrap().code,"wrongAccount");
 }
 #[test]
 fn items_with_their_own_key_open_like_bitwarden_clients_write_them() {
  let account=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  let cipher_key=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  let seal=|text:&str,key:&SymmetricCryptoKey|text.to_owned().encrypt_with_key(key).unwrap().to_string();
  let wrapped=(&cipher_key.to_encoded()).encrypt_with_key(&account).unwrap().to_string();
  let document=|validation_key:&SymmetricCryptoKey,item_key:&str|json!({"encrypted":true,VALIDATION_FIELD:seal("uuid",validation_key),
   "folders":[{"id":"f1","name":seal("Work",&account)}],
   "items":[
    {"type":1,"folderId":"f1","key":item_key,"name":seal("Keyed",&cipher_key),"notes":seal("under the item key",&cipher_key),
     "login":{"username":seal("u",&cipher_key),"password":seal("p1",&cipher_key),"uris":[{"uri":seal("https://a.example",&cipher_key),"match":null}]},
     "fields":[{"name":seal("PIN",&cipher_key),"value":seal("42",&cipher_key),"type":1}]},
    {"type":1,"name":seal("Plain",&account),"login":{"password":seal("p2",&account)}}]});
  let parsed=parse(&document(&account,&wrapped).to_string(),None,Some(&account)).unwrap();
  assert_eq!(login_names(&parsed),["Keyed","Plain"]);
  assert_eq!(parsed.folders,["Work"]);
  assert_eq!(parsed.entries[0].cipher.notes.as_deref(),Some("under the item key"));
  assert_eq!(parsed.entries[0].cipher.fields[0].value.as_deref(),Some("42"));
  let CipherType::Login(keyed)=&parsed.entries[0].cipher.r#type else {panic!("login")};
  assert_eq!((keyed.password.as_deref(),keyed.username.as_deref()),(Some("p1"),Some("u")));
  assert_eq!(keyed.login_uris[0].uri.as_deref(),Some("https://a.example"));
  let CipherType::Login(plain)=&parsed.entries[1].cipher.r#type else {panic!("login")};
  assert_eq!(plain.password.as_deref(),Some("p2"));
  // A file for another account fails the validation check; a damaged item key is its own error.
  let other=SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
  assert_eq!(parse(&document(&other,&wrapped).to_string(),None,Some(&account)).err().unwrap().code,"wrongAccount");
  let foreign_wrapped=(&cipher_key.to_encoded()).encrypt_with_key(&other).unwrap().to_string();
  assert_eq!(parse(&document(&account,&foreign_wrapped).to_string(),None,Some(&account)).err().unwrap().code,"unreadableItem");
  let blob=json!({"encrypted":true,VALIDATION_FIELD:seal("uuid",&account),"folders":[],"items":[{"type":1,"data":"opaque"}]});
  assert_eq!(parse(&blob.to_string(),None,Some(&account)).err().unwrap().code,"unreadableItem");
 }
}
