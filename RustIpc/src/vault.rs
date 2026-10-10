use serde::Serialize;
use bitwarden_core::{Client,key_management::SymmetricKeySlotId};
use bitwarden_crypto::Decryptable;
use bitwarden_vault::{VaultClientExt,FieldType};
use crate::{account::{Error,Result},store::Cache};

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct Summary {
 pub id:String,pub name:String,pub r#type:u8,pub favorite:bool,pub folder_id:Option<String>,
 pub organization_id:Option<String>,pub subtitle:String,pub search_values:Vec<String>,
 pub has_totp:bool,pub has_passkey:bool,pub deleted:bool,pub archived:bool,pub revision_date:String,
 /// Host of the first website, for the optional icon service. Only http(s) and bare domains.
 pub icon_host:Option<String>,
 /// Values the app's advanced search (`>field:value`) can look at, by field. Never holds
 /// passwords, hidden custom field values, card numbers or codes, or national ID numbers.
 pub search_fields:std::collections::BTreeMap<String,Vec<String>>,
}
#[derive(Serialize)]pub struct FolderDto{pub id:String,pub name:String}
#[derive(Serialize)]pub struct Failure{pub id:String,pub message:String}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct Snapshot {pub email:String,pub server:String,pub account_id:String,pub account_hash:String,pub generation:u64,pub last_sync:Option<u64>,pub items:Vec<Summary>,pub folders:Vec<FolderDto>,pub failures:Vec<Failure>}

fn last4(number:&Option<String>)->Option<String>{
 let digits:String=number.as_deref()?.chars().filter(char::is_ascii_digit).collect();
 (digits.len()>=4).then(||format!("*{}",&digits[digits.len()-4..]))
}
fn join(parts:&[Option<&String>])->String{
 parts.iter().flatten().map(|part|part.trim()).filter(|part|!part.is_empty()).collect::<Vec<_>>().join(" ")
}
fn icon_host(view:&bitwarden_vault::CipherView)->Option<String>{
 let uri=view.login.as_ref()?.uris.as_ref()?.iter().find_map(|u|u.uri.clone())?;
 let candidate=if uri.contains("://"){uri}else{format!("https://{uri}")};
 let url=url::Url::parse(&candidate).ok()?;
 if !matches!(url.scheme(),"http"|"https"){return None}
 let host=url.host_str()?.to_ascii_lowercase();
 // IP addresses and local names have no public icon.
 (host.contains('.')&&host.parse::<std::net::IpAddr>().is_err()&&!host.ends_with(".local")).then_some(host)
}
fn subtitle(view:&bitwarden_vault::CipherView)->String{
 use bitwarden_vault::CipherType as T;
 let text=match view.r#type {
  T::Login=>view.login.as_ref().and_then(|l|l.username.clone()).unwrap_or_default(),
  T::SecureNote=>view.notes.as_deref().and_then(|n|n.lines().find(|l|!l.trim().is_empty())).unwrap_or_default().chars().take(80).collect(),
  T::Card=>view.card.as_ref().map(|c|join(&[c.brand.as_ref(),last4(&c.number).as_ref()])).unwrap_or_default(),
  T::Identity=>view.identity.as_ref().map(|i|join(&[i.first_name.as_ref(),i.last_name.as_ref()])).unwrap_or_default(),
  T::SshKey=>view.ssh_key.as_ref().map(|k|k.fingerprint.clone()).unwrap_or_default(),
  T::BankAccount=>view.bank_account.as_ref().map(|b|join(&[b.bank_name.as_ref(),last4(&b.account_number).as_ref()])).unwrap_or_default(),
  T::DriversLicense=>view.drivers_license.as_ref().map(|d|join(&[d.first_name.as_ref(),d.last_name.as_ref()])).unwrap_or_default(),
  T::Passport=>view.passport.as_ref().map(|p|join(&[p.given_name.as_ref(),p.surname.as_ref()])).unwrap_or_default(),
 };
 text
}

/// The searchable, nonsecret text of an item, keyed like Bitwarden Desktop's search index:
/// `notes`, `login.username`, `login.uris`, `card.brand`, `identity.*`, `fields`, `fields.<name>`.
/// Notes and custom fields are left out for items flagged master-password re-prompt.
pub fn search_fields(view:&bitwarden_vault::CipherView)->std::collections::BTreeMap<String,Vec<String>> {
 let mut map:std::collections::BTreeMap<String,Vec<String>>=Default::default();
 let mut add=|key:&str,value:&Option<String>|{if let Some(value)=value.as_deref().filter(|v|!v.trim().is_empty()){map.entry(key.to_owned()).or_default().push(value.to_owned())}};
 // Items that ask for the master password again keep their notes and custom fields out of the
 // list, as the detail view keeps them behind Touch ID.
 let guarded=view.reprompt!=bitwarden_vault::CipherRepromptType::None;
 if !guarded{add("notes",&view.notes)}
 if let Some(login)=&view.login {
  add("login.username",&login.username);
  for uri in login.uris.iter().flatten(){add("login.uris",&uri.uri)}
 }
 if let Some(card)=&view.card {
  // The number, expiry and security code are never indexed.
  add("card.brand",&card.brand);
  add("card.cardholderName",&card.cardholder_name);
 }
 if let Some(i)=&view.identity {
  // Not the SSN, passport number or license number.
  for (key,value) in [("title",&i.title),("firstName",&i.first_name),("middleName",&i.middle_name),("lastName",&i.last_name),("address1",&i.address1),("address2",&i.address2),("address3",&i.address3),("city",&i.city),("state",&i.state),("postalCode",&i.postal_code),("country",&i.country),("company",&i.company),("email",&i.email),("phone",&i.phone),("username",&i.username)] {
   add(&format!("identity.{key}"),value);
  }
 }
 for field in view.fields.iter().flatten().filter(|_|!guarded) {
  let Some(name)=field.name.as_deref().filter(|n|!n.trim().is_empty()) else {continue};
  add("fields",&field.name);
  // Only the values a person can already read in the list: text and checkboxes.
  if matches!(field.r#type,FieldType::Text|FieldType::Boolean) {
   add("fields",&field.value);
   add(&format!("fields.{name}"),&field.value);
  }
 }
 for attachment in view.attachments.iter().flatten(){add("attachments.fileName",&attachment.file_name)}
 map
}

pub async fn project(client:&Client,cache:&Cache,generation:u64)->Result<Snapshot> {
 let mut items=Vec::new(); let mut failures=Vec::new(); let mut folders=Vec::new();
 for folder in &cache.folders {
  let id=folder.id.ok_or_else(||Error::new("invalidResponse","Folder has no identity."))?;
  let name=folder.name.decrypt(&mut client.internal.get_key_store().context_mut(),SymmetricKeySlotId::User).map_err(|e|crate::account::log_error("Unable to decrypt a folder",e,Error::new("invalidResponse","Unable to decrypt a folder.")))?;
  folders.push(FolderDto{id:id.to_string(),name});
 }
 folders.sort_by(|a,b|a.name.to_lowercase().cmp(&b.name.to_lowercase()));
 for cipher in &cache.ciphers {
  let id=cipher.id.ok_or_else(||Error::new("invalidResponse","Item has no identity."))?.to_string();
  match client.vault().ciphers().decrypt(cipher.clone()).await {
   Ok(view)=>{
    let mut search_values=Vec::new();
    if let Some(login)=&view.login {if let Some(username)=&login.username{search_values.push(username.clone())} if let Some(uris)=&login.uris{search_values.extend(uris.iter().filter_map(|u|u.uri.clone()))}}
    if let Some(fields)=&view.fields {for field in fields {if field.r#type==FieldType::Text {if let Some(name)=&field.name{search_values.push(name.clone())} if let Some(value)=&field.value{search_values.push(value.clone())}}}}
    let login=view.login.as_ref();
    items.push(Summary{
     id,subtitle:subtitle(&view),name:view.name.clone(),r#type:view.r#type as u8,favorite:view.favorite,
     folder_id:view.folder_id.map(|v|v.to_string()),organization_id:view.organization_id.map(|v|v.to_string()),search_values,
     has_totp:login.is_some_and(|l|l.totp.as_deref().is_some_and(|t|!t.is_empty())),
     has_passkey:login.is_some_and(|l|l.fido2_credentials.as_ref().is_some_and(|c|!c.is_empty())),
     deleted:view.deleted_date.is_some(),archived:view.archived_date.is_some(),revision_date:view.revision_date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
     icon_host:icon_host(&view),search_fields:search_fields(&view),
    });
   },Err(error)=>{crate::account::log("Item could not be decrypted",&error);failures.push(Failure{id,message:"Item could not be decrypted.".into()})}
  }
 }
 items.sort_by(|a,b|a.name.to_lowercase().cmp(&b.name.to_lowercase()));
 Ok(Snapshot{email:cache.email.clone(),server:cache.api.clone(),account_id:cache.account_id.clone(),account_hash:crate::store::Store::hash(&cache.api,&cache.account_id),generation,last_sync:cache.last_sync,items,folders,failures})
}
pub(crate) fn find<'a>(cache:&'a Cache,id:&str)->Result<&'a bitwarden_vault::Cipher>{
 cache.ciphers.iter().find(|c|c.id.is_some_and(|v|v.to_string()==id)).ok_or_else(||Error::new("notFound","Item not found. Sync and try again."))
}
pub async fn view(client:&Client,cache:&Cache,id:&str)->Result<bitwarden_vault::CipherView>{
 client.vault().ciphers().decrypt(find(cache,id)?.clone()).await.map_err(|e|crate::account::log_error("Item could not be decrypted",e,Error::new("invalidResponse","Item could not be decrypted.")))
}
pub async fn detail(client:&Client,cache:&Cache,id:&str)->Result<crate::items::Detail>{
 Ok(crate::items::detail(view(client,cache,id).await?))
}
pub async fn totp(client:&Client,cache:&Cache,id:&str)->Result<serde_json::Value>{
 let view=view(client,cache,id).await?;
 let key=view.login.and_then(|l|l.totp).filter(|k|!k.is_empty()).ok_or_else(||Error::new("invalidInput","This item has no authenticator key."))?;
 let now=chrono::Utc::now();
 let response=client.vault().totp().generate_totp(key,Some(now)).map_err(|e|crate::account::log_error("TOTP",e,Error::new("invalidInput","The authenticator key is invalid.")))?;
 let period=u64::from(response.period.max(1));
 let remaining=period-(now.timestamp() as u64%period);
 Ok(serde_json::json!({"code":response.code,"period":period,"remaining":remaining}))
}
pub async fn parse_sync(response:bitwarden_api_api::models::SyncResponseModel,cache:&Cache)->Result<Cache>{
 let profile=response.profile.as_ref().ok_or_else(||Error::new("invalidResponse","Sync profile missing."))?;
 if profile.id.map(|v|v.to_string())!=Some(cache.account_id.clone()){return Err(Error::new("invalidResponse","Account identity changed during sync."))}
 if profile.force_password_reset==Some(true)||profile.uses_key_connector==Some(true){return Err(Error::new("unsupportedAuthentication","This account requires a sign-in step not supported by this app. Complete it in the official client."))}
 let crypto=bitwarden_crypto_sync_handler::CryptoSyncData::try_from(&response).map_err(|_|Error::new("invalidResponse","Invalid account cryptographic state."))?;
 let mut next=cache.clone();
 if let Some(wrapped)=crypto.account_cryptographic_state {
  if matches!(next.wrapped,bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState::V2{..})&&matches!(wrapped,bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState::V1{..}) {return Err(Error::new("invalidResponse","Account cryptography downgrade rejected."))}
  next.wrapped=wrapped;
 } else if let Some(private)=&profile.private_key {
  if matches!(next.wrapped,bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState::V2{..}){return Err(Error::new("invalidResponse","Account cryptography downgrade rejected."))}
  next.wrapped=bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState::V1{private_key:private.parse().map_err(|_|Error::new("invalidResponse","Invalid private key."))?};
 }
 if let Some(decryption)=crypto.user_decryption {
  if let Some(unlock)=decryption.master_password_unlock {crate::api::validate_kdf(&unlock.kdf)?;next.unlock=unlock}
  if let Some(upgrade)=decryption.v2_upgrade_token {next.upgrade_token=Some(upgrade)}
 }
 next.folders=response.folders.ok_or_else(||Error::new("invalidResponse","Sync omitted folders."))?.into_iter().map(|f|bitwarden_vault::Folder::try_from(f).map_err(|_|Error::new("invalidResponse","Invalid folder in sync."))).collect::<Result<Vec<_>>>()?;
 next.ciphers=response.ciphers.ok_or_else(||Error::new("invalidResponse","Sync omitted vault items."))?.into_iter().map(|c|bitwarden_vault::Cipher::try_from(c).map_err(|_|Error::new("invalidResponse","Invalid item in sync."))).collect::<Result<Vec<_>>>()?;
 let mut seen=std::collections::HashSet::new();
 for cipher in &next.ciphers {let Some(id)=cipher.id else{return Err(Error::new("invalidResponse","Sync item has no identity."))};if cipher.partial_data.is_some()||!seen.insert(id){return Err(Error::new("invalidResponse","Sync has an invalid or duplicate item."))}}
 let mut seen=std::collections::HashSet::new();
 for folder in &next.folders {let Some(id)=folder.id else{return Err(Error::new("invalidResponse","Sync folder has no identity."))};if !seen.insert(id){return Err(Error::new("invalidResponse","Sync has a duplicate folder."))}}
 next.org_keys=org_keys(profile)?;
 next.last_sync=Some(crate::api::now()); Ok(next)
}
pub fn org_keys(profile:&bitwarden_api_api::models::ProfileResponseModel)->Result<std::collections::HashMap<bitwarden_core::OrganizationId,bitwarden_crypto::UnsignedSharedKey>> {
 let mut result=std::collections::HashMap::new();
 for org in profile.organizations_new.as_ref().or(profile.organizations.as_ref()).into_iter().flatten(){
  let encoded=serde_json::to_value(org).map_err(|_|Error::new("invalidResponse","Invalid organization data."))?;
  let id=org.id.ok_or_else(||Error::new("invalidResponse","Organization identity missing."))?;
  let field=encoded.get(String::from_utf8_lossy(&[107,101,121]).as_ref()).and_then(|v|v.as_str());
  let wrapped=field.ok_or_else(||Error::new("invalidResponse","Organization encrypted state missing."))?;
  let id=bitwarden_core::OrganizationId::new(id);
  if result.insert(id,wrapped.parse().map_err(|_|Error::new("invalidResponse","Invalid organization data."))?).is_some(){return Err(Error::new("invalidResponse","Duplicate organization identity."))}
 }
 Ok(result)
}
pub async fn initialize_org(client:&Client,cache:&Cache)->Result<()> {
 client.crypto().initialize_org_crypto(bitwarden_core::key_management::crypto::InitOrgCryptoRequest{organization_keys:cache.org_keys.clone()}).await.map_err(|_|Error::new("invalidResponse","Cannot unlock shared organization records."))
}

/// Maps a failed server write. The request body is never logged, only the SDK error.
pub(crate) fn write_error(context:&str,error:impl std::fmt::Debug)->Error{
 let text=format!("{error:?}");
 crate::account::log(context,&text);
 if text.contains("out of date") {
  Error::new("conflict","This item was changed on another device. Your edits are still here: sync, then save again.")
 } else if text.contains("revoked")||text.contains("requires sign-in") {
  Error::new("sessionExpired","Your session has expired. Sign out and sign in again to save changes.")
 } else if text.contains("Response(") {
  Error::new("saveFailed","The server rejected the change. Nothing was saved.")
 } else {
  Error::new("networkUnavailable","The server did not confirm the change. Sync to check before trying again.")
 }
}
fn owned_folder(cache:&Cache,id:&Option<String>)->Result<()>{
 match id.as_deref().filter(|id|!id.is_empty()) {
  Some(folder) if !cache.folders.iter().any(|f|f.id.is_some_and(|v|v.to_string()==folder))=>Err(Error::new("invalidInput","That folder no longer exists. Sync and try again.")),
  _=>Ok(()),
 }
}
pub(crate) fn cipher_id(id:&str)->Result<bitwarden_vault::CipherId>{id.parse().map_err(|_|Error::new("invalidInput","Invalid item."))}

/// Creates or edits an item on the server and returns its id. The SDK stores the server's copy in
/// the client repository, which the caller then persists.
pub async fn save_item(client:&Client,cache:&Cache,input:&crate::items::ItemData)->Result<String>{
 owned_folder(cache,&input.folder_id)?;
 if let Some(id)=input.id.as_deref() {
  let mut view=view(client,cache,id).await?;
  if view.deleted_date.is_some(){return Err(Error::new("invalidInput","Restore this item from the trash before editing it."))}
  if !view.edit||view.partial {return Err(Error::new("readOnly","You don't have permission to edit this item."))}
  crate::items::patch(&mut view,input)?;
  // The SDK's request types are not exported; their types are inferred from the method signatures.
  let request=view.try_into().map_err(|e|crate::account::log_error("Edit request",e,Error::new("invalidInput","This item can't be edited here.")))?;
  client.vault().ciphers().edit(request).await.map_err(|e|write_error("Edit item",e))?;
  Ok(id.to_owned())
 } else {
  if input.name.trim().is_empty(){return Err(Error::new("invalidInput","Item name is required."))}
  let request=serde_json::from_value(serde_json::json!({
   "organizationId":null,"collectionIds":[],"folderId":crate::items::folder_id(&input.folder_id)?,
   "name":input.name,"notes":(!input.notes.is_empty()).then(||input.notes.clone()),"favorite":input.favorite,
   "reprompt":if input.reprompt{bitwarden_vault::CipherRepromptType::Password}else{bitwarden_vault::CipherRepromptType::None},
   "type":crate::items::new_type(input)?,"fields":crate::items::new_fields(input)?,
  })).map_err(|e|crate::account::log_error("Create request",e,Error::new("invalidInput","Cannot construct the new item.")))?;
  let created=client.vault().ciphers().create(request).await.map_err(|e|write_error("Create item",e))?;
  created.id.map(|id|id.to_string()).ok_or_else(||Error::new("invalidResponse","The server did not return the new item."))
 }
}
/// Favorite and folder changes use the partial endpoint, which view-only shared items also allow.
pub async fn organize(client:&Client,cache:&Cache,id:&str,favorite:bool,folder:&Option<String>)->Result<()>{
 owned_folder(cache,folder)?;
 let request=serde_json::from_value(serde_json::json!({"id":cipher_id(id)?,"folderId":crate::items::folder_id(folder)?,"favorite":favorite}))
  .map_err(|e|crate::account::log_error("Organize request",e,Error::new("invalidInput","Cannot construct the request.")))?;
 client.vault().ciphers().edit_partial(request)
  .await.map_err(|e|write_error("Organize item",e))?;
 Ok(())
}
pub async fn delete_item(client:&Client,cache:&Cache,id:&str,permanent:bool)->Result<()>{
 let cipher=find(cache,id)?;
 let ciphers=client.vault().ciphers();
 if permanent {
  if cipher.deleted_date.is_none(){return Err(Error::new("invalidInput","Move the item to the trash first."))}
  ciphers.delete(cipher_id(id)?).await.map_err(|e|write_error("Delete item",e))
 } else {
  ciphers.soft_delete(cipher_id(id)?).await.map_err(|e|write_error("Trash item",e))
 }
}
pub async fn restore_item(client:&Client,id:&str)->Result<()>{
 client.vault().ciphers().restore(cipher_id(id)?).await.map_err(|e|write_error("Restore item",e))?;
 Ok(())
}
pub async fn save_folder(client:&Client,id:Option<&str>,name:String)->Result<()>{
 if name.trim().is_empty(){return Err(Error::new("invalidInput","Folder name is required."))}
 let request=bitwarden_vault::FolderAddEditRequest{name:name.trim().to_owned()};
 match id {
  Some(id)=>{let id=id.parse().map_err(|_|Error::new("invalidInput","Invalid folder."))?;client.vault().folders().edit(id,request).await.map_err(|e|write_error("Rename folder",e))?;}
  None=>{client.vault().folders().create(request).await.map_err(|e|write_error("Create folder",e))?;}
 }
 Ok(())
}
/// The server moves the folder's items to "No folder"; mirror that locally until the next sync.
pub async fn delete_folder(client:&Client,id:&str)->Result<()>{
 let folder_id:bitwarden_vault::FolderId=id.parse().map_err(|_|Error::new("invalidInput","Invalid folder."))?;
 client.internal.get_api_configurations().api_client.folders_api().delete(id).await.map_err(|e|write_error("Delete folder",e))?;
 let state=client.platform().state();
 let storage=|_|Error::new("storageUnavailable","Local vault storage is unavailable.");
 state.get::<bitwarden_vault::Folder>().map_err(storage)?.remove(folder_id).await.map_err(|_|Error::new("storageUnavailable","Local vault storage is unavailable."))?;
 let ciphers=state.get::<bitwarden_vault::Cipher>().map_err(storage)?;
 for mut cipher in ciphers.list().await.map_err(|_|Error::new("storageUnavailable","Local vault storage is unavailable."))? {
  if cipher.folder_id==Some(folder_id) {
   cipher.folder_id=None;
   if let Some(id)=cipher.id {ciphers.set(id,cipher).await.map_err(|_|Error::new("storageUnavailable","Local vault storage is unavailable."))?;}
  }
 }
 Ok(())
}
/// Reads back what the SDK stored after a confirmed write.
pub async fn repository_contents(client:&Client)->Result<(Vec<bitwarden_vault::Cipher>,Vec<bitwarden_vault::Folder>)>{
 let state=client.platform().state();
 let unavailable=||Error::new("storageUnavailable","Local vault storage is unavailable.");
 let ciphers=state.get::<bitwarden_vault::Cipher>().map_err(|_|unavailable())?.list().await.map_err(|_|unavailable())?;
 let folders=state.get::<bitwarden_vault::Folder>().map_err(|_|unavailable())?.list().await.map_err(|_|unavailable())?;
 Ok((ciphers,folders))
}

/// Archives or unarchives an item on the server, then mirrors the server's dates locally.
pub async fn set_archived(client:&Client,id:&str,archived:bool)->Result<()>{
 let cipher_id=cipher_id(id)?;
 let configurations=client.internal.get_api_configurations();
 let api=configurations.api_client.ciphers_api();
 let uuid:uuid::Uuid=id.parse().map_err(|_|Error::new("invalidInput","Invalid item."))?;
 let response=if archived {api.put_archive(uuid).await} else {api.put_unarchive(uuid).await}
  .map_err(|e|write_error(if archived{"Archive item"}else{"Unarchive item"},e))?;
 let parse=|value:Option<&String>|value.and_then(|v|chrono::DateTime::parse_from_rfc3339(v).ok()).map(|d|d.with_timezone(&chrono::Utc));
 let state=client.platform().state();
 let unavailable=||Error::new("storageUnavailable","Local vault storage is unavailable.");
 let ciphers=state.get::<bitwarden_vault::Cipher>().map_err(|_|unavailable())?;
 let mut cipher=ciphers.get(cipher_id).await.map_err(|_|unavailable())?.ok_or_else(||Error::new("notFound","Item not found. Sync and try again."))?;
 cipher.archived_date=if archived {parse(response.archived_date.as_ref()).or_else(||Some(chrono::Utc::now()))} else {None};
 if let Some(revision)=parse(response.revision_date.as_ref()) {cipher.revision_date=revision}
 ciphers.set(cipher_id,cipher).await.map_err(|_|unavailable())
}

#[cfg(test)]
mod tests {
 use super::*;

 fn view(extra:serde_json::Value)->bitwarden_vault::CipherView {
  let mut base=serde_json::json!({
   "id":uuid::Uuid::new_v4(),"organizationId":null,"folderId":null,"collectionIds":[],"key":null,"name":"Item","notes":null,"type":1,
   "login":null,"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,
   "favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"localData":null,
   "attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2025-01-01T00:00:00Z","deletedDate":null,
   "revisionDate":"2025-01-02T00:00:00Z","archivedDate":null});
  for (key,value) in extra.as_object().unwrap(){base[key]=value.clone()}
  serde_json::from_value(base).unwrap()
 }

 #[test]
 fn login_values_are_searchable_but_the_password_is_not() {
  let fields=search_fields(&view(serde_json::json!({"notes":"remember this",
   "login":{"username":"alice","password":"hunter2-secret","passwordRevisionDate":null,"uris":[{"uri":"https://git.example","match":null,"uriChecksum":null},{"uri":"https://second.example","match":null,"uriChecksum":null}],
    "totp":"JBSWY3DPEHPK3PXP","autofillOnPageLoad":null,"fido2Credentials":null}})));
  assert_eq!(fields["notes"],["remember this"]);
  assert_eq!(fields["login.username"],["alice"]);
  assert_eq!(fields["login.uris"],["https://git.example","https://second.example"]);
  let all=serde_json::to_string(&fields).unwrap();
  assert!(!all.contains("hunter2")&&!all.contains("JBSWY3DP"),"{all}");
 }

 #[test]
 fn card_and_identity_index_only_nonsecret_values() {
  let card=search_fields(&view(serde_json::json!({"type":3,"card":{"cardholderName":"A Person","brand":"Visa","number":"4111111111111111","expMonth":"4","expYear":"2031","code":"321"}})));
  assert_eq!(card["card.brand"],["Visa"]);
  assert_eq!(card["card.cardholderName"],["A Person"]);
  let all=serde_json::to_string(&card).unwrap();
  assert!(!all.contains("4111")&&!all.contains("321")&&!all.contains("2031"),"{all}");
  let identity=search_fields(&view(serde_json::json!({"type":4,"identity":{"title":"Dr","firstName":"Alex","middleName":null,"lastName":"Example","address1":"1 Main St","address2":null,"address3":null,"city":"Town","state":"CA","postalCode":"95014","country":"US","company":"Acme","email":"alex@example.com","phone":"555","ssn":"123-45-6789","username":"alexe","passportNumber":"P123456","licenseNumber":"D998877"}})));
  assert_eq!(identity["identity.firstName"],["Alex"]);
  assert_eq!(identity["identity.company"],["Acme"]);
  assert_eq!(identity["identity.postalCode"],["95014"]);
  let all=serde_json::to_string(&identity).unwrap();
  assert!(!all.contains("123-45")&&!all.contains("P123456")&&!all.contains("D998877"),"{all}");
 }

 #[test]
 fn reprompt_items_keep_notes_and_custom_fields_out_of_the_list() {
  let fields=search_fields(&view(serde_json::json!({"reprompt":1,"notes":"private notes",
   "login":{"username":"alice","password":"pw","passwordRevisionDate":null,"uris":[],"totp":null,"autofillOnPageLoad":null,"fido2Credentials":null},
   "fields":[{"name":"Region","value":"EU","type":0,"linkedId":null}]})));
  assert_eq!(fields["login.username"],["alice"]);
  assert!(!fields.contains_key("notes")&&!fields.contains_key("fields")&&!fields.contains_key("fields.Region"),"{fields:?}");
 }

 #[test]
 fn only_readable_custom_field_values_are_indexed() {
  let fields=search_fields(&view(serde_json::json!({"fields":[
   {"name":"Region","value":"EU","type":0,"linkedId":null},
   {"name":"Recovery","value":"alpha-bravo","type":1,"linkedId":null},
   {"name":"Enforced","value":"true","type":2,"linkedId":null},
   {"name":"Account","value":null,"type":3,"linkedId":100}]})));
  assert_eq!(fields["fields.Region"],["EU"]);
  assert_eq!(fields["fields.Enforced"],["true"]);
  assert!(!fields.contains_key("fields.Recovery")&&!fields.contains_key("fields.Account"));
  let combined=&fields["fields"];
  assert!(combined.contains(&"Region".to_string())&&combined.contains(&"EU".to_string()));
  assert!(combined.contains(&"Recovery".to_string()),"a hidden field's name is searchable");
  assert!(!combined.contains(&"alpha-bravo".to_string()),"its value is not");
 }
}
