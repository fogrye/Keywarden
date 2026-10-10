use std::sync::{LazyLock,Mutex,RwLock,atomic::{AtomicU64,Ordering}};
use serde::Serialize;
use serde_json::{Value,json};
use bitwarden_core::{Client,ClientSettings,DeviceType,key_management::{crypto::{InitUserCryptoRequest,InitUserCryptoMethod},MasterPasswordUnlockData,account_cryptographic_state::WrappedAccountCryptographicState}};
use bitwarden_crypto::{EncString,Kdf};
use bitwarden_state::registry::StateRegistry;
use bitwarden_vault::{Cipher,Folder};
use base64::{Engine as _,engine::general_purpose::URL_SAFE_NO_PAD};
use crate::{api::{self,Endpoints,KeychainTokenHandler,Tokens},store::{Store,Cache},vault};

pub type Result<T,E=Error>=std::result::Result<T,E>;
#[derive(Serialize,Debug)] pub struct Error{pub code:&'static str,pub message:&'static str}
impl Error{pub fn new(code:&'static str,message:&'static str)->Self{Self{code,message}}}
static GENERATION:AtomicU64=AtomicU64::new(1);
static STATE:LazyLock<Mutex<State>>=LazyLock::new(||Mutex::new(State{cache:None,client:None}));
static IDENTITY:LazyLock<RwLock<Option<Value>>>=LazyLock::new(||RwLock::new(None));
static LANE:LazyLock<tokio::sync::Mutex<()>>=LazyLock::new(||tokio::sync::Mutex::new(()));
struct State{cache:Option<Cache>,client:Option<Client>}
fn current(g:u64)->Result<()>{if GENERATION.load(Ordering::Acquire)==g{Ok(())}else{Err(Error::new("cancelled","Account operation was cancelled."))}}
fn update_identity(cache:Option<&Cache>,phase:&str){if let Ok(mut identity)=IDENTITY.write(){*identity=cache.map(|c|json!({"accountId":c.account_id,"accountHash":Store::hash(&c.api,&c.account_id),"server":c.api,"email":c.email,"phase":phase,"generation":generation()}));}}
pub fn generation()->u64{GENERATION.load(Ordering::Acquire)}
pub fn identity()->Option<Value>{IDENTITY.read().ok().and_then(|v|v.clone())}
pub fn invalidate()->u64{
 let next=GENERATION.fetch_add(1,Ordering::AcqRel)+1;
 crate::import::discard();
 if let Ok(mut state)=STATE.lock(){if let Some(client)=state.client.take(){client.internal.get_key_store().clear()} update_identity(state.cache.as_ref(),if state.cache.is_some(){"locked"}else{"loggedOut"});}
 next
}
fn state()->Result<std::sync::MutexGuard<'static,State>>{STATE.lock().map_err(|_|Error::new("storageUnavailable","Account state unavailable."))}
fn finish_pending_sign_out(store:&Store)->Result<()> {
 if let Some((api,id))=store.pending_sign_out()? {
  let hash=Store::hash(&api,&id);
  api::credential(2,&hash,&[])?;
  api::credential(4,&hash,&[])?;
  api::credential(6,&hash,&[])?;
  store.finish_sign_out(&api,&id)?;
 }
 Ok(())
}
fn restore()->Result<()> {
 let needs_restore={let active=state()?;active.cache.is_none()};
 if needs_restore {
  let store=Store::new();
  finish_pending_sign_out(&store)?;
  let cache=store.active()?;
  let mut active=state()?;
  if active.cache.is_none(){active.cache=cache;update_identity(active.cache.as_ref(),if active.cache.is_some(){"locked"}else{"loggedOut"});}
 }
 Ok(())
}
pub fn dispatch(req:crate::app::Request)->Result<Value>{crate::RUNTIME.block_on(async {let _guard=LANE.lock().await;dispatch_inner(req).await})}
async fn dispatch_inner(req:crate::app::Request)->Result<Value>{
 use crate::app::Request;
 restore()?;let g=generation();
 match req {
 Request::Status=>{let active=state()?;Ok(active.cache.as_ref().map_or_else(||json!({"phase":"loggedOut","generation":g}),|c|json!({"phase":if active.client.is_some(){"unlocked"}else{"locked"},"email":c.email,"server":c.api,"accountId":c.account_id,"accountHash":Store::hash(&c.api,&c.account_id),"pinEnabled":crate::pin::enabled(&Store::hash(&c.api,&c.account_id)),"generation":g})))},
 Request::Login{email,password,server}=>login(email,password,server,g).await,
 Request::Unlock{password}=>unlock(password,g,None).await,
 Request::UnlockPin{pin}=>unlock_pin(pin,g).await,
 Request::EnrollPin{pin}=>{let (cache,client)=authorized()?;crate::pin::enroll(&client,&cache,&Store::hash(&cache.api,&cache.account_id),&pin)?;Ok(json!({}))},
 Request::DisablePin=>{let cache=state()?.cache.clone().ok_or_else(||Error::new("loggedOut","Sign in first."))?;crate::pin::remove(&Store::hash(&cache.api,&cache.account_id))?;Ok(json!({}))},
 Request::Sync=>sync(g).await,
 Request::Item{id}=>{let (cache,client)=authorized()?;let detail=vault::detail(&client,&cache,&id).await?;current(g)?;encode(detail)},
 Request::Totp{id}=>{let (cache,client)=authorized()?;vault::totp(&client,&cache,&id).await},
 Request::SaveItem{item}=>{let (cache,client)=authorized()?;let id=vault::save_item(&client,&cache,&item).await?;persist(&client,g,Some(id)).await},
 Request::Organize{id,favorite,folder_id}=>{let (cache,client)=authorized()?;vault::organize(&client,&cache,&id,favorite,&folder_id).await?;persist(&client,g,Some(id)).await},
 Request::DeleteItem{id,permanent}=>{let (cache,client)=authorized()?;vault::delete_item(&client,&cache,&id,permanent).await?;persist(&client,g,(!permanent).then_some(id)).await},
 Request::ArchiveItem{id,archived}=>{let (_,client)=authorized()?;vault::set_archived(&client,&id,archived).await?;persist(&client,g,Some(id)).await},
 Request::RestoreItem{id}=>{let (_,client)=authorized()?;vault::restore_item(&client,&id).await?;persist(&client,g,Some(id)).await},
 Request::AttachmentDownload{id,attachment_id,path}=>{let (cache,client)=authorized()?;crate::attachments::download(&client,&cache,&id,&attachment_id,&path).await?;current(g)?;Ok(json!({}))},
 Request::AttachmentUpload{id,path}=>{let (cache,client)=authorized()?;crate::attachments::upload(&client,&cache,&id,&path).await?;persist(&client,g,Some(id)).await},
 Request::AttachmentDelete{id,attachment_id}=>{let (cache,client)=authorized()?;crate::attachments::delete(&client,&cache,&id,&attachment_id).await?;persist(&client,g,Some(id)).await},
 Request::ExportVault{format,file_password,master_password,path}=>{
  let (cache,client)=authorized()?;
  verify_master_password(&cache,master_password).await?;current(g)?;
  let Some(path)=path else {return Ok(json!({"verified":true}))};
  let exported=crate::transfer::export(&client,&cache,&format,file_password,&path).await?;current(g)?;
  Ok(exported.json())
 },
 Request::ImportPrepare{path,file_password}=>{
  let (_,client)=authorized()?;
  crate::import::discard();
  let parsed=crate::import::read(&client,&path,file_password).await?;current(g)?;
  let summary=parsed.summary();
  crate::import::hold(g,parsed);
  Ok(summary)
 },
 Request::ImportDiscard=>{crate::import::discard();Ok(json!({}))},
 Request::ImportCommit=>{
  let (_,client)=authorized()?;
  let imported=crate::import::commit(&client,g).await?;current(g)?;
  // The import endpoint does not fill the SDK's repository, so a full sync brings the items in.
  // If that sync fails the import still happened: the app refreshes on its own.
  let snapshot=sync(g).await.ok();
  Ok(json!({"items":imported.items,"folders":imported.folders,"snapshot":snapshot}))
 },
 Request::SaveFolder{id,name}=>{let (_,client)=authorized()?;vault::save_folder(&client,id.as_deref(),name).await?;persist(&client,g,None).await},
 Request::DeleteFolder{id}=>{let (_,client)=authorized()?;vault::delete_folder(&client,&id).await?;persist(&client,g,None).await},
 Request::Lock=>{invalidate();Ok(json!({}))},
 Request::Logout=>{
  invalidate();
  let store=Store::new();
  let active_cache=state()?.cache.clone();
  if let Some(cache)=active_cache {store.begin_sign_out(&cache)?;let mut active=state()?;active.cache=None;update_identity(None,"loggedOut");}
  finish_pending_sign_out(&store)?;
  Ok(json!({}))
 },
 Request::Generate{..}|Request::GenerateUsername{..}|Request::PasswordStrength{..}=>Err(Error::new("invalidInput","Invalid account operation.")),
 }
}
/// Re-authentication for sensitive actions: derives the account key from the typed master password
/// on a scratch client, so nothing is unlocked or stored, and compares it with the unlocked vault.
async fn verify_master_password(cache:&Cache,password:String)->Result<()>{
 if password.is_empty(){return Err(Error::new("invalidPassword","Enter your master password."))}
 let user_id=cache.account_id.parse().map_err(|_|Error::new("invalidResponse","Invalid account identity."))?;
 let scratch=client(cache,None);
 let result=scratch.crypto().initialize_user_crypto(InitUserCryptoRequest {user_id:Some(user_id),kdf_params:cache.unlock.kdf.clone(),email:cache.email.clone(),account_cryptographic_state:cache.wrapped.clone(),method:InitUserCryptoMethod::MasterPasswordUnlock{password,master_password_unlock:cache.unlock.clone()},upgrade_token:cache.upgrade_token.clone()}).await;
 scratch.internal.get_key_store().clear();
 result.map_err(|_|Error::new("invalidPassword","That master password is incorrect."))
}
fn authorized()->Result<(Cache,Client)>{let active=state()?;Ok((active.cache.clone().ok_or_else(||Error::new("loggedOut","Sign in first."))?,active.client.clone().ok_or_else(||Error::new("locked","Unlock the vault first."))?))}
fn encode(value:impl Serialize)->Result<Value>{serde_json::to_value(value).map_err(|_|Error::new("invalidResponse","Cannot encode reply."))}
/// Logs a non-secret failure cause to stderr. Callers pass SDK/HTTP errors, never request bodies.
pub fn log(context:&str,error:&dyn std::fmt::Debug){
 let mut text=format!("{error:?}");
 if text.len()>600 {let mut end=600;while !text.is_char_boundary(end){end-=1}text.truncate(end);text.push('…')}
 eprintln!("[keywarden] {context}: {text}");
 crate::log_line(&format!("{context}: {text}"));
}
pub fn log_error(context:&str,error:impl std::fmt::Debug,mapped:Error)->Error{log(context,&error);mapped}
/// Persists what the SDK repository holds after a server-confirmed write. The ciphertext is
/// committed even if the vault was locked meanwhile; only the decrypted snapshot is withheld.
async fn persist(client:&Client,g:u64,id:Option<String>)->Result<Value>{
 let (ciphers,folders)=vault::repository_contents(client).await?;
 let next={
  let mut active=state()?;
  let mut next=active.cache.clone().ok_or_else(||Error::new("loggedOut","Sign in first."))?;
  next.ciphers=ciphers;next.folders=folders;
  Store::new().commit(&next)?;
  active.cache=Some(next.clone());
  next
 };
 current(g)?;
 let snapshot=vault::project(client,&next,g).await?;
 current(g)?;
 Ok(json!({"snapshot":snapshot,"id":id}))
}
fn client(cache:&Cache,tokens:Option<Tokens>)->Client{
 let settings=ClientSettings {api_url:cache.api.clone(),identity_url:cache.identity.clone(),device_type:DeviceType::MacOsDesktop,device_identifier:None,user_agent:concat!("Keywarden/",env!("CARGO_PKG_VERSION")).into(),bitwarden_client_version:Some(env!("CARGO_PKG_VERSION").into()),..ClientSettings::default()};
 let handler=KeychainTokenHandler::new(Store::hash(&cache.api,&cache.account_id),cache.api.clone(),cache.identity.clone(),cache.email.clone(),cache.unlock.kdf.clone(),tokens);
 Client::builder().with_settings(settings).with_state(StateRegistry::new_with_memory_db()).with_token_handler(handler).with_middleware(vec![std::sync::Arc::new(api::OriginPolicy{api:cache.api.clone()})]).build()
}
async fn initialize(cache:&Cache,method:InitUserCryptoMethod,tokens:Option<Tokens>)->Result<Client>{
 let instance=client(cache,tokens);
 let user_id=cache.account_id.parse().map_err(|_|Error::new("invalidResponse","Invalid account identity."))?;
 instance.crypto().initialize_user_crypto(InitUserCryptoRequest {user_id:Some(user_id),kdf_params:cache.unlock.kdf.clone(),email:cache.email.clone(),account_cryptographic_state:cache.wrapped.clone(),method,upgrade_token:cache.upgrade_token.clone()}).await.map_err(|_|Error::new("invalidPassword","Cannot unlock account with the supplied credential."))?;
 vault::initialize_org(&instance,cache).await?;
 let registry=instance.platform().state();
 let ciphers=registry.get::<Cipher>().map_err(|_|Error::new("storageUnavailable","Item repository unavailable."))?;
 for cipher in &cache.ciphers {ciphers.set(cipher.id.ok_or_else(||Error::new("invalidResponse","Item identity missing."))?,cipher.clone()).await.map_err(|_|Error::new("storageUnavailable","Item repository unavailable."))?;}
 let folders=registry.get::<Folder>().map_err(|_|Error::new("storageUnavailable","Folder repository unavailable."))?;
 for folder in &cache.folders {folders.set(folder.id.ok_or_else(||Error::new("invalidResponse","Folder identity missing."))?,folder.clone()).await.map_err(|_|Error::new("storageUnavailable","Folder repository unavailable."))?;}
 Ok(instance)
}
fn jwt_subject(token:&str)->Result<String>{let encoded=token.split('.').nth(1).ok_or_else(||Error::new("invalidResponse","Identity token missing account subject."))?;let data=URL_SAFE_NO_PAD.decode(encoded).map_err(|_|Error::new("invalidResponse","Invalid identity token."))?;let claims:Value=serde_json::from_slice(&data).map_err(|_|Error::new("invalidResponse","Invalid identity claims."))?;let subject=claims.get("sub").and_then(Value::as_str).ok_or_else(||Error::new("invalidResponse","Identity subject missing."))?;let parsed=uuid::Uuid::parse_str(subject).map_err(|_|Error::new("invalidResponse","Invalid identity subject."))?;Ok(parsed.to_string())}
async fn login(email:String,password:String,server:String,g:u64)->Result<Value>{
 let email=email.trim().to_lowercase();if email.is_empty()||password.is_empty(){return Err(Error::new("invalidInput","Email and master password are required."))}
 let endpoints=Endpoints::parse(&server)?;let device=Store::new().device_id()?;
 let (response,kdf,salt)=api::login_request(&endpoints,&email,&password,&device).await?;current(g)?;
 let access=response.get("access_token").and_then(Value::as_str).ok_or_else(||Error::new("invalidResponse","Access token missing."))?;
 if response.get("token_type").and_then(Value::as_str).is_none_or(|v|!v.eq_ignore_ascii_case("bearer")){return Err(Error::new("invalidResponse","Unsupported token type."))}
 let subject=jwt_subject(access)?;let refresh=response.get("refresh_token").and_then(Value::as_str).unwrap_or_default().to_owned();
 let expiry=response.get("expires_in").and_then(Value::as_u64).filter(|value|*value>0&&*value<=86400).ok_or_else(||Error::new("invalidResponse","Invalid token expiration."))?;
 let tokens=Tokens{access:access.into(),refresh,expires_at:api::now()+expiry};
 let (unlock,wrapped)=login_crypto(&response,&kdf,&salt)?;
 let cache=Cache{schema_version:1,account_id:subject,email,api:endpoints.api,identity:endpoints.identity,unlock,wrapped,upgrade_token:None,org_keys:Default::default(),ciphers:Vec::new(),folders:Vec::new(),last_sync:None};
 let instance=initialize(&cache,InitUserCryptoMethod::MasterPasswordUnlock{password,master_password_unlock:cache.unlock.clone()},Some(tokens.clone())).await?;
 current(g)?;
 let response=instance.internal.get_api_configurations().api_client.sync_api().get(None).await.map_err(|_|Error::new("networkUnavailable","Unable to download vault."))?;
 let profile=response.profile.as_ref().ok_or_else(||Error::new("invalidResponse","Sync profile missing."))?;
 if profile.id.map(|v|v.to_string())!=Some(cache.account_id.clone()){return Err(Error::new("invalidResponse","Account identity mismatch."))}
 if profile.force_password_reset==Some(true)||profile.uses_key_connector==Some(true){return Err(Error::new("unsupportedAuthentication","This account requires a sign-in step not supported by this app. Complete it in the official client."))}
 let candidate=vault::parse_sync(response,&cache).await?;
 let key=instance.crypto().get_user_encryption_key().await.map_err(|_|Error::new("invalidResponse","Account key unavailable."))?.to_string();
 let fresh=initialize(&candidate,InitUserCryptoMethod::DecryptedKey{decrypted_user_key:key},Some(tokens.clone())).await?;
 let snapshot=vault::project(&fresh,&candidate,g).await?;current(g)?;Store::new().commit(&candidate)?;current(g)?;
 api::save_tokens(&Store::hash(&candidate.api,&candidate.account_id),&tokens)?;
 let mut active=state()?;active.cache=Some(candidate);active.client=Some(fresh);update_identity(active.cache.as_ref(),"unlocked");serde_json::to_value(snapshot).map_err(|_|Error::new("invalidResponse","Cannot encode vault."))
}
fn login_crypto(response:&Value,kdf:&Kdf,salt:&str)->Result<(MasterPasswordUnlockData,WrappedAccountCryptographicState)>{
 let modern=crate::api::unique_alias(response,&["userDecryptionOptions","UserDecryptionOptions"])?;
 let unlock=if let Some(options)=modern {
  let value=api::unique_alias(options,&["masterPasswordUnlock","MasterPasswordUnlock"])?.ok_or_else(||Error::new("unsupportedAuthentication","This account requires an unsupported sign-in method."))?;
  let model:bitwarden_api_api::models::MasterPasswordUnlockResponseModel=serde_json::from_value(value.clone()).map_err(|_|Error::new("invalidResponse","Invalid account unlock data."))?;
  MasterPasswordUnlockData::try_from(&model).map_err(|_|Error::new("invalidResponse","Invalid account unlock data."))?
 }else{
  let wrapped=api::unique_alias(response,&["Key","key"])?.and_then(Value::as_str).ok_or_else(||Error::new("invalidResponse","Account unlock data missing."))?;
  MasterPasswordUnlockData{kdf:kdf.clone(),salt:salt.into(),master_key_wrapped_user_key:wrapped.parse::<EncString>().map_err(|_|Error::new("invalidResponse","Invalid account unlock data."))?,contained_key_id:None}
 };
 api::validate_kdf(&unlock.kdf)?;
 if unlock.salt.is_empty()||unlock.salt.len()>4096{return Err(Error::new("invalidResponse","Invalid account unlock salt."))}
 let wrapped=if let Some(account)=api::unique_alias(response,&["accountKeys","AccountKeys"])?{let model:bitwarden_api_api::models::PrivateKeysResponseModel=serde_json::from_value(account.clone()).map_err(|_|Error::new("invalidResponse","Invalid account cryptographic state."))?;WrappedAccountCryptographicState::try_from(&model).map_err(|_|Error::new("invalidResponse","Invalid account cryptographic state."))?}else{let private=api::unique_alias(response,&["PrivateKey","privateKey"])?.and_then(Value::as_str).ok_or_else(||Error::new("invalidResponse","Account private data missing."))?;WrappedAccountCryptographicState::V1{private_key:private.parse().map_err(|_|Error::new("invalidResponse","Invalid account private data."))?}};
 Ok((unlock,wrapped))
}
async fn unlock_pin(pin:String,g:u64)->Result<Value>{
 let cache=state()?.cache.clone().ok_or_else(||Error::new("loggedOut","Sign in first."))?;
 let hash=Store::hash(&cache.api,&cache.account_id);
 let method=crate::pin::method(&cache,&hash,pin)?;
 let tokens=api::load_tokens(&hash)?;
 match initialize(&cache,method,tokens).await {
  Ok(instance)=>{
   crate::pin::attempted(&hash,true)?;
   let snapshot=vault::project(&instance,&cache,g).await?;current(g)?;
   let mut active=state()?;active.client=Some(instance);update_identity(active.cache.as_ref(),"unlocked");
   encode(snapshot)
  }
  Err(_)=>Err(crate::pin::attempted(&hash,false)?),
 }
}
async fn unlock(password:String,g:u64,key:Option<String>)->Result<Value>{let cache=state()?.cache.clone().ok_or_else(||Error::new("loggedOut","Sign in first."))?;
 let tokens=api::load_tokens(&Store::hash(&cache.api,&cache.account_id))?;
 let method=if let Some(decrypted_user_key)=key{InitUserCryptoMethod::DecryptedKey{decrypted_user_key}}else{InitUserCryptoMethod::MasterPasswordUnlock{password,master_password_unlock:cache.unlock.clone()}};
 let instance=initialize(&cache,method,tokens).await?;let snapshot=vault::project(&instance,&cache,g).await?;current(g)?;let mut active=state()?;active.client=Some(instance);update_identity(active.cache.as_ref(),"unlocked");serde_json::to_value(snapshot).map_err(|_|Error::new("invalidResponse","Cannot encode vault."))
}
async fn sync(g:u64)->Result<Value>{let (cache,instance)=authorized()?;let response=instance.internal.get_api_configurations().api_client.sync_api().get(None).await.map_err(|_|Error::new("networkUnavailable","Unable to sync vault."))?;current(g)?;let next=vault::parse_sync(response,&cache).await?;
 if next.wrapped!=cache.wrapped{return Err(Error::new("sessionExpired","Account cryptography changed; sign in again."))}
 let fresh=initialize(&next,InitUserCryptoMethod::DecryptedKey{decrypted_user_key:instance.crypto().get_user_encryption_key().await.map_err(|_|Error::new("locked","Account key unavailable."))?.to_string()},api::load_tokens(&Store::hash(&next.api,&next.account_id))?).await?;
 let snapshot=vault::project(&fresh,&next,g).await?;current(g)?;Store::new().commit(&next)?;current(g)?;let mut active=state()?;active.cache=Some(next);active.client=Some(fresh);update_identity(active.cache.as_ref(),"unlocked");serde_json::to_value(snapshot).map_err(|_|Error::new("invalidResponse","Cannot encode vault."))
}
pub fn biometric_unlock(text:String,expected:u64)->Result<Value>{crate::RUNTIME.block_on(async {let _guard=LANE.lock().await;current(expected)?;unlock(String::new(),expected,Some(text)).await})}
pub fn enroll(expected:u64)->Result<()> {
 crate::RUNTIME.block_on(async {
  let _guard=LANE.lock().await;
  current(expected)?;
  let (cache,instance)=authorized()?;
  let b64=instance.crypto().get_user_encryption_key().await.map_err(|_|Error::new("locked","Account key unavailable."))?;
  current(expected)?;
  let text=zeroize::Zeroizing::new(b64.to_string());
  #[derive(Serialize)]
  #[serde(rename_all="camelCase")]
  struct Enrollment<'a> {account_id:&'a str,server:&'a str,key_id:Option<&'a str>,key_b64:&'a str}
  let bytes=zeroize::Zeroizing::new(serde_json::to_vec(&Enrollment{account_id:&cache.account_id,server:&cache.api,key_id:None,key_b64:&text}).map_err(|_|Error::new("invalidResponse","Cannot encode enrollment."))?);
  let hash=Store::hash(&cache.api,&cache.account_id);
  api::credential(3,&hash,&bytes)?;
  if let Err(error)=current(expected){let _=api::credential(4,&hash,&[]);return Err(error)}
  Ok(())
 })
}
