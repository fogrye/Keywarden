use std::{num::NonZeroU32, sync::{Arc,Mutex}, time::{Duration,SystemTime,UNIX_EPOCH}, ffi::CString};
use bitwarden_crypto::{Kdf,KeyStore};
use bitwarden_core::{key_management::{KeySlotIds,MasterPasswordAuthenticationData},auth::auth_tokens::TokenHandler};
use bitwarden_state::registry::StateRegistry;
use serde::{Deserialize,Serialize};
use serde_json::Value;
use url::Url;
use zeroize::{Zeroize,Zeroizing};
use crate::account::{Error,Result};

#[derive(Clone,Serialize,Deserialize)]
pub struct Endpoints { pub api:String,pub identity:String,pub server:String }
impl Endpoints {
 pub fn parse(input:&str)->Result<Self> {
  let input=input.trim().trim_end_matches('/');
  let input=if input.is_empty(){"https://bitwarden.com"}else{input};
  let url=Url::parse(input).map_err(|_|Error::new("invalidInput","Invalid server URL."))?;
  let host=url.host_str().ok_or_else(||Error::new("invalidInput","Invalid server URL."))?;
  if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !matches!(url.scheme(),"https"|"http") || (url.scheme()=="http" && !matches!(host,"localhost"|"127.0.0.1"|"[::1]"|"::1")) { return Err(Error::new("invalidInput","Server must be HTTPS (except loopback HTTP) without credentials or query.")); }
  let normalized=url.to_string().trim_end_matches('/').to_string();
  if normalized=="https://bitwarden.com" {return Ok(Self{api:"https://api.bitwarden.com".into(),identity:"https://identity.bitwarden.com".into(),server:normalized})}
  if normalized=="https://bitwarden.eu" {return Ok(Self{api:"https://api.bitwarden.eu".into(),identity:"https://identity.bitwarden.eu".into(),server:normalized})}
  Ok(Self{api:format!("{normalized}/api"),identity:format!("{normalized}/identity"),server:normalized})
 }
}
fn aliases<'a>(v:&'a Value,names:&[&str])->Result<Option<&'a Value>> {
 let mut found=None;
 for name in names { if let Some(value)=v.get(*name) { if found.is_some(){return Err(Error::new("invalidResponse","Server returned conflicting authentication fields."))} found=Some(value); } }
 Ok(found)
}
pub fn unique_alias<'a>(value:&'a Value,names:&[&str])->Result<Option<&'a Value>>{aliases(value,names)}
fn integer(v:&Value,names:&[&str],min:u64,max:u64)->Result<u32>{
 let n=aliases(v,names)?.and_then(Value::as_u64).ok_or_else(||Error::new("invalidResponse","Invalid account KDF settings."))?;
 if n<min || n>max {return Err(Error::new("invalidResponse","Account KDF settings exceed supported security/resource limits."))} Ok(n as u32)
}
pub fn parse_prelogin(v:&Value,email:&str)->Result<(Kdf,String)> {
 let source=aliases(v,&["kdfSettings","KdfSettings"])?.unwrap_or(v);
 let kind=aliases(source,&["kdfType","KdfType","kdf","Kdf"])?.and_then(Value::as_i64).ok_or_else(||Error::new("invalidResponse","Invalid account KDF settings."))?;
 let iterations=integer(source,&["iterations","Iterations","kdfIterations","KdfIterations"],if kind==0{5000}else{2},if kind==0{2_000_000}else{10})?;
 let nz=|n|NonZeroU32::new(n).expect("validated positive KDF parameter");
 let kdf=match kind {0=>Kdf::PBKDF2{iterations:nz(iterations)},1=>Kdf::Argon2id{iterations:nz(iterations),memory:nz(integer(source,&["memory","Memory","kdfMemory","KdfMemory"],16,1024)?),parallelism:nz(integer(source,&["parallelism","Parallelism","kdfParallelism","KdfParallelism"],1,16)?)},_=>return Err(Error::new("invalidResponse","Unsupported account KDF."))};
 let outer=aliases(v,&["salt","Salt"])?;
 let inner=if std::ptr::eq(source,v){None}else{aliases(source,&["salt","Salt"])?};
 if outer.is_some()&&inner.is_some(){return Err(Error::new("invalidResponse","Server returned conflicting KDF salts."))}
 let salt=outer.or(inner).and_then(Value::as_str).unwrap_or(email);
 if salt.is_empty() || salt.len()>4096 {return Err(Error::new("invalidResponse","Invalid account KDF salt."))} Ok((kdf,salt.to_string()))
}
pub fn validate_kdf(kdf:&Kdf)->Result<()>{
 let valid=match kdf {
  Kdf::PBKDF2{iterations}=> (5000..=2_000_000).contains(&iterations.get()),
  Kdf::Argon2id{iterations,memory,parallelism}=> (2..=10).contains(&iterations.get())&&(16..=1024).contains(&memory.get())&&(1..=16).contains(&parallelism.get()),
 };
 if valid {Ok(())}else{Err(Error::new("invalidResponse","Account KDF settings exceed supported security/resource limits."))}
}
// Send our product version, never an invented official-client version to bypass crypto checks.
const CLIENT_VERSION:&str=env!("CARGO_PKG_VERSION");
fn identity_http()->Result<reqwest::Client>{
 let mut headers=reqwest::header::HeaderMap::new();
 headers.insert("Bitwarden-Client-Name",reqwest::header::HeaderValue::from_static("desktop"));
 headers.insert("Bitwarden-Client-Version",reqwest::header::HeaderValue::from_static(CLIENT_VERSION));
 headers.insert("Device-Type",reqwest::header::HeaderValue::from_static("7"));
 bitwarden_api_base::new_http_client_builder().default_headers(headers)
  .user_agent(concat!("Keywarden/",env!("CARGO_PKG_VERSION")))
  .redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build()
  .map_err(|_|Error::new("networkUnavailable","Cannot initialize secure network client."))
}
fn login_error(status:reqwest::StatusCode,body:&Value)->Error{
 if status==reqwest::StatusCode::TOO_MANY_REQUESTS{return Error::new("rateLimited","Too many sign-in attempts. Wait a few minutes, then try again.")}
 if status.is_server_error(){return Error::new("networkUnavailable","The account server is temporarily unavailable. Try again later.")}
 let code=body.get("error").and_then(Value::as_str).unwrap_or("");
 let message=body.get("ErrorModel").and_then(|v|v.get("Message")).and_then(Value::as_str).unwrap_or("");
 match code {
  "version_header_missing"=>return Error::new("clientVersionRejected","The server did not receive Keywarden's client version. Update Keywarden, then try again."),
  "invalid_client_version"=>return Error::new("clientVersionRejected","The server requires a newer client for this account's encryption. Use an up-to-date official Bitwarden client."),
  _=>{}
 }
 if message=="new device verification required"{return Error::new("deviceVerificationRequired","Bitwarden requires an email code to verify this new device. Keywarden does not yet support new-device verification.")}
 if code=="device_error"{return Error::new("deviceRejected","Bitwarden rejected this device's sign-in information.")}
 if body.get("TwoFactorProviders2").and_then(Value::as_object).is_some_and(|v|!v.is_empty())
  || body.get("TwoFactorProviders").and_then(Value::as_array).is_some_and(|v|!v.is_empty()){
  return Error::new("twoFactorRequired","This account requires two-step login. Keywarden does not yet support two-step login.")
 }
 if body.get("SsoOrganizationIdentifier").and_then(Value::as_str).is_some_and(|v|!v.is_empty()){
  return Error::new("unsupportedAuthentication","This account requires single sign-on. Keywarden does not yet support single sign-on.")
 }
 if body.get("HCaptcha_SiteKey").and_then(Value::as_str).is_some_and(|v|!v.is_empty()){
  return Error::new("captchaRequired","Bitwarden requires a CAPTCHA for this sign-in. Keywarden does not yet support CAPTCHA verification.")
 }
 if matches!(code,"invalid_grant"|"invalid_username_or_password"){return Error::new("invalidPassword","Email or master password is incorrect.")}
 Error::new("signInFailed","The server rejected sign-in. Try again later or check your account in the official Bitwarden client.")
}
pub async fn login_request(endpoints:&Endpoints,email:&str,password:&str,device_id:&str)->Result<(Value,Kdf,String)> {
 let client=identity_http()?;
 let modern=format!("{}/accounts/prelogin/password",endpoints.identity);
 let mut response=client.post(modern).json(&serde_json::json!({"email":email})).send().await.map_err(|_|Error::new("networkUnavailable","Could not connect to the account server."))?;
 if matches!(response.status().as_u16(),404|405) {response=client.post(format!("{}/accounts/prelogin",endpoints.identity)).json(&serde_json::json!({"email":email})).send().await.map_err(|_|Error::new("networkUnavailable","Could not connect to the account server."))?;}
 if !response.status().is_success(){let status=response.status();return Err(login_error(status,&response.json::<Value>().await.unwrap_or(Value::Null)))}
 let prelogin:Value=response.json().await.map_err(|_|Error::new("invalidResponse","Invalid prelogin response."))?;
 let (kdf,salt)=parse_prelogin(&prelogin,email)?;
 let hash=MasterPasswordAuthenticationData::derive(password,&kdf,&salt).map_err(|_|Error::new("invalidResponse","Account KDF could not be derived."))?.master_password_authentication_hash.to_string();
 let body=[("grant_type","password"),("username",email),("password",hash.as_str()),("scope","api offline_access"),("client_id","desktop"),("deviceType","7"),("deviceIdentifier",device_id),("deviceName","Keywarden")];
 let response=client.post(format!("{}/connect/token",endpoints.identity)).form(&body).send().await.map_err(|_|Error::new("networkUnavailable","Could not connect to the identity server."))?;
 let status=response.status();
 if !status.is_success(){return Err(login_error(status,&response.json::<Value>().await.unwrap_or(Value::Null)))}
 let token:Value=response.json().await.map_err(|_|Error::new("invalidResponse","Invalid identity response."))?;
 for key in ["forcePasswordReset","resetMasterPassword","apiUseKeyConnector"] {if token.get(key).and_then(Value::as_bool)==Some(true){return Err(Error::new("unsupportedAuthentication","This account requires a sign-in step not supported by this app. Complete it in the official client."))}}
 Ok((token,kdf,salt))
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Tokens {pub access:String,pub refresh:String,pub expires_at:u64}
impl Drop for Tokens {fn drop(&mut self){self.access.zeroize();self.refresh.zeroize()}}
unsafe extern "C" {fn bw_credentials(action:i32,account_hash:*const std::ffi::c_char,input:*const u8,input_length:usize,output:*mut u8,capacity:usize)->i32;}
pub fn credential(action:i32,hash:&str,input:&[u8])->Result<Vec<u8>> {
 let hash=CString::new(hash).map_err(|_|Error::new("invalidInput","Invalid account identity."))?;
 let reads=matches!(action,0|7);
 let mut output=Zeroizing::new(vec![0u8;if reads{16384}else{0}]);
 let n=unsafe{bw_credentials(action,hash.as_ptr(),input.as_ptr(),input.len(),output.as_mut_ptr(),output.len())};
 if reads {
  if n<0 || n as usize>output.len(){return Err(Error::new("storageUnavailable","Secure credential storage is unavailable."))}
  Ok(output[..n as usize].to_vec())
 } else if n==1 {Ok(Vec::new())}
 else {Err(Error::new("storageUnavailable","Secure credential storage is unavailable."))}
}
pub fn load_tokens(hash:&str)->Result<Option<Tokens>>{let bytes=Zeroizing::new(credential(0,hash,&[])?); if bytes.is_empty(){return Ok(None)}serde_json::from_slice(&bytes).map(Some).map_err(|_|Error::new("storageUnavailable","Stored credentials are invalid."))}
pub fn save_tokens(hash:&str,tokens:&Tokens)->Result<()>{let bytes=Zeroizing::new(serde_json::to_vec(tokens).map_err(|_|Error::new("invalidResponse","Invalid token record."))?);credential(1,hash,&bytes).map(|_|())}
pub struct KeychainTokenHandler {
 pub hash:String,pub api:String,pub identity:String,pub email:String,pub kdf:Kdf,
 pub tokens:Arc<Mutex<Option<Tokens>>>,refresh:Arc<tokio::sync::Mutex<()>>,
}
impl KeychainTokenHandler {
 pub fn new(hash:String,api:String,identity:String,email:String,kdf:Kdf,tokens:Option<Tokens>)->Arc<Self>{
  Arc::new(Self{hash,api,identity,email,kdf,tokens:Arc::new(Mutex::new(tokens)),refresh:Arc::new(tokio::sync::Mutex::new(()))})
 }
}
#[async_trait::async_trait]
impl TokenHandler for KeychainTokenHandler {
 fn initialize_middleware(&self,_state:&StateRegistry,_identity:bitwarden_api_base::Configuration,_keys:KeyStore<KeySlotIds>)->Arc<dyn reqwest_middleware::Middleware>{
  Arc::new(AuthMiddleware{api:self.api.clone(),identity:self.identity.clone(),email:self.email.clone(),kdf:self.kdf.clone(),hash:self.hash.clone(),tokens:self.tokens.clone(),refresh:self.refresh.clone()})
 }
 async fn set_tokens(&self,access:String,refresh:Option<String>,expires_in:u64){if let Some(refresh)=refresh {let t=Tokens{access,refresh,expires_at:now()+expires_in};if save_tokens(&self.hash,&t).is_ok(){if let Ok(mut guard)=self.tokens.lock(){*guard=Some(t)}}}}
}
struct AuthMiddleware{api:String,identity:String,email:String,kdf:Kdf,hash:String,tokens:Arc<Mutex<Option<Tokens>>>,refresh:Arc<tokio::sync::Mutex<()>>}
fn allowed_api_url(target:&Url,base:&str)->bool {
 let Ok(origin)=Url::parse(base) else{return false};
 let path=origin.path().trim_end_matches('/');
 target.origin()==origin.origin() && target.path().strip_prefix(path).is_some_and(|suffix|suffix.is_empty()||suffix.starts_with('/'))
}
impl AuthMiddleware {
 fn failure(message:&'static str)->reqwest_middleware::Error{reqwest_middleware::Error::Middleware(std::io::Error::other(message).into())}
 async fn access(&self,force:bool)->std::result::Result<String,reqwest_middleware::Error>{
  let cached=self.tokens.lock().map_err(|_|Self::failure("Credential lock unavailable"))?.clone().ok_or_else(||Self::failure("Account requires sign-in"))?;
  if !force && cached.expires_at>now()+60{return Ok(cached.access.clone())}
  let _single=self.refresh.lock().await;
  let cached=self.tokens.lock().map_err(|_|Self::failure("Credential lock unavailable"))?.clone().ok_or_else(||Self::failure("Account requires sign-in"))?;
  if !force && cached.expires_at>now()+60{return Ok(cached.access.clone())}
  if cached.refresh.is_empty(){return Err(Self::failure("Account requires sign-in"))}
  let identity_client=identity_http().map_err(|_|Self::failure("Secure identity client unavailable"))?;
  let identity=bitwarden_api_api::Configuration{base_path:self.identity.clone(),client:reqwest_middleware::ClientBuilder::new(identity_client).build()};
  let method=bitwarden_core::client::login_method::UserLoginMethod::Username{client_id:"desktop".into(),email:self.email.clone(),kdf:self.kdf.clone()};
  let (access,rotated,expires)=match bitwarden_core::auth::renew::renew_pm_token_sdk_managed(Some(cached.refresh.clone()),&method,identity).await {
   Ok(data)=>data,
   Err(bitwarden_core::auth::login::LoginError::IdentityFail(failure)) if failure.error=="invalid_grant"=>{
    crate::account::invalidate();
    let _=credential(2,&self.hash,&[]);
    let _=credential(4,&self.hash,&[]);
    let _=credential(6,&self.hash,&[]);
    return Err(Self::failure("Account session revoked"));
   },
   Err(_)=>return Err(Self::failure("Account session expired or network unavailable")),
  };
  let updated=Tokens{access,refresh:rotated.unwrap_or_else(||cached.refresh.clone()),expires_at:now()+expires};
  save_tokens(&self.hash,&updated).map_err(|_|Self::failure("Secure credential storage unavailable"))?;
  let result=updated.access.clone();
  *self.tokens.lock().map_err(|_|Self::failure("Credential lock unavailable"))?=Some(updated);
  Ok(result)
 }
}
#[async_trait::async_trait]
impl reqwest_middleware::Middleware for AuthMiddleware {
 async fn handle(&self,mut req:reqwest::Request,ext:&mut http::Extensions,next:reqwest_middleware::Next<'_>)->std::result::Result<reqwest::Response,reqwest_middleware::Error>{
  if !allowed_api_url(req.url(),&self.api){return Err(Self::failure("API origin violation"))}
  let bearer=ext.get::<bitwarden_api_base::AuthRequired>().is_some();
  if bearer {
   let token=self.access(false).await?;
   let header=reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_|Self::failure("Invalid session token"))?;
   req.headers_mut().insert(reqwest::header::AUTHORIZATION,header);
  }
  let retry=if bearer && req.method()==reqwest::Method::GET{req.try_clone()}else{None};
  let response=next.clone().run(req,ext).await?;
  if response.status()!=reqwest::StatusCode::UNAUTHORIZED{return Ok(response)}
  let Some(mut retry)=retry else{return Ok(response)};
  let token=self.access(true).await?;
  let header=reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_|Self::failure("Invalid session token"))?;
  retry.headers_mut().insert(reqwest::header::AUTHORIZATION,header);
  next.run(retry,ext).await
 }
}
pub fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).map_or(0,|d|d.as_secs())}
/// Request extension for file transfers, which get a long deadline instead of the usual 30 seconds.
#[derive(Clone,Copy)]
pub struct LongTransfer;
pub struct OriginPolicy {pub api:String}
#[async_trait::async_trait]
impl reqwest_middleware::Middleware for OriginPolicy {
 async fn handle(&self,req:reqwest::Request,ext:&mut http::Extensions,next:reqwest_middleware::Next<'_>)->std::result::Result<reqwest::Response,reqwest_middleware::Error>{
  if !allowed_api_url(req.url(),&self.api) {
   return Err(reqwest_middleware::Error::Middleware(std::io::Error::other("API origin violation").into()));
  }
  let limit=Duration::from_secs(if ext.get::<LongTransfer>().is_some(){1800}else{30});
  tokio::time::timeout(limit,next.run(req,ext)).await.map_err(|_|reqwest_middleware::Error::Middleware(std::io::Error::other("Network deadline exceeded").into()))?
 }
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn identity_errors_distinguish_credentials_challenges_and_server_failures(){
  use reqwest::StatusCode;
  let cases=[
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"version_header_missing"}),"clientVersionRejected"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_client_version"}),"clientVersionRejected"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"device_error","ErrorModel":{"Message":"new device verification required"}}),"deviceVerificationRequired"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"device_error","ErrorModel":{"Message":"no device information provided"}}),"deviceRejected"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_grant","TwoFactorProviders2":{"0":null}}),"twoFactorRequired"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_grant","TwoFactorProviders":[0]}),"twoFactorRequired"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_grant","SsoOrganizationIdentifier":"example"}),"unsupportedAuthentication"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_grant","HCaptcha_SiteKey":"fixture"}),"captchaRequired"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_grant","TwoFactorProviders2":{},"TwoFactorProviders":[]}),"invalidPassword"),
   (StatusCode::BAD_REQUEST,serde_json::json!({"error":"invalid_username_or_password"}),"invalidPassword"),
   (StatusCode::TOO_MANY_REQUESTS,Value::Null,"rateLimited"),
   (StatusCode::SERVICE_UNAVAILABLE,serde_json::json!({"error":"invalid_grant"}),"networkUnavailable"),
   (StatusCode::FORBIDDEN,serde_json::json!({"error":"unknown","error_description":"secret-token"}),"signInFailed"),
  ];
  for (status,body,expected) in cases{
   let error=login_error(status,&body);
   assert_eq!(error.code,expected,"status: {status}");
   assert!(!error.message.contains("secret-token"));
  }
 }
 #[tokio::test]
 async fn sign_in_succeeds_when_identity_requires_a_client_version(){
  use std::io::{BufRead,Read,Write};
  let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  listener.set_nonblocking(true).unwrap();
  let base=format!("http://{}",listener.local_addr().unwrap());
  let server=std::thread::spawn(move || {
   for _ in 0..2{
    let deadline=std::time::Instant::now()+Duration::from_secs(5);
    let mut stream=loop{
     match listener.accept(){
      Ok((stream,_))=>break stream,
      Err(error) if error.kind()==std::io::ErrorKind::WouldBlock && std::time::Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(10)),
      Err(error)=>panic!("identity fixture did not receive a request: {error}"),
     }
    };
    // macOS inherits the listener's nonblocking mode on accepted sockets.
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader=std::io::BufReader::new(&mut stream);
    let mut line=String::new();
    reader.read_line(&mut line).unwrap();
    let prelogin=line.starts_with("POST /identity/accounts/prelogin/password ");
    let mut has_version=false;
    let mut length=0;
    loop{
     line.clear();reader.read_line(&mut line).unwrap();
     if line=="\r\n" || line.is_empty(){break}
     if let Some((name,value))=line.split_once(':'){
      if name.eq_ignore_ascii_case("Bitwarden-Client-Version"){
       let parts:Vec<_>=value.trim().split('.').collect();
       has_version=parts.len()==3 && parts.iter().all(|v|v.parse::<u32>().is_ok());
      }
      if name.eq_ignore_ascii_case("Content-Length"){length=value.trim().parse::<usize>().unwrap();}
     }
    }
    let mut body=vec![0;length];reader.read_exact(&mut body).unwrap();
    drop(reader);
    let (status,body)=if !has_version{
     ("400 Bad Request",r#"{"error":"version_header_missing"}"#)
    }else if prelogin{
     ("200 OK",r#"{"kdf":0,"kdfIterations":5000}"#)
    }else{
     ("200 OK",r#"{"access_token":"fixture-access-token","token_type":"Bearer"}"#)
    };
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
   }
  });
  let result=login_request(&Endpoints::parse(&base).unwrap(),"fixture@example.test","fixture-password","fixture-device").await;
  server.join().unwrap();
  let (token,_,salt)=result.unwrap();
  assert_eq!(token["access_token"],"fixture-access-token");
  assert_eq!(salt,"fixture@example.test");
 }
 #[test]
 fn canonical_servers_reject_credential_relocation() {
  let us=Endpoints::parse("https://bitwarden.com/").unwrap();
  assert_eq!(us.api,"https://api.bitwarden.com");
  assert_eq!(us.identity,"https://identity.bitwarden.com");
  let custom=Endpoints::parse("https://EXAMPLE.com:443/vault///").unwrap();
  assert_eq!(custom.api,"https://example.com/vault/api");
  assert_eq!(custom.identity,"https://example.com/vault/identity");
  for input in ["http://example.com","https://user:pass@example.com","https://example.com?url=https://elsewhere","https://example.com/#fragment","http://127.0.0.2"] {
   assert!(Endpoints::parse(input).is_err(),"{input}");
  }
  assert!(Endpoints::parse("http://127.0.0.1:8443").is_ok());
 }
 #[test]
 fn kdf_limits_and_duplicate_aliases_fail_before_derivation() {
  let email="fixture@example.test";
  let good=serde_json::json!({"Kdf":0,"KdfIterations":5000});
  assert!(matches!(parse_prelogin(&good,email).unwrap().0,Kdf::PBKDF2{..}));
  for bad in [
   serde_json::json!({"kdf":0,"kdfIterations":4999}),
   serde_json::json!({"kdf":0,"kdfIterations":2000001}),
   serde_json::json!({"kdf":1,"kdfIterations":2,"kdfMemory":15,"kdfParallelism":1}),
   serde_json::json!({"kdf":1,"kdfIterations":2,"kdfMemory":16,"kdfParallelism":17}),
   serde_json::json!({"kdf":0,"Kdf":1,"kdfIterations":5000}),
   serde_json::json!({"kdf":0,"kdfIterations":5000,"KdfIterations":5000}),
   serde_json::json!({"kdf":0,"kdfIterations":5000.5}),
  ] {assert!(parse_prelogin(&bad,email).is_err(),"{bad}")}
 }
}
