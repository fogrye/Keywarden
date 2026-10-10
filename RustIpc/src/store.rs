use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, os::unix::fs::{DirBuilderExt,MetadataExt,OpenOptionsExt,PermissionsExt}, path::{Component,Path, PathBuf}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use bitwarden_core::{key_management::{MasterPasswordUnlockData, V2UpgradeToken, account_cryptographic_state::WrappedAccountCryptographicState}, OrganizationId};
use bitwarden_crypto::UnsignedSharedKey;
use bitwarden_vault::{Cipher, Folder};
use std::collections::HashMap;
use crate::account::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Cache {
    pub schema_version: u8,
    pub account_id: String,
    pub email: String,
    pub api: String,
    pub identity: String,
    pub unlock: MasterPasswordUnlockData,
    pub wrapped: WrappedAccountCryptographicState,
    pub upgrade_token: Option<V2UpgradeToken>,
    pub org_keys: HashMap<OrganizationId, UnsignedSharedKey>,
    pub ciphers: Vec<Cipher>,
    pub folders: Vec<Folder>,
    pub last_sync: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Pointer { api: String, account_id: String }

pub struct Store { root: PathBuf }
impl Store {
    pub fn new() -> Self {
        let test_root = if cfg!(debug_assertions) {
            std::env::var_os("BW_TEST_DATA_DIR").or_else(||std::env::var_os("BW_UI_TEST_DATA_DIR")).map(PathBuf::from)
        } else {None};
        let root = test_root.map(system_temp_path).unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join("Library/Application Support/Keywarden/Vault")
        });
        Self { root }
    }
    pub fn hash(api: &str, account_id: &str) -> String {
        let namespace=if cfg!(debug_assertions) {std::env::var("BW_TEST_NAMESPACE").or_else(|_|std::env::var("BW_UI_TEST_NAMESPACE")).ok()}else{None};
        let scope=namespace.map_or_else(||format!("{api}\n{account_id}"),|name|format!("{name}\n{api}\n{account_id}"));
        hex::encode(Sha256::digest(scope.as_bytes()))
    }
    pub fn device_id(&self)->Result<String> {
        secure_directory(&self.root)?;
        let path=self.root.join("device-id.json");
        if let Some(id)=read_json::<String>(&path)? {
            uuid::Uuid::parse_str(&id).map_err(|_|Error::new("storageUnavailable","Installation identity is invalid."))?;
            return Ok(id);
        }
        let id=uuid::Uuid::new_v4().to_string();
        atomic_json(&path,&id)?;
        Ok(id)
    }
    pub fn active(&self) -> Result<Option<Cache>> {
        if !check_directory(&self.root,false)? {return Ok(None)}
        let Some(pointer) = read_json::<Pointer>(&self.root.join("active-account.json"))? else { return Ok(None) };
        let dir = self.root.join(Self::hash(&pointer.api, &pointer.account_id));
        if !check_directory(&dir,false)? {return Err(Error::new("storageUnavailable","Account cache is missing; sign in to recover."))}
        let cache = read_json::<Cache>(&dir.join("cache.json"))?.ok_or_else(|| Error::new("storageUnavailable", "Account cache is missing; sign in to recover."))?;
        if cache.schema_version != 1 || cache.account_id != pointer.account_id || cache.api != pointer.api {
            return Err(Error::new("storageUnavailable", "Account cache is incompatible; sign in to recover."));
        }
        crate::api::validate_kdf(&cache.unlock.kdf)?;
        if cache.unlock.salt.is_empty() || cache.unlock.salt.len()>4096 {return Err(Error::new("storageUnavailable","Account cache contains invalid KDF salt."));}
        Ok(Some(cache))
    }
    pub fn commit(&self, cache: &Cache) -> Result<()> {
        if self.signed_out()? {return Err(Error::new("storageUnavailable","Complete pending sign-out before signing in."))}
        secure_directory(&self.root)?;
        let dir = self.root.join(Self::hash(&cache.api, &cache.account_id));
        secure_directory(&dir)?;
        atomic_json(&dir.join("cache.json"), cache)?;
        atomic_json(&self.root.join("active-account.json"), &Pointer {api:cache.api.clone(),account_id:cache.account_id.clone()})
    }
    pub fn begin_sign_out(&self, cache: &Cache) -> Result<()> {
        secure_directory(&self.root)?;
        atomic_json(&self.root.join("signed-out.json"), &Pointer {api:cache.api.clone(),account_id:cache.account_id.clone()})
    }
    pub fn pending_sign_out(&self)->Result<Option<(String,String)>> {
        if !check_directory(&self.root,false)? {return Ok(None)}
        Ok(read_json::<Pointer>(&self.root.join("signed-out.json"))?.map(|p|(p.api,p.account_id)))
    }
    pub fn finish_sign_out(&self, api:&str, account_id:&str) -> Result<()> {
        if !check_directory(&self.root,false)? {return Err(storage(std::io::Error::other("Signed-out cache root is missing")))}
        let dir = self.root.join(Self::hash(api,account_id));
        if check_directory(&dir,false)? {remove_checked(&dir.join("cache.json"))?}
        remove_checked(&self.root.join("active-account.json"))?;
        remove_checked(&self.root.join("signed-out.json"))
    }
    pub fn signed_out(&self) -> Result<bool> { Ok(self.pending_sign_out()?.is_some()) }
}
fn storage(_: std::io::Error) -> Error { Error::new("storageUnavailable", "Secure account storage is unavailable.") }
fn system_temp_path(path:PathBuf)->PathBuf {
    for (source,target,expected) in [("/var","/private/var",Path::new("private/var")),("/tmp","/private/tmp",Path::new("private/tmp"))] {
        if let Ok(rest)=path.strip_prefix(source) {
            if let Ok(link)=fs::symlink_metadata(source) {
                if link.uid()==0 && link.file_type().is_symlink() && fs::read_link(source).is_ok_and(|destination|destination==expected) {
                    return Path::new(target).join(rest);
                }
            }
        }
    }
    path
}
fn secure_directory(path:&Path)->Result<()> {check_directory(path,true).map(|_|())}
fn check_directory(path:&Path,create:bool)->Result<bool> {
    if !path.is_absolute(){return Err(storage(std::io::Error::other("Cache root must be absolute")))}
    let mut current=PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir=>{current.push("/")},
            Component::Normal(name)=>current.push(name),
            _=>return Err(storage(std::io::Error::other("Unsafe cache path component"))),
        }
        let metadata=match fs::symlink_metadata(&current) {
            Ok(metadata)=>metadata,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound && !create=>return Ok(false),
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{
                fs::DirBuilder::new().mode(0o700).create(&current).map_err(storage)?;
                fs::symlink_metadata(&current).map_err(storage)?
            },
            Err(error)=>return Err(storage(error)),
        };
        let mode=metadata.permissions().mode();
        let owner=metadata.uid();
        let protected=current==path || current.file_name().is_some_and(|name|name=="Keywarden");
        if !metadata.is_dir() || metadata.file_type().is_symlink() || (owner!=0 && owner!=unsafe{getuid()})
            || (protected && (owner!=unsafe{getuid()} || mode&0o077!=0))
            || (!protected && mode&0o022!=0 && !(owner==0 && mode&0o1000!=0)) {
            return Err(storage(std::io::Error::other("Unsafe cache directory")));
        }
    }
    Ok(true)
}
fn check_file(path:&Path)->Result<bool> {
    let metadata=match fs::symlink_metadata(path) {
        Ok(metadata)=>metadata,
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(false),
        Err(error)=>return Err(storage(error)),
    };
    if !metadata.is_file()||metadata.file_type().is_symlink()||metadata.nlink()!=1||metadata.uid()!=unsafe{getuid()}||metadata.permissions().mode()&0o077!=0 {
        return Err(storage(std::io::Error::other("Unsafe account file")));
    }
    Ok(true)
}
fn remove_checked(path:&Path)->Result<()> {
    if check_file(path)? {fs::remove_file(path).map_err(storage)?}
    Ok(())
}
unsafe extern "C" { fn getuid() -> u32; }
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !check_directory(path.parent().ok_or_else(||storage(std::io::Error::other("Missing cache parent")))?,false)? {return Ok(None)}
    if !check_file(path)? {return Ok(None)}
    let mut file=OpenOptions::new().read(true).custom_flags(0x100).open(path).map_err(storage)?;
    let md=file.metadata().map_err(storage)?;
    let entry=fs::symlink_metadata(path).map_err(storage)?;
    if !md.is_file() || md.nlink()!=1 || md.uid()!=unsafe { getuid() } || md.permissions().mode() & 0o077 != 0 || entry.file_type().is_symlink() || md.dev()!=entry.dev() || md.ino()!=entry.ino() || md.len()>64*1024*1024 {return Err(storage(std::io::Error::other("unsafe cache")))}
    let mut bytes=Vec::new(); file.read_to_end(&mut bytes).map_err(storage)?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_|Error::new("storageUnavailable","Account cache is corrupt; sign in to recover."))
}
fn atomic_json<T:Serialize>(path:&Path, value:&T)->Result<()> {
    secure_directory(path.parent().ok_or_else(||storage(std::io::Error::other("Missing cache parent")))?)?;
    check_file(path)?;
    let bytes=serde_json::to_vec(value).map_err(|_|storage(std::io::Error::other("serialize cache")))?;
    let temp=path.with_file_name(format!(".{}-{}.tmp",path.file_name().unwrap_or_default().to_string_lossy(),uuid::Uuid::new_v4()));
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).map_err(storage)?;
    let result=(|| {
        file.write_all(&bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        check_file(path)?;
        fs::rename(&temp,path).map_err(storage)?;
        File::open(path.parent().unwrap()).map_err(storage)?.sync_all().map_err(storage)
    })();
    if result.is_err() {let _=fs::remove_file(temp);} result
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{num::NonZeroU32,os::unix::fs::symlink};
    use bitwarden_core::key_management::KeySlotIds;
    use bitwarden_crypto::{Decryptable,KeyStore,Kdf,PrimitiveEncryptable};

    struct Fixture {store:Store}
    impl Fixture {
        fn new()->Self {
            let root=system_temp_path(std::env::temp_dir()).join(format!("keywarden-cache-test-{}",uuid::Uuid::new_v4()));
            Self{store:Store{root}}
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self){let _=fs::remove_dir_all(&self.store.root);}
    }
    fn encrypted_folder()->(Cache,bitwarden_crypto::SymmetricCryptoKey) {
        let keys=KeyStore::<KeySlotIds>::default();
        let mut context=keys.context_mut();
        let id=context.generate_symmetric_key();
        #[allow(deprecated)]
        let key=context.dangerous_get_symmetric_key(id).unwrap().clone();
        let email="fixture@example.test";
        let unlock=MasterPasswordUnlockData::derive("fixture master password",&Kdf::PBKDF2{iterations:NonZeroU32::new(5000).unwrap()},email,id,&context).unwrap();
        let name="Seed Folder".to_string().encrypt(&mut context,id).unwrap();
        let folder:Folder=serde_json::from_value(serde_json::json!({"id":uuid::Uuid::new_v4(),"name":name.to_string(),"revisionDate":"2025-01-01T00:00:00Z"})).unwrap();
        let cache=Cache {
            schema_version:1,account_id:uuid::Uuid::new_v4().to_string(),email:email.into(),
            api:"https://api.bitwarden.com".into(),identity:"https://identity.bitwarden.com".into(),
            wrapped:WrappedAccountCryptographicState::V1{private_key:unlock.master_key_wrapped_user_key.clone()},
            unlock,upgrade_token:None,org_keys:HashMap::new(),ciphers:Vec::new(),
            folders:vec![folder],last_sync:Some(100),
        };
        (cache,key)
    }
    #[test]
    fn encrypted_cache_survives_restart_and_sdk_password_unwrap() {
        let fixture=Fixture::new();
        let (cache,original)=encrypted_folder();
        fixture.store.commit(&cache).unwrap();
        let path=fixture.store.root.join(Store::hash(&cache.api,&cache.account_id)).join("cache.json");
        let on_disk=fs::read(&path).unwrap();
        assert!(!on_disk.windows(b"Seed Folder".len()).any(|part|part==b"Seed Folder"));
        assert!(!on_disk.windows(b"fixture master password".len()).any(|part|part==b"fixture master password"));
        let restored=fixture.store.active().unwrap().unwrap();
        let keys=KeyStore::<KeySlotIds>::default();
        let mut context=keys.context_mut();
        assert!(restored.unlock.unwrap_to_context("incorrect password",&mut context).is_err());
        let id=restored.unlock.unwrap_to_context("fixture master password",&mut context).unwrap();
        #[allow(deprecated)]
        let key=context.dangerous_get_symmetric_key(id).unwrap();
        assert_eq!(key,&original);
        let name:String=restored.folders[0].name.decrypt(&mut context,id).unwrap();
        assert_eq!(name,"Seed Folder");
        let old=fs::read(&path).unwrap();
        fs::write(&path,b"{broken").unwrap();
        assert!(fixture.store.active().is_err());
        assert_eq!(fs::read(&path).unwrap(),b"{broken");
        fs::write(&path,old).unwrap();
        assert_eq!(fixture.store.active().unwrap().unwrap().folders.len(),1);
    }
    #[test]
    fn symlinked_cache_component_or_destination_cannot_replace_existing_data() {
        let fixture=Fixture::new();
        let (cache,_)=encrypted_folder();
        let outside=fixture.store.root.with_extension("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside,fs::Permissions::from_mode(0o700)).unwrap();
        let dir=fixture.store.root.join(Store::hash(&cache.api,&cache.account_id));
        secure_directory(&fixture.store.root).unwrap();
        symlink(&outside,&dir).unwrap();
        assert!(fixture.store.commit(&cache).is_err());
        assert!(!outside.join("cache.json").exists());
        fs::remove_file(&dir).unwrap();
        fixture.store.commit(&cache).unwrap();
        let cache_path=dir.join("cache.json");
        let outside_file=outside.join("outside.json");
        fs::write(&outside_file,b"unchanged").unwrap();
        fs::set_permissions(&outside_file,fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&cache_path).unwrap();
        symlink(&outside_file,&cache_path).unwrap();
        assert!(fixture.store.active().is_err());
        assert!(fixture.store.commit(&cache).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(),b"unchanged");
        fs::remove_file(cache_path).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
