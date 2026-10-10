use std::{ffi::{CStr, CString, c_char}, sync::LazyLock};
use bitwarden_generators::{GeneratorClientsExt, PassphraseGeneratorRequest, PasswordGeneratorRequest};
use serde::Deserialize;
use serde_json::{Value, json};
use crate::account::{self, Error};

pub(crate) static GENERATOR: LazyLock<bitwarden_core::Client> = LazyLock::new(|| bitwarden_core::Client::new(None));

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Request {
    Status,
    Login { email:String,password:String,server:String },
    Unlock { password:String },
    UnlockPin { pin:String },
    EnrollPin { pin:String },
    DisablePin,
    Sync,
    Item { id:String },
    Totp { id:String },
    SaveItem { item:crate::items::ItemData },
    Organize { id:String, favorite:bool, folder_id:Option<String> },
    DeleteItem { id:String, permanent:bool },
    RestoreItem { id:String },
    ArchiveItem { id:String, archived:bool },
    AttachmentDownload { id:String, attachment_id:String, path:String },
    AttachmentUpload { id:String, path:String },
    AttachmentDelete { id:String, attachment_id:String },
    /// `format`: json, csv, jsonEncryptedAccount or jsonEncryptedPassword. The master password is
    /// checked before anything is written. The file goes to `path`; only counts come back. Without
    /// a `path` the call only checks the master password, so the save panel can follow it.
    ExportVault { format:String, file_password:Option<String>, master_password:String, path:Option<String> },
    /// Reads the file, decrypts it and holds the items in memory; replies with counts only.
    ImportPrepare { path:String, file_password:Option<String> },
    ImportCommit,
    ImportDiscard,
    SaveFolder { id:Option<String>, name:String },
    DeleteFolder { id:String },
    Lock,
    Logout,
    PasswordStrength { password:String, email:Option<String>, inputs:Option<Vec<String>> },
    Generate {
        mode: String, length: Option<u8>, lowercase: Option<bool>, uppercase: Option<bool>,
        numbers: Option<bool>, special: Option<bool>, avoid_ambiguous: Option<bool>,
        num_words: Option<u8>, separator: Option<String>, capitalize: Option<bool>,
        include_number: Option<bool>, min_number: Option<u8>, min_special: Option<u8>,
    },
    /// Username generation. `token` is a forwarder secret and must never be logged.
    GenerateUsername {
        kind: String, capitalize: Option<bool>, include_number: Option<bool>,
        email: Option<String>, domain: Option<String>, service: Option<String>,
        token: Option<String>, base_url: Option<String>, website: Option<String>,
    },
}

/// zxcvbn score (0-4) from the SDK. Like Bitwarden Desktop, only the first 100 characters are scored,
/// which also bounds the cost. The email's local part, item name and username are penalized inputs.
fn password_strength(password: String, email: Option<String>, inputs: Option<Vec<String>>) -> Value {
    let password: String = password.chars().take(100).collect();
    let inputs: Vec<String> = inputs.unwrap_or_default().into_iter()
        .map(|input| input.trim().to_lowercase()).filter(|input| !input.is_empty()).collect();
    let score = if password.is_empty() { 0 } else {
        GENERATOR.auth().password_strength(password, email.unwrap_or_default(), inputs)
    };
    json!({"score":score})
}

fn dispatch(request: Request) -> Result<Value, Error> {
    match request {
        Request::PasswordStrength { password, email, inputs } => Ok(password_strength(password, email, inputs)),
        Request::Generate { mode, length, lowercase, uppercase, numbers, special,
            avoid_ambiguous, num_words, separator, capitalize, include_number, min_number, min_special } => {
            let generator = GENERATOR.generator();
            let text = match mode.as_str() {
                "password" => generator.password(PasswordGeneratorRequest {
                    length: length.unwrap_or(16), lowercase: lowercase.unwrap_or(true),
                    uppercase: uppercase.unwrap_or(true), numbers: numbers.unwrap_or(true),
                    special: special.unwrap_or(false), avoid_ambiguous: avoid_ambiguous.unwrap_or(false),
                    min_number: min_number.map(|value| value.min(9)),
                    min_special: min_special.map(|value| value.min(9)),
                    ..Default::default()
                }).map_err(|_| Error::new("invalidInput","Invalid password generator options."))?,
                "passphrase" => generator.passphrase(PassphraseGeneratorRequest {
                    num_words: num_words.unwrap_or(3),
                    word_separator: separator.unwrap_or_else(|| " ".into()),
                    capitalize: capitalize.unwrap_or(false), include_number: include_number.unwrap_or(false),
                }).map_err(|_| Error::new("invalidInput","Invalid passphrase generator options."))?,
                _ => return Err(Error::new("invalidInput","Unknown generator mode.")),
            };
            Ok(json!({"text":text}))
        }
        Request::GenerateUsername { kind, capitalize, include_number, email, domain, service, token, base_url, website } =>
            crate::generator::username(crate::generator::UsernameInput {
                kind, capitalize, include_number, email, domain, service, token, base_url, website,
            }).map(|text| json!({"text":text})),
        other => std::thread::Builder::new()
            .name("keywarden-account".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || account::dispatch(other))
            .map_err(|_| Error::new("storageUnavailable", "Cannot start account worker."))?
            .join()
            .unwrap_or_else(|_| Err(Error::new("invalidResponse", "Account operation failed.")))
    }
}

fn reply(result: Result<Value,Error>) -> *mut c_char {
    let value=match result {Ok(value)=>json!({"ok":true,"value":value}),Err(error)=>json!({"ok":false,"error":error})};
    CString::new(value.to_string()).expect("JSON cannot contain NUL").into_raw()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bw_app_request(request: *const c_char) -> *mut c_char {
    let result=std::panic::catch_unwind(||{
        if request.is_null(){return Err(Error::new("invalidInput","Invalid request."))}
        let bytes=unsafe {CStr::from_ptr(request)}.to_bytes();
        if bytes.len()>1024*1024{return Err(Error::new("invalidInput","Request too large."))}
        let request=serde_json::from_slice::<Request>(bytes).map_err(|_|Error::new("invalidInput","Invalid or unsupported request."))?;
        dispatch(request)
    }).unwrap_or_else(|_|Err(Error::new("invalidResponse","Account operation failed.")));
    reply(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bw_app_response_free(response: *mut c_char) {
    if !response.is_null() {
        let text=unsafe {CString::from_raw(response)};
        let mut bytes=text.into_bytes_with_nul();
        zeroize::Zeroize::zeroize(&mut bytes);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn bw_app_invalidate_session()->u64{account::invalidate()}
#[unsafe(no_mangle)]
pub extern "C" fn bw_app_generation()->u64{account::generation()}
#[unsafe(no_mangle)]
pub extern "C" fn bw_app_account_identity()->*mut c_char{account::identity().map(|v|CString::new(v.to_string()).expect("identity JSON").into_raw()).unwrap_or(std::ptr::null_mut())}
#[unsafe(no_mangle)]
pub extern "C" fn bw_app_enroll_biometrics(expected_generation:u64)->i32{if account::enroll(expected_generation).is_ok(){1}else{-1}}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bw_app_unlock_with_key(bytes:*const u8,length:usize,expected_generation:u64)->*mut c_char{
    if bytes.is_null()||length==0||length>4096{return reply(Err(Error::new("invalidInput","Invalid account credential.")))}
    let text=unsafe{std::slice::from_raw_parts(bytes,length)};
    let text=match std::str::from_utf8(text){Ok(s)=>s.to_owned(),Err(_)=>return reply(Err(Error::new("invalidInput","Invalid account credential.")))};
    reply(account::biometric_unlock(text,expected_generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[unsafe(no_mangle)]
    extern "C" fn bw_log(_message: *const c_char) {}

    // The Rust-only test executable has no Swift Keychain owner; an in-memory map stands in for it.
    static CREDENTIALS: std::sync::Mutex<Vec<((u8, String), Vec<u8>)>> = std::sync::Mutex::new(Vec::new());
    #[unsafe(no_mangle)]
    extern "C" fn bw_credentials(
        action: i32, account: *const c_char, input: *const u8, length: usize,
        output: *mut u8, capacity: usize,
    ) -> i32 {
        let account = unsafe { CStr::from_ptr(account) }.to_string_lossy().into_owned();
        let service = match action { 0..=2 => 0, 3 | 4 => 1, _ => 2 };
        let key = (service, account);
        let mut store = CREDENTIALS.lock().unwrap();
        store.retain(|(stored, _)| !(matches!(action, 1..=6) && *stored == key));
        match action {
            0 | 7 => store.iter().find(|(stored, _)| *stored == key).map_or(0, |(_, value)| {
                if value.len() > capacity { return -1 }
                unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len()) };
                value.len() as i32
            }),
            1 | 3 | 5 => { store.push((key, unsafe { std::slice::from_raw_parts(input, length) }.to_vec())); 1 }
            2 | 4 | 6 => 1,
            _ => -1,
        }
    }


    fn request(input: &str) -> Value {
        let input = CString::new(input).unwrap();
        let ptr = unsafe { bw_app_request(input.as_ptr()) };
        assert!(!ptr.is_null());
        let reply: Value = serde_json::from_slice(unsafe { CStr::from_ptr(ptr) }.to_bytes()).unwrap();
        unsafe { bw_app_response_free(ptr) };
        reply
    }

    #[test]
    fn password_strength_scores_and_penalizes_user_inputs() {
        let score = |json: &str| request(json)["value"]["score"].as_u64().unwrap();
        assert_eq!(score(r#"{"op":"passwordStrength","password":"password"}"#), 0);
        assert_eq!(score(r#"{"op":"passwordStrength","password":"VeryStrong123@#","email":"random@bitwarden.com"}"#), 4);
        assert_eq!(score(r#"{"op":"passwordStrength","password":""}"#), 0);
        let plain = score(r#"{"op":"passwordStrength","password":"zebracorn7734"}"#);
        let penalized = score(r#"{"op":"passwordStrength","password":"zebracorn7734","email":"zebracorn@example.com","inputs":["ZebraCorn7734"]}"#);
        assert!(penalized < plain, "{penalized} !< {plain}");
    }

    #[test]
    fn password_strength_bounds_very_long_input() {
        let long = "a".repeat(100_000);
        let reply = request(&json!({"op":"passwordStrength","password":long}).to_string());
        assert!(reply["value"]["score"].as_u64().is_some_and(|score| score <= 1), "{reply}");
    }

    #[test]
    fn password_options_produce_requested_length_and_character_classes() {
        let reply = request(r#"{"op":"generate","mode":"password","length":24,"lowercase":true,"uppercase":false,"numbers":false,"special":false}"#);
        let generated = reply["value"]["text"].as_str().unwrap();
        assert_eq!(generated.chars().count(), 24);
        assert!(generated.chars().all(|character| character.is_ascii_lowercase()));
    }

    #[test]
    fn password_minimum_numbers_and_special_characters_are_honoured() {
        for _ in 0..40 {
            let reply = request(r#"{"op":"generate","mode":"password","length":20,"lowercase":true,"uppercase":true,"numbers":true,"special":true,"minNumber":5,"minSpecial":4}"#);
            let generated = reply["value"]["text"].as_str().unwrap();
            assert_eq!(generated.chars().count(), 20);
            assert!(generated.chars().filter(char::is_ascii_digit).count() >= 5, "{generated}");
            assert!(generated.chars().filter(|c| "!@#$%^&*".contains(*c)).count() >= 4, "{generated}");
        }
    }

    #[test]
    fn minimums_are_ignored_for_disabled_sets_and_rejected_when_they_exceed_the_length() {
        let reply = request(r#"{"op":"generate","mode":"password","length":12,"lowercase":true,"uppercase":false,"numbers":false,"special":false,"minNumber":9,"minSpecial":9}"#);
        assert!(reply["value"]["text"].as_str().unwrap().chars().all(|c| c.is_ascii_lowercase()));
        let reply = request(r#"{"op":"generate","mode":"password","length":8,"lowercase":true,"uppercase":true,"numbers":true,"special":true,"minNumber":9,"minSpecial":9}"#);
        assert_eq!(reply["ok"], false);
    }

    #[test]
    fn username_ops_dispatch_through_the_json_entry_point() {
        let reply = request(r#"{"op":"generateUsername","kind":"subaddress","email":"you@example.com"}"#);
        let text = reply["value"]["text"].as_str().unwrap();
        assert!(text.starts_with("you+") && text.ends_with("@example.com"), "{text}");
        let reply = request(r#"{"op":"generateUsername","kind":"word","capitalize":true,"includeNumber":true}"#);
        assert_eq!(reply["ok"], true);
        let reply = request(r#"{"op":"generateUsername","kind":"forwarded","service":"firefox"}"#);
        assert_eq!(reply["ok"], false);
    }

    #[test]
    fn ambiguous_characters_can_be_excluded() {
        let reply = request(r#"{"op":"generate","mode":"password","length":80,"avoidAmbiguous":true}"#);
        let generated = reply["value"]["text"].as_str().unwrap();
        assert_eq!(generated.chars().count(), 80);
        assert!(!generated.chars().any(|character| "0O1Il".contains(character)));
    }

    #[test]
    fn passphrase_options_produce_requested_word_count() {
        let reply = request(r#"{"op":"generate","mode":"passphrase","numWords":5,"separator":"-","capitalize":false,"includeNumber":false}"#);
        let generated = reply["value"]["text"].as_str().unwrap();
        assert_eq!(generated.split('-').count(), 5);
    }

    #[test]
    fn invalid_generator_options_and_unknown_operations_fail_explicitly() {
        for input in [
            r#"{"op":"generate","mode":"invalid"}"#,
            r#"{"op":"generate","mode":"password","length":0}"#,
            r#"{"op":"unrecognized"}"#,
        ] {
            let reply = request(input);
            assert_eq!(reply["ok"], false);
            assert!(reply["error"]["message"].as_str().is_some_and(|error| !error.is_empty()));
        }
    }

    /// End-to-end against a disposable server: `BW_E2E_SERVER=http://127.0.0.1:18088 cargo test e2e -- --ignored`.
    /// Registers a fresh account; never point it at a real account's server.
    #[test]
    #[ignore]
    fn e2e_items_round_trip_through_a_real_server() {
        let Ok(server) = std::env::var("BW_E2E_SERVER") else { return };
        let root = std::env::temp_dir().join(format!("bw-e2e-{}", uuid::Uuid::new_v4()));
        unsafe {
            std::env::set_var("BW_TEST_DATA_DIR", &root);
            std::env::set_var("BW_TEST_NAMESPACE", uuid::Uuid::new_v4().to_string());
        }
        let email = format!("e2e-{}@example.test", uuid::Uuid::new_v4());
        let password = format!("e2e-{}", uuid::Uuid::new_v4());
        register(&server, &email, &password);

        let ok = |reply: Value| -> Value {
            assert_eq!(reply["ok"], true, "{reply}");
            reply["value"].clone()
        };
        let op = |value: Value| ok(request(&value.to_string()));
        let find = |snapshot: &Value, id: &str| snapshot["items"].as_array().unwrap().iter()
            .find(|item| item["id"] == id).cloned();

        op(json!({"op":"login","email":email,"password":password,"server":server}));
        let saved = op(json!({"op":"saveItem","item":{"type":1,"name":"Mail","folderId":null,
            "login":{"username":"me","password":"first","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://mail.example","match":null}]},
            "fields":[{"name":"PIN","value":"1234","type":1}]}}));
        let id = saved["id"].as_str().unwrap().to_owned();
        assert_eq!(find(&saved["snapshot"], &id).unwrap()["hasTotp"], true);
        // Advanced search reads these; secrets are not among them.
        let searchable = find(&saved["snapshot"], &id).unwrap()["searchFields"].clone();
        assert_eq!(searchable["login.username"], json!(["me"]));
        assert_eq!(searchable["login.uris"], json!(["https://mail.example"]));
        assert!(!searchable.to_string().contains("1234") && !searchable.to_string().contains("first"), "hidden values and passwords are not searchable");

        let mut detail = op(json!({"op":"item","id":id}));
        assert_eq!(detail["item"]["login"]["password"], "first");
        assert_eq!(detail["item"]["fields"][0]["value"], "1234");
        assert_eq!(op(json!({"op":"totp","id":id}))["code"].as_str().unwrap().len(), 6);

        detail["item"]["login"]["password"] = json!("second");
        detail["item"]["name"] = json!("Mail (edited)");
        let edited = op(json!({"op":"saveItem","item":detail["item"]}));
        assert_eq!(find(&edited["snapshot"], &id).unwrap()["name"], "Mail (edited)");
        let detail = op(json!({"op":"item","id":id}));
        assert_eq!(detail["item"]["login"]["password"], "second");
        assert_eq!(detail["passwordHistory"][0]["password"], "first");

        // Clone: the same fields without the id create a second item and leave the source alone.
        let mut clone = detail["item"].clone();
        clone["id"] = Value::Null;
        clone["name"] = json!("Mail (edited) - Clone");
        let cloned = op(json!({"op":"saveItem","item":clone}));
        let clone_id = cloned["id"].as_str().unwrap().to_owned();
        assert_ne!(clone_id, id);
        let copy = op(json!({"op":"item","id":clone_id}));
        assert_eq!(copy["item"]["login"]["password"], "second");
        assert_eq!(copy["item"]["fields"][0]["value"], "1234");
        assert_eq!(copy["passwordHistory"].as_array().unwrap().len(), 0, "history is not cloned");
        assert_eq!(op(json!({"op":"item","id":id}))["item"]["name"], "Mail (edited)", "source unchanged");
        op(json!({"op":"deleteItem","id":clone_id,"permanent":false}));
        let removed = op(json!({"op":"deleteItem","id":clone_id,"permanent":true}));
        assert!(find(&removed["snapshot"], &clone_id).is_none());

        let archived = op(json!({"op":"archiveItem","id":id,"archived":true}));
        assert_eq!(find(&archived["snapshot"], &id).unwrap()["archived"], true);
        let synced = op(json!({"op":"sync"}));
        assert_eq!(find(&synced, &id).unwrap()["archived"], true, "server keeps the archive");
        let unarchived = op(json!({"op":"archiveItem","id":id,"archived":false}));
        assert_eq!(find(&unarchived["snapshot"], &id).unwrap()["archived"], false);

        // Attachments: upload (larger than the 1 MB request cap), download, survive an edit and a
        // sync, then delete. Contents go by file path and never through the JSON reply.
        let scratch = root.join("attachments");
        std::fs::create_dir_all(&scratch).unwrap();
        let source = scratch.join("report.bin");
        let contents: Vec<u8> = (0..2_500_000u32).map(|n| (n.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(&source, &contents).unwrap();
        let uploaded = op(json!({"op":"attachmentUpload","id":id,"path":source}));
        assert!(find(&uploaded["snapshot"], &id).is_some());
        let detail = op(json!({"op":"item","id":id}));
        let attachments = detail["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1, "{detail}");
        assert_eq!(attachments[0]["fileName"], "report.bin");
        let attachment_id = attachments[0]["id"].as_str().unwrap().to_owned();
        assert!(!attachment_id.is_empty());
        let saved_copy = scratch.join("downloaded.bin");
        op(json!({"op":"attachmentDownload","id":id,"attachmentId":attachment_id,"path":saved_copy}));
        assert!(std::fs::read(&saved_copy).unwrap() == contents, "downloaded bytes differ");
        // A second, tiny attachment; a stale editor save must not drop either.
        let note = scratch.join("note.txt");
        std::fs::write(&note, b"hello").unwrap();
        op(json!({"op":"attachmentUpload","id":id,"path":note}));
        let mut detail = op(json!({"op":"item","id":id}));
        assert_eq!(detail["attachments"].as_array().unwrap().len(), 2);
        detail["item"]["notes"] = json!("edited after attaching");
        op(json!({"op":"saveItem","item":detail["item"]}));
        let synced = op(json!({"op":"sync"}));
        assert!(find(&synced, &id).is_some());
        let detail = op(json!({"op":"item","id":id}));
        assert_eq!(detail["attachments"].as_array().unwrap().len(), 2, "attachments survive edit and sync");
        assert_eq!(detail["item"]["notes"], "edited after attaching");
        let again = scratch.join("again.bin");
        op(json!({"op":"attachmentDownload","id":id,"attachmentId":attachment_id,"path":again}));
        assert!(std::fs::read(&again).unwrap() == contents, "bytes differ after sync");
        // Limits and bad input are refused before anything is sent.
        let huge = scratch.join("huge.bin");
        std::fs::File::create(&huge).unwrap().set_len(500 * 1024 * 1024 + 1).unwrap();
        let reply = request(&json!({"op":"attachmentUpload","id":id,"path":huge}).to_string());
        assert_eq!(reply["error"]["code"], "tooLarge", "{reply}");
        let reply = request(&json!({"op":"attachmentUpload","id":id,"path":"relative.txt"}).to_string());
        assert_eq!(reply["ok"], false);
        let reply = request(&json!({"op":"attachmentDownload","id":id,"attachmentId":"nope","path":again}).to_string());
        assert_eq!(reply["error"]["code"], "notFound", "{reply}");
        assert_eq!(op(json!({"op":"item","id":id}))["attachments"].as_array().unwrap().len(), 2);
        op(json!({"op":"attachmentDelete","id":id,"attachmentId":attachment_id}));
        let detail = op(json!({"op":"item","id":id}));
        let remaining = detail["attachments"].as_array().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["fileName"], "note.txt");
        let synced = op(json!({"op":"sync"}));
        assert!(find(&synced, &id).is_some());
        assert_eq!(op(json!({"op":"item","id":id}))["attachments"].as_array().unwrap().len(), 1, "server deleted it");
        op(json!({"op":"attachmentDelete","id":id,"attachmentId":remaining[0]["id"]}));
        assert_eq!(op(json!({"op":"item","id":id}))["attachments"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&scratch);

        let folders = op(json!({"op":"saveFolder","id":null,"name":"Work"}));
        let folder = folders["snapshot"]["folders"][0]["id"].as_str().unwrap().to_owned();
        let moved = op(json!({"op":"organize","id":id,"favorite":true,"folderId":folder}));
        let item = find(&moved["snapshot"], &id).unwrap();
        assert_eq!((item["favorite"].clone(), item["folderId"].clone()), (json!(true), json!(folder)));
        op(json!({"op":"saveFolder","id":folder,"name":"Work (renamed)"}));

        let card = op(json!({"op":"saveItem","item":{"type":3,"name":"Visa","folderId":null,
            "card":{"cardholderName":"E2E","expMonth":"1","expYear":"2031","code":"123","brand":"Visa","number":"4111111111111111"}}}));
        let card_id = card["id"].as_str().unwrap().to_owned();
        assert_eq!(find(&card["snapshot"], &card_id).unwrap()["subtitle"], "Visa *1111");

        // The other structured types can be created and read back. Older Bitwarden-compatible
        // servers predate them and answer "Invalid type" (saveFailed); the request is still built
        // and encrypted by the SDK, so that outcome is reported and skipped. Bitwarden's own
        // servers accept them.
        for (item, expected) in [
            (json!({"type":6,"name":"Checking","folderId":null,"bankAccount":{"bankName":"Bank","accountNumber":"12345678","iban":"DE0012"}}), "Bank *5678"),
            (json!({"type":7,"name":"Licence","folderId":null,"driversLicense":{"firstName":"Alex","lastName":"Example","licenseNumber":"D1"}}), "Alex Example"),
            (json!({"type":8,"name":"Passport","folderId":null,"passport":{"givenName":"Alex","surname":"Example","passportNumber":"P1"}}), "Alex Example"),
        ] {
            let reply = request(&json!({"op":"saveItem","item":item}).to_string());
            if reply["ok"] == false && reply["error"]["code"] == "saveFailed" {
                eprintln!("e2e: server rejected item type {} (not supported by this server)", item["type"]);
                continue;
            }
            let created = ok(reply);
            let created_id = created["id"].as_str().unwrap().to_owned();
            assert_eq!(find(&created["snapshot"], &created_id).unwrap()["subtitle"], expected);
            let detail = op(json!({"op":"item","id":created_id}));
            assert_eq!(detail["item"]["type"], item["type"]);
            op(json!({"op":"deleteItem","id":created_id,"permanent":false}));
            op(json!({"op":"deleteItem","id":created_id,"permanent":true}));
        }

        let trashed = op(json!({"op":"deleteItem","id":card_id,"permanent":false}));
        assert_eq!(find(&trashed["snapshot"], &card_id).unwrap()["deleted"], true);
        let restored = op(json!({"op":"restoreItem","id":card_id}));
        assert_eq!(find(&restored["snapshot"], &card_id).unwrap()["deleted"], false);
        op(json!({"op":"deleteItem","id":card_id,"permanent":false}));
        let gone = op(json!({"op":"deleteItem","id":card_id,"permanent":true}));
        assert!(find(&gone["snapshot"], &card_id).is_none());
        let emptied = op(json!({"op":"deleteFolder","id":folder}));
        assert_eq!(find(&emptied["snapshot"], &id).unwrap()["folderId"], Value::Null);

        // The server agrees with the local cache, and the cache survives a lock.
        let synced = op(json!({"op":"sync"}));
        let item = find(&synced, &id).unwrap();
        assert_eq!((item["name"].clone(), item["favorite"].clone(), item["folderId"].clone()),
            (json!("Mail (edited)"), json!(true), Value::Null));
        assert!(find(&synced, &card_id).is_none());
        op(json!({"op":"lock"}));
        let reply = request(&json!({"op":"unlock","password":"wrong"}).to_string());
        assert_eq!(reply["ok"], false);
        let unlocked = op(json!({"op":"unlock","password":password}));
        assert_eq!(unlocked["items"].as_array().unwrap().len(), 1);

        // PIN unlock: wrong PINs are counted, the right one unlocks, five wrong ones disable it.
        op(json!({"op":"enrollPin","pin":"4827"}));
        assert_eq!(op(json!({"op":"status"}))["pinEnabled"], true);
        op(json!({"op":"lock"}));
        let wrong = request(&json!({"op":"unlockPin","pin":"0000"}).to_string());
        assert_eq!(wrong["error"]["code"], "invalidPin", "{wrong}");
        assert_eq!(op(json!({"op":"unlockPin","pin":"4827"}))["items"].as_array().unwrap().len(), 1);
        op(json!({"op":"lock"}));
        for attempt in 1..=5 {
            let reply = request(&json!({"op":"unlockPin","pin":"1111"}).to_string());
            let expected = if attempt < 5 { "invalidPin" } else { "pinUnavailable" };
            assert_eq!(reply["error"]["code"], expected, "attempt {attempt}: {reply}");
        }
        assert_eq!(op(json!({"op":"status"}))["pinEnabled"], false);
        let reply = request(&json!({"op":"unlockPin","pin":"4827"}).to_string());
        assert_eq!(reply["error"]["code"], "pinUnavailable");
        op(json!({"op":"unlock","password":password}));

        // Export and import. The vault now holds one login ("Mail (edited)"); add one of each of
        // the other kinds a file can carry, in a folder.
        let files = root.join("transfer");
        std::fs::create_dir_all(&files).unwrap();
        let export_folder = op(json!({"op":"saveFolder","id":null,"name":"Export Work"}))["snapshot"]["folders"][0]["id"].as_str().unwrap().to_owned();
        let mut originals = vec![id.clone()];
        for item in [
            json!({"type":1,"name":"Bank Login","folderId":export_folder,"favorite":true,"reprompt":true,"notes":"line one\nline two",
                "login":{"username":"bank.user","password":"first-pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://bank.example","match":3},{"uri":"https://bank2.example","match":null}]},
                "fields":[{"name":"PIN","value":"9876","type":1},{"name":"Region","value":"EU","type":0}]}),
            json!({"type":2,"name":"Export Note","folderId":null,"notes":"secret words"}),
            json!({"type":3,"name":"Export Visa","folderId":null,"card":{"cardholderName":"E2E","expMonth":"4","expYear":"2031","code":"321","brand":"Visa","number":"4111111111111111"}}),
            json!({"type":4,"name":"Export Person","folderId":export_folder,"identity":{"firstName":"Alex","lastName":"Example","email":"alex@example.com"}}),
        ] { originals.push(op(json!({"op":"saveItem","item":item}))["id"].as_str().unwrap().to_owned()); }
        // Give the bank login a password history entry.
        let mut bank = op(json!({"op":"item","id":originals[1]}));
        bank["item"]["login"]["password"] = json!("second-pw");
        op(json!({"op":"saveItem","item":bank["item"]}));
        let names = |snapshot: &Value| -> Vec<String> {
            let mut names: Vec<String> = snapshot["items"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap().to_owned()).collect();
            names.sort();
            names
        };
        let expected_all = vec!["Bank Login", "Export Note", "Export Person", "Export Visa", "Mail (edited)"];
        assert_eq!(names(&op(json!({"op":"sync"}))), expected_all);

        // Re-authentication: a wrong master password writes nothing.
        let target = |name: &str| files.join(name).to_string_lossy().into_owned();
        let export = |format: &str, name: &str, file_password: Option<&str>, master: &str| request(&json!({
            "op":"exportVault","format":format,"filePassword":file_password,"masterPassword":master,"path":target(name)}).to_string());
        let refused = export("json", "refused.json", None, "wrong-password");
        assert_eq!(refused["error"]["code"], "invalidPassword", "{refused}");
        assert!(!files.join("refused.json").exists(), "nothing is written before re-authentication");
        assert_eq!(op(json!({"op":"exportVault","format":"json","masterPassword":password}))["verified"], true);
        let wrong_verify = request(&json!({"op":"exportVault","format":"json","masterPassword":"nope"}).to_string());
        assert_eq!(wrong_verify["error"]["code"], "invalidPassword");
        let missing_folder = request(&json!({"op":"exportVault","format":"json","masterPassword":password,"path":"/nonexistent-dir-e2e/x.json"}).to_string());
        assert_eq!(missing_folder["ok"], false);
        let no_password = export("jsonEncryptedPassword", "nopw.json", None, &password);
        assert_eq!(no_password["ok"], false);
        assert!(!files.join("nopw.json").exists());

        let json_report = ok(export("json", "vault.json", None, &password));
        assert_eq!((json_report["items"].clone(), json_report["folders"].clone(), json_report["omitted"].clone()), (json!(5), json!(1), json!(0)));
        let csv_report = ok(export("csv", "vault.csv", None, &password));
        assert_eq!((csv_report["items"].clone(), csv_report["omitted"].clone()), (json!(3), json!(2)), "CSV holds only logins and notes");
        let protected_report = ok(export("jsonEncryptedPassword", "protected.json", Some("file-password-e2e"), &password));
        assert_eq!(protected_report["items"], 5);
        let account_report = ok(export("jsonEncryptedAccount", "account.json", None, &password));
        assert_eq!(account_report["items"], 5);
        let plain = std::fs::read_to_string(files.join("vault.json")).unwrap();
        assert!(plain.contains("Bank Login") && plain.contains("second-pw") && plain.contains("first-pw"), "plain JSON holds the data and password history");
        for encrypted in ["protected.json", "account.json"] {
            let text = std::fs::read_to_string(files.join(encrypted)).unwrap();
            assert!(!text.contains("Bank Login") && !text.contains("second-pw") && !text.contains("4111111111111111"), "{encrypted} is encrypted");
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["encrypted"], true);
        }
        let account_file: Value = serde_json::from_str(&std::fs::read_to_string(files.join("account.json")).unwrap()).unwrap();
        assert!(account_file.get("passwordProtected").is_none() && account_file["encKeyValidation_DO_NOT_EDIT"].is_string());
        let protected_file: Value = serde_json::from_str(&std::fs::read_to_string(files.join("protected.json")).unwrap()).unwrap();
        assert_eq!(protected_file["passwordProtected"], true);
        // The trash and the archive: trashed items are not exported.
        let trash_me = op(json!({"op":"saveItem","item":{"type":2,"name":"Export Trashed","folderId":null,"notes":"x"}}))["id"].as_str().unwrap().to_owned();
        op(json!({"op":"deleteItem","id":trash_me,"permanent":false}));
        assert_eq!(ok(export("json", "with-trash.json", None, &password))["items"], 5, "trashed items are left out");
        op(json!({"op":"deleteItem","id":trash_me,"permanent":true}));

        // Import: nothing happens until the counts are confirmed; a lock discards what was read.
        let prepare = |name: &str, file_password: Option<&str>| request(&json!({"op":"importPrepare","path":target(name),"filePassword":file_password}).to_string());
        let commit_without_prepare = request(&json!({"op":"importCommit"}).to_string());
        assert_eq!(commit_without_prepare["error"]["code"], "notFound");
        let preview = ok(prepare("vault.json", None));
        assert_eq!((preview["items"].clone(), preview["folders"].clone(), preview["skipped"].clone()), (json!(5), json!(1), json!(0)));
        assert_eq!(op(json!({"op":"sync"}))["items"].as_array().unwrap().len(), 5, "preparing imports nothing");
        op(json!({"op":"lock"}));
        op(json!({"op":"unlock","password":password}));
        assert_eq!(request(&json!({"op":"importCommit"}).to_string())["error"]["code"], "notFound", "locking discards the parsed file");
        assert_eq!(prepare("protected.json", None)["error"]["code"], "passwordRequired");
        assert_eq!(prepare("protected.json", Some("not the password"))["error"]["code"], "invalidFilePassword");
        assert_eq!(op(json!({"op":"importDiscard"})), json!({}));
        assert_eq!(request(&json!({"op":"importCommit"}).to_string())["error"]["code"], "notFound");
        std::fs::write(files.join("junk.json"), b"{\"hello\":1}").unwrap();
        assert_eq!(prepare("junk.json", None)["error"]["code"], "unrecognizedFile");
        assert_eq!(prepare("does-not-exist.json", None)["ok"], false);

        // An account-restricted file re-imports into the same account (the vault doubles).
        assert_eq!(ok(prepare("account.json", None))["items"], 5);
        let doubled = op(json!({"op":"importCommit"}));
        assert_eq!((doubled["items"].clone(), doubled["folders"].clone()), (json!(5), json!(1)));
        let after = &doubled["snapshot"];
        assert_eq!(after["items"].as_array().unwrap().len(), 10, "{after}");
        let mut doubled_names = expected_all.clone();
        doubled_names.extend(expected_all.iter());
        doubled_names.sort();
        assert_eq!(names(after), doubled_names);
        assert_eq!(after["folders"].as_array().unwrap().iter().filter(|f| f["name"] == "Export Work").count(), 2);
        // Remove the copies again, and the extra folder.
        let copies: Vec<String> = after["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_owned()).filter(|i| !originals.contains(i)).collect();
        assert_eq!(copies.len(), 5);
        for copy in &copies {
            op(json!({"op":"deleteItem","id":copy,"permanent":false}));
            op(json!({"op":"deleteItem","id":copy,"permanent":true}));
        }
        let folder_ids: Vec<String> = op(json!({"op":"sync"}))["folders"].as_array().unwrap().iter().filter(|f| f["name"] == "Export Work").map(|f| f["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(folder_ids.len(), 2);
        for extra in folder_ids.iter().filter(|f| **f != export_folder) {op(json!({"op":"deleteFolder","id":extra}));}
        assert_eq!(names(&op(json!({"op":"sync"}))), expected_all);

        // Everything else goes into a fresh throwaway account: the account-restricted file is
        // refused there, the others import with their contents.
        op(json!({"op":"logout"}));
        let other_email = format!("e2e-{}@example.test", uuid::Uuid::new_v4());
        let other_password = format!("e2e-{}", uuid::Uuid::new_v4());
        register(&server, &other_email, &other_password);
        let first = op(json!({"op":"login","email":other_email,"password":other_password,"server":server}));
        assert_eq!(first["items"].as_array().unwrap().len(), 0);
        assert_eq!(prepare("account.json", None)["error"]["code"], "wrongAccount");
        assert_eq!(op(json!({"op":"sync"}))["items"].as_array().unwrap().len(), 0, "a refused file imports nothing");

        assert_eq!(ok(prepare("vault.json", None))["items"], 5);
        let imported = op(json!({"op":"importCommit"}));
        assert_eq!((imported["items"].clone(), imported["folders"].clone()), (json!(5), json!(1)));
        assert_eq!(names(&imported["snapshot"]), expected_all);
        let snapshot = &imported["snapshot"];
        let folder_of = |name: &str| snapshot["items"].as_array().unwrap().iter().find(|i| i["name"] == name).unwrap()["folderId"].clone();
        let work = snapshot["folders"][0]["id"].clone();
        assert_eq!(snapshot["folders"][0]["name"], "Export Work");
        assert_eq!((folder_of("Bank Login"), folder_of("Export Person"), folder_of("Export Note")), (work.clone(), work, Value::Null));
        let bank_id = snapshot["items"].as_array().unwrap().iter().find(|i| i["name"] == "Bank Login").unwrap()["id"].as_str().unwrap().to_owned();
        assert_eq!(snapshot["items"].as_array().unwrap().iter().find(|i| i["name"] == "Bank Login").unwrap()["favorite"], true);
        let bank = op(json!({"op":"item","id":bank_id}));
        assert_eq!(bank["item"]["login"]["password"], "second-pw");
        assert_eq!(bank["item"]["login"]["username"], "bank.user");
        assert_eq!(bank["item"]["login"]["totp"], "JBSWY3DPEHPK3PXP");
        assert_eq!(bank["item"]["login"]["uris"].as_array().unwrap().len(), 2);
        assert_eq!(bank["item"]["notes"], "line one\nline two");
        assert_eq!(bank["item"]["reprompt"], true, "the master password re-prompt flag survives");
        assert_eq!(bank["item"]["fields"].as_array().unwrap().len(), 2);
        assert_eq!(bank["passwordHistory"][0]["password"], "first-pw", "password history survives");
        let visa = snapshot["items"].as_array().unwrap().iter().find(|i| i["name"] == "Export Visa").unwrap()["id"].as_str().unwrap().to_owned();
        let visa = op(json!({"op":"item","id":visa}));
        assert_eq!((visa["item"]["card"]["number"].clone(), visa["item"]["card"]["brand"].clone()), (json!("4111111111111111"), json!("Visa")));

        // CSV: logins and notes only, folder names kept. Password-protected JSON: everything again.
        assert_eq!(ok(prepare("vault.csv", None))["items"], 3);
        let csv = op(json!({"op":"importCommit"}));
        assert_eq!(csv["items"], 3);
        let mut with_csv: Vec<String> = expected_all.iter().map(|n| n.to_string()).collect();
        with_csv.extend(["Bank Login".to_string(), "Export Note".to_string(), "Mail (edited)".to_string()]);
        with_csv.sort();
        assert_eq!(names(&csv["snapshot"]), with_csv);
        let csv_bank = csv["snapshot"]["items"].as_array().unwrap().iter().filter(|i| i["name"] == "Bank Login").map(|i| i["id"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
        for copy in &csv_bank {
            let detail = op(json!({"op":"item","id":copy}));
            assert_eq!((detail["item"]["login"]["password"].clone(), detail["item"]["fields"].as_array().unwrap().len()), (json!("second-pw"), 2));
        }
        let protected = ok(prepare("protected.json", Some("file-password-e2e")));
        assert_eq!(protected["items"], 5);
        let last = op(json!({"op":"importCommit"}));
        assert_eq!(last["snapshot"]["items"].as_array().unwrap().len(), 13);
        let copy_ids: Vec<&Value> = last["snapshot"]["items"].as_array().unwrap().iter().filter(|i| i["name"] == "Bank Login").map(|i| &i["id"]).collect();
        assert_eq!(copy_ids.len(), 3);
        let _ = std::fs::remove_dir_all(&files);

        op(json!({"op":"logout"}));
        let _ = std::fs::remove_dir_all(root);
    }

    fn register(server: &str, email: &str, password: &str) {
        let kdf = bitwarden_crypto::Kdf::PBKDF2 { iterations: std::num::NonZeroU32::new(600_000).unwrap() };
        let keys = bitwarden_core::Client::new(None).auth()
            .make_register_keys(email.into(), password.into(), kdf).unwrap();
        let body = json!({
            "email": email, "name": "E2E", "masterPasswordHash": keys.master_password_hash.to_string(),
            "masterPasswordHint": null, "key": keys.encrypted_user_key.to_string(),
            "kdf": 0, "kdfIterations": 600_000,
            "keys": {"publicKey": keys.keys.public.to_string(), "encryptedPrivateKey": keys.keys.private.to_string()},
        });
        let response = crate::RUNTIME.block_on(async {
            reqwest::Client::new().post(format!("{server}/identity/accounts/register")).json(&body).send().await
        }).unwrap();
        assert!(response.status().is_success(), "register: {}", response.status());
    }

    /// Seeds a disposable account with one item of each kind for UI tests and screenshots:
    /// `BW_E2E_SERVER=… BW_SEED_EMAIL=… BW_SEED_PASSWORD=… cargo test seed -- --ignored`.
    #[test]
    #[ignore]
    fn seed_demo_vault() {
        let (Ok(server), Ok(email), Ok(password)) = (std::env::var("BW_E2E_SERVER"),
            std::env::var("BW_SEED_EMAIL"), std::env::var("BW_SEED_PASSWORD")) else { return };
        let root = std::env::temp_dir().join(format!("bw-seed-{}", uuid::Uuid::new_v4()));
        unsafe {
            std::env::set_var("BW_TEST_DATA_DIR", &root);
            std::env::set_var("BW_TEST_NAMESPACE", uuid::Uuid::new_v4().to_string());
        }
        register(&server, &email, &password);
        let op = |value: Value| {
            let reply = request(&value.to_string());
            assert_eq!(reply["ok"], true, "{reply}");
            reply["value"].clone()
        };
        op(json!({"op":"login","email":email,"password":password,"server":server}));
        let work = op(json!({"op":"saveFolder","id":null,"name":"Work"}))["snapshot"]["folders"][0]["id"].clone();
        op(json!({"op":"saveFolder","id":null,"name":"Personal"}));
        for item in [
            json!({"type":1,"name":"Seed Login","folderId":work,"favorite":true,
                "login":{"username":"seed.user@example.com","password":"Seed-Password-1","totp":"JBSWY3DPEHPK3PXP",
                    "uris":[{"uri":"https://github.com","match":null},{"uri":"https://gist.github.com","match":null}]},
                "fields":[{"name":"Recovery code","value":"alpha-bravo","type":1},{"name":"Region","value":"EU","type":0},
                    {"name":"MFA enforced","value":"true","type":2},{"name":"Account","value":"","type":3,"linkedId":100}],
                "notes":"Primary development account."}),
            json!({"type":1,"name":"Mail","folderId":null,
                "login":{"username":"me@example.com","password":"correct horse battery staple","uris":[{"uri":"https://mail.example.com","match":null}]}}),
            json!({"type":1,"name":"Router admin","folderId":null,"reprompt":true,
                "login":{"username":"admin","password":"hunter2","uris":[{"uri":"http://192.168.1.1","match":null}]}}),
            json!({"type":3,"name":"Travel Visa","folderId":null,
                "card":{"cardholderName":"Alex Example","expMonth":"4","expYear":"2031","code":"321","brand":"Visa","number":"4111111111111111"}}),
            json!({"type":4,"name":"Alex Example","folderId":null,
                "identity":{"title":"Mx","firstName":"Alex","lastName":"Example","email":"alex@example.com","phone":"+1 555 0100",
                    "address1":"1 Infinite Loop","city":"Cupertino","state":"CA","postalCode":"95014","country":"US"}}),
            json!({"type":2,"name":"Wi-Fi","folderId":null,"notes":"Network: Home-5G\nPassword: sunflower-meadow-42"}),
        ] { op(json!({"op":"saveItem","item":item})); }
        let _ = std::fs::remove_dir_all(root);
    }
}
