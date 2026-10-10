//! Item wire format shared with Swift, and the mapping to and from SDK views.
//!
//! Edits never rebuild a cipher from this DTO. They start from the decrypted `CipherView` and
//! patch only the fields the editor exposes, so passkeys, password history, attachments, the
//! per-item key and anything else the UI does not show survive a save unchanged.

use bitwarden_vault::{
    BankAccountView, CardView, CipherRepromptType, CipherType, CipherView, DriversLicenseView,
    FieldType, FieldView, FolderId, IdentityView, LoginUriView, LoginView,
    PassportView, SshKeyView, UriMatchType,
};
use serde::{Deserialize, Serialize};

use crate::account::{Error, Result};

/// The editable part of an item. `id` is `None` when creating.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ItemData {
    pub id: Option<String>,
    pub r#type: u8,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: bool,
    pub folder_id: Option<String>,
    pub login: Option<LoginData>,
    pub card: Option<CardView>,
    pub identity: Option<IdentityView>,
    pub ssh_key: Option<SshKeyView>,
    pub bank_account: Option<BankAccountView>,
    pub drivers_license: Option<DriversLicenseView>,
    pub passport: Option<PassportView>,
    #[serde(default)]
    pub fields: Vec<FieldData>,
    /// Set by the editor to drop the login's passkeys on save. Edits keep passkeys otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove_passkeys: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub uris: Vec<UriData>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UriData {
    pub uri: String,
    pub r#match: Option<UriMatchType>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FieldData {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    pub r#type: FieldType,
    /// The SDK's `LinkedIdType` is not exported; it serializes as its numeric id.
    pub linked_id: Option<u32>,
}

/// Everything the detail pane shows. Read-only extras sit beside the editable `item`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub item: ItemData,
    pub organization_id: Option<String>,
    pub editable: bool,
    pub view_password: bool,
    pub passkeys: Vec<Passkey>,
    pub password_history: Vec<HistoryEntry>,
    pub attachments: Vec<Attachment>,
    pub creation_date: String,
    pub revision_date: String,
    pub deleted_date: Option<String>,
    pub archived_date: Option<String>,
    pub password_revision_date: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub rp_id: String,
    pub user_name: Option<String>,
    pub creation_date: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub password: String,
    pub last_used_date: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: String,
    pub file_name: String,
    pub size: Option<String>,
}

fn text(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn optional(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

pub fn cipher_type(raw: u8) -> Result<CipherType> {
    Ok(match raw {
        1 => CipherType::Login,
        2 => CipherType::SecureNote,
        3 => CipherType::Card,
        4 => CipherType::Identity,
        5 => CipherType::SshKey,
        6 => CipherType::BankAccount,
        7 => CipherType::DriversLicense,
        8 => CipherType::Passport,
        _ => return Err(Error::new("invalidInput", "Unsupported item type.")),
    })
}

pub fn detail(view: CipherView) -> Detail {
    let login = view.login.as_ref();
    let item = ItemData {
        id: view.id.map(|id| id.to_string()),
        r#type: view.r#type as u8,
        name: view.name.clone(),
        notes: text(&view.notes),
        favorite: view.favorite,
        reprompt: view.reprompt != CipherRepromptType::None,
        folder_id: view.folder_id.map(|id| id.to_string()),
        login: login.map(|login| LoginData {
            username: text(&login.username),
            password: text(&login.password),
            totp: text(&login.totp),
            uris: login.uris.iter().flatten()
                .filter_map(|uri| uri.uri.clone().map(|value| UriData { uri: value, r#match: uri.r#match }))
                .collect(),
        }),
        card: view.card.clone(),
        identity: view.identity.clone(),
        ssh_key: view.ssh_key.clone(),
        bank_account: view.bank_account.clone(),
        drivers_license: view.drivers_license.clone(),
        passport: view.passport.clone(),
        remove_passkeys: false,
        fields: view.fields.iter().flatten().map(|field| FieldData {
            name: text(&field.name),
            value: text(&field.value),
            r#type: field.r#type,
            linked_id: field.linked_id.and_then(|id| serde_json::to_value(id).ok()?.as_u64()?.try_into().ok()),
        }).collect(),
    };
    Detail {
        item,
        organization_id: view.organization_id.map(|id| id.to_string()),
        editable: view.edit && !view.partial,
        view_password: view.view_password,
        passkeys: login.and_then(|login| login.fido2_credentials.as_ref()).into_iter().flatten()
            .map(|credential| Passkey {
                rp_id: credential.rp_id.clone(),
                user_name: credential.user_name.clone(),
                creation_date: credential.creation_date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
            }).collect(),
        password_history: view.password_history.iter().flatten().map(|entry| HistoryEntry {
            password: entry.password.clone(),
            last_used_date: entry.last_used_date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        }).collect(),
        attachments: view.attachments.iter().flatten().map(|attachment| Attachment {
            id: attachment.id.clone().unwrap_or_default(),
            file_name: attachment.file_name.clone().unwrap_or_else(|| "Attachment".into()),
            size: attachment.size_name.clone(),
        }).collect(),
        creation_date: view.creation_date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        revision_date: view.revision_date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        deleted_date: view.deleted_date.map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)),
        archived_date: view.archived_date.map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)),
        password_revision_date: login.and_then(|login| login.password_revision_date).map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)),
    }
}

pub fn folder_id(value: &Option<String>) -> Result<Option<FolderId>> {
    value.as_deref().filter(|id| !id.is_empty())
        .map(|id| id.parse::<FolderId>().map_err(|_| Error::new("invalidInput", "Invalid folder.")))
        .transpose()
}

fn fields(input: &[FieldData]) -> Result<Vec<FieldView>> {
    input.iter().map(|field| Ok(FieldView {
        name: optional(field.name.clone()),
        value: optional(field.value.clone()),
        r#type: field.r#type,
        linked_id: field.linked_id.map(|id| serde_json::from_value(serde_json::json!(id))).transpose()
            .map_err(|_| Error::new("invalidInput", "Invalid linked field."))?,
    })).collect()
}

fn patch_login(login: &mut LoginView, input: &LoginData) {
    login.username = optional(input.username.clone());
    login.password = optional(input.password.clone());
    login.totp = optional(input.totp.trim().to_owned());
    let uris: Vec<LoginUriView> = input.uris.iter()
        .filter(|uri| !uri.uri.trim().is_empty())
        .map(|uri| LoginUriView { uri: Some(uri.uri.trim().to_owned()), r#match: uri.r#match, uri_checksum: None })
        .collect();
    login.uris = if uris.is_empty() { None } else { Some(uris) };
}

pub fn empty_login() -> LoginView {
    LoginView {
        username: None, password: None, password_revision_date: None, uris: None, totp: None,
        autofill_on_page_load: None, fido2_credentials: None,
    }
}

/// Applies the editor's fields onto a decrypted view. The item type cannot change.
pub fn patch(view: &mut CipherView, input: &ItemData) -> Result<()> {
    if input.name.trim().is_empty() {
        return Err(Error::new("invalidInput", "Item name is required."));
    }
    if cipher_type(input.r#type)? != view.r#type {
        return Err(Error::new("invalidInput", "An item's type cannot be changed."));
    }
    view.name = input.name.clone();
    view.notes = optional(input.notes.clone());
    view.favorite = input.favorite;
    view.reprompt = if input.reprompt { CipherRepromptType::Password } else { CipherRepromptType::None };
    view.folder_id = folder_id(&input.folder_id)?;
    view.fields = if input.fields.is_empty() { None } else { Some(fields(&input.fields)?) };
    match view.r#type {
        CipherType::Login => {
            let login = view.login.get_or_insert_with(empty_login);
            patch_login(login, input.login.as_ref().ok_or_else(|| Error::new("invalidInput", "Login details are missing."))?);
            if input.remove_passkeys { login.fido2_credentials = None; }
        }
        CipherType::Card => view.card = input.card.clone(),
        CipherType::Identity => view.identity = input.identity.clone(),
        CipherType::BankAccount => view.bank_account = input.bank_account.clone(),
        CipherType::DriversLicense => view.drivers_license = input.drivers_license.clone(),
        CipherType::Passport => view.passport = input.passport.clone(),
        // SSH keys are generated or imported as a validated triple; keep the stored key material.
        CipherType::SshKey | CipherType::SecureNote => {}
    }
    Ok(())
}

/// Builds the SDK's type payload for a new item.
pub fn new_type(input: &ItemData) -> Result<bitwarden_vault::CipherViewType> {
    use bitwarden_vault::{CipherViewType, SecureNoteType, SecureNoteView};
    Ok(match cipher_type(input.r#type)? {
        CipherType::Login => {
            let mut login = empty_login();
            patch_login(&mut login, input.login.as_ref().ok_or_else(|| Error::new("invalidInput", "Login details are missing."))?);
            CipherViewType::Login(login)
        }
        CipherType::SecureNote => CipherViewType::SecureNote(SecureNoteView { r#type: SecureNoteType::Generic }),
        CipherType::Card => CipherViewType::Card(input.card.clone().ok_or_else(|| Error::new("invalidInput", "Card details are missing."))?),
        CipherType::Identity => CipherViewType::Identity(input.identity.clone().ok_or_else(|| Error::new("invalidInput", "Identity details are missing."))?),
        CipherType::BankAccount => CipherViewType::BankAccount(input.bank_account.clone().ok_or_else(|| Error::new("invalidInput", "Bank account details are missing."))?),
        CipherType::DriversLicense => CipherViewType::DriversLicense(input.drivers_license.clone().ok_or_else(|| Error::new("invalidInput", "Driver's license details are missing."))?),
        CipherType::Passport => CipherViewType::Passport(input.passport.clone().ok_or_else(|| Error::new("invalidInput", "Passport details are missing."))?),
        CipherType::SshKey => return Err(Error::new("invalidInput", "SSH keys can only be created in the official client.")),
    })
}

pub fn new_fields(input: &ItemData) -> Result<Vec<FieldView>> {
    fields(&input.fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitwarden_vault::Fido2CredentialView;
    use chrono::Utc;

    fn fixture() -> CipherView {
        let mut view: CipherView = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(), "organizationId": null, "folderId": null, "collectionIds": [],
            "key": null, "name": "Mail", "notes": "old", "type": 1,
            "login": {"username": "me", "password": "old-pass", "passwordRevisionDate": null,
                "uris": [{"uri": "https://mail.example", "match": 3, "uriChecksum": null}],
                "totp": null, "autofillOnPageLoad": true, "fido2Credentials": null},
            "identity": null, "card": null, "secureNote": null, "sshKey": null,
            "bankAccount": null, "driversLicense": null, "passport": null,
            "favorite": false, "reprompt": 0, "organizationUseTotp": false, "edit": true,
            "permissions": null, "viewPassword": true, "localData": null, "attachments": null,
            "fields": [{"name": "linked", "value": null, "type": 3, "linkedId": 100}],
            "passwordHistory": [{"password": "older", "lastUsedDate": "2025-01-01T00:00:00Z"}],
            "creationDate": "2025-01-01T00:00:00Z", "deletedDate": null,
            "revisionDate": "2025-01-02T00:00:00Z", "archivedDate": null
        })).unwrap();
        view.login.as_mut().unwrap().fido2_credentials = Some(vec![Fido2CredentialView {
            credential_id: "c".into(), key_type: "public-key".into(), key_algorithm: "ECDSA".into(),
            key_curve: "P-256".into(), key_value: "k".into(), rp_id: "mail.example".into(),
            user_handle: None, user_name: Some("me".into()), counter: "0".into(), rp_name: None,
            user_display_name: None, discoverable: "true".into(), creation_date: Utc::now(),
        }]);
        view
    }

    #[test]
    fn edit_preserves_fields_the_editor_does_not_show() {
        let mut view = fixture();
        let mut input = detail(view.clone()).item;
        input.name = "Mail (work)".into();
        input.login.as_mut().unwrap().password = "new-pass".into();
        input.login.as_mut().unwrap().uris.push(UriData { uri: " https://second.example ".into(), r#match: None });
        patch(&mut view, &input).unwrap();

        let login = view.login.as_ref().unwrap();
        assert_eq!(view.name, "Mail (work)");
        assert_eq!(login.password.as_deref(), Some("new-pass"));
        assert_eq!(login.fido2_credentials.as_ref().unwrap().len(), 1, "passkey kept");
        assert_eq!(login.autofill_on_page_load, Some(true), "autofill flag kept");
        assert_eq!(view.password_history.as_ref().unwrap().len(), 1, "history kept");
        assert_eq!(login.uris.as_ref().unwrap()[0].r#match, Some(UriMatchType::Exact), "match rule kept");
        assert_eq!(login.uris.as_ref().unwrap()[1].uri.as_deref(), Some("https://second.example"));
        let linked = &view.fields.as_ref().unwrap()[0];
        assert_eq!(linked.r#type, FieldType::Linked);
        assert!(linked.linked_id.is_some(), "linked field target kept");
    }

    #[test]
    fn removing_a_passkey_drops_only_the_passkey() {
        let mut view = fixture();
        let mut input = detail(view.clone()).item;
        assert!(!input.remove_passkeys, "a plain detail never asks for removal");
        input.remove_passkeys = true;
        patch(&mut view, &input).unwrap();
        let login = view.login.as_ref().unwrap();
        assert!(login.fido2_credentials.is_none(), "passkey removed");
        assert_eq!(login.username.as_deref(), Some("me"));
        assert_eq!(login.autofill_on_page_load, Some(true));
        assert_eq!(view.password_history.as_ref().unwrap().len(), 1, "history kept");
        // The flag is not echoed back to the UI, so a reloaded draft never removes by accident.
        assert!(serde_json::to_value(detail(view).item).unwrap().get("removePasskeys").is_none());
    }

    #[test]
    fn a_clone_is_built_from_the_editable_fields_only() {
        // The clone's payload is the source's ItemData with its id dropped. It never carries the
        // passkey, history, attachments, key or dates, because the create path rebuilds from it.
        let view = fixture();
        let mut input = detail(view.clone()).item;
        input.id = None;
        input.name = format!("{} - Clone", input.name);
        input.remove_passkeys = true; // ignored by create
        let bitwarden_vault::CipherViewType::Login(login) = new_type(&input).unwrap() else { panic!("login expected") };
        assert!(login.fido2_credentials.is_none(), "no passkey in a clone");
        assert_eq!(login.password.as_deref(), Some("old-pass"));
        assert_eq!(login.uris.as_ref().unwrap()[0].r#match, Some(UriMatchType::Exact));
        assert_eq!(new_fields(&input).unwrap().len(), 1);
        assert!(input.id.is_none(), "saving takes the create path, so the source cannot be overwritten");
    }

    #[test]
    fn edit_rejects_type_changes_and_empty_names() {
        let mut view = fixture();
        let mut input = detail(view.clone()).item;
        input.r#type = 2;
        assert!(patch(&mut view, &input).is_err());
        let mut input = detail(view.clone()).item;
        input.name = "  ".into();
        assert!(patch(&mut view, &input).is_err());
    }

    #[test]
    fn swift_payloads_decode() {
        let input: ItemData = serde_json::from_str(r#"{"type":3,"name":"Visa","folderId":null,
            "card":{"cardholderName":"A","expMonth":"1","expYear":"2030","code":"123","brand":"Visa","number":"4111"},
            "fields":[{"name":"PIN","value":"1","type":1}]}"#).unwrap();
        assert!(matches!(new_type(&input).unwrap(), bitwarden_vault::CipherViewType::Card(_)));
        assert_eq!(new_fields(&input).unwrap()[0].r#type, FieldType::Hidden);
    }

    #[test]
    fn new_bank_license_and_passport_items_build() {
        use bitwarden_vault::CipherViewType as V;
        let bank: ItemData = serde_json::from_str(r#"{"type":6,"name":"B","bankAccount":{"bankName":"Bank","iban":"DE00"}}"#).unwrap();
        assert!(matches!(new_type(&bank).unwrap(), V::BankAccount(b) if b.iban.as_deref() == Some("DE00")));
        let license: ItemData = serde_json::from_str(r#"{"type":7,"name":"L","driversLicense":{"firstName":"A","licenseNumber":"1"}}"#).unwrap();
        assert!(matches!(new_type(&license).unwrap(), V::DriversLicense(_)));
        let passport: ItemData = serde_json::from_str(r#"{"type":8,"name":"P","passport":{"surname":"S","passportNumber":"9"}}"#).unwrap();
        assert!(matches!(new_type(&passport).unwrap(), V::Passport(_)));
        // Details are required, and SSH keys are still not creatable.
        let missing: ItemData = serde_json::from_str(r#"{"type":8,"name":"P"}"#).unwrap();
        assert!(new_type(&missing).is_err());
        let ssh: ItemData = serde_json::from_str(r#"{"type":5,"name":"K"}"#).unwrap();
        assert!(new_type(&ssh).is_err());
    }
}
