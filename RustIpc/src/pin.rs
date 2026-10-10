//! PIN unlock: the user key wrapped in the SDK's Argon2 password-protected envelope, kept in the
//! Keychain for this device only. Five wrong PINs delete it, after which the master password is
//! required, as in the official clients.

use bitwarden_core::{Client, key_management::crypto::InitUserCryptoMethod};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{account::{Error, Result}, api, store::Cache};

const MAX_ATTEMPTS: u8 = 5;
const STORE: i32 = 5;
const DELETE: i32 = 6;
const READ: i32 = 7;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    account_id: String,
    server: String,
    envelope: String,
    failures: u8,
}

fn read(hash: &str) -> Result<Option<Record>> {
    let bytes = Zeroizing::new(api::credential(READ, hash, &[])?);
    if bytes.is_empty() { return Ok(None) }
    serde_json::from_slice(&bytes).map(Some)
        .map_err(|_| Error::new("storageUnavailable", "Stored PIN is invalid."))
}

fn write(hash: &str, record: &Record) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(record)
        .map_err(|_| Error::new("invalidResponse", "Cannot encode PIN."))?);
    api::credential(STORE, hash, &bytes).map(|_| ())
}

pub fn enabled(hash: &str) -> bool {
    matches!(read(hash), Ok(Some(_)))
}

pub fn remove(hash: &str) -> Result<()> {
    api::credential(DELETE, hash, &[]).map(|_| ())
}

pub fn enroll(client: &Client, cache: &Cache, hash: &str, pin: &str) -> Result<()> {
    if pin.chars().count() < 4 {
        return Err(Error::new("invalidInput", "Use a PIN of at least 4 characters."));
    }
    let response = client.crypto().enroll_pin(pin.to_owned())
        .map_err(|e| crate::account::log_error("Enroll PIN", e, Error::new("invalidResponse", "Could not set up the PIN.")))?;
    write(hash, &Record {
        account_id: cache.account_id.clone(),
        server: cache.api.clone(),
        envelope: response.pin_protected_user_key_envelope.into(),
        failures: 0,
    })
}

/// The unlock method for `pin`, or an error that says how many attempts remain.
pub fn method(cache: &Cache, hash: &str, pin: String) -> Result<InitUserCryptoMethod> {
    let record = read(hash)?.ok_or_else(|| Error::new("pinUnavailable", "PIN unlock is not set up. Use your master password."))?;
    if record.account_id != cache.account_id || record.server != cache.api {
        remove(hash)?;
        return Err(Error::new("pinUnavailable", "PIN unlock is not set up. Use your master password."));
    }
    Ok(InitUserCryptoMethod::PinEnvelope {
        pin,
        pin_protected_user_key_envelope: record.envelope.parse()
            .map_err(|_| Error::new("storageUnavailable", "Stored PIN is invalid."))?,
    })
}

/// Records the outcome of a PIN attempt.
pub fn attempted(hash: &str, succeeded: bool) -> Result<Error> {
    let Some(mut record) = read(hash)? else {
        return Ok(Error::new("pinUnavailable", "PIN unlock is not set up. Use your master password."));
    };
    if succeeded {
        if record.failures != 0 { record.failures = 0; write(hash, &record)?; }
        return Ok(Error::new("ok", ""));
    }
    record.failures += 1;
    if record.failures >= MAX_ATTEMPTS {
        remove(hash)?;
        return Ok(Error::new("pinUnavailable", "Too many incorrect PINs. PIN unlock is off; use your master password."));
    }
    write(hash, &record)?;
    Ok(Error::new("invalidPin", "Incorrect PIN."))
}
