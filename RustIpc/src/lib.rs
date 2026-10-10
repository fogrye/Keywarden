use std::{
    ffi::CString,
    io::{self, Read, Write},
    os::fd::{FromRawFd, RawFd},
    os::unix::net::UnixStream,
    sync::{Arc, LazyLock, atomic::{AtomicU64, AtomicUsize, Ordering}},
    time::Duration,
};

use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::{
    CommunicationBackend, CommunicationBackendReceiver, Endpoint, ErrorKind, HostId,
    InMemorySessionRepository, IncomingMessage, IpcClient, IpcClientExt, IpcClientImpl,
    NoiseCryptoProvider, NoiseCryptoProviderState, OutgoingMessage, RpcHandler, RpcRequest, Source,
    discover::{DiscoverHandler, DiscoverResponse},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

mod app;
mod attachments;
mod account;
mod api;
mod generator;
mod import;
mod items;
mod pin;
mod store;
mod transfer;
mod vault;

// Native messaging uses a little-endian 32-bit JSON length, independent of machine word size.
const MAX_FRAME: usize = 1024 * 1024;
const MAX_KEY_B64: usize = 4096;
const MAX_PORTS: usize = 16;
const MAX_QUEUED: usize = 16;
static ACTIVE_PORTS: AtomicUsize = AtomicUsize::new(0);
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(4).build()
        .expect("IPC runtime")
});
static BIOMETRIC_WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static LEGACY_WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

unsafe extern "C" {
    fn bw_biometric(connection_id: u64, request_id: u64, generation: u64, action: i32,
        user_id: *const std::ffi::c_char, out: *mut u8, cap: usize) -> i32;
    fn bw_legacy_process(connection_id: u64, input: *const u8, length: usize,
        output: *mut u8, capacity: usize) -> i32;
    fn bw_connection_cancel(connection_id: u64);
    fn bw_app_generation() -> u64;
    fn bw_log(message: *const std::ffi::c_char);
}

/// Sends a diagnostic line to the app's unified log. Never pass secrets or message payloads.
pub(crate) fn log_line(text: &str) {
    if let Ok(text) = CString::new(text.replace('\0', "")) {
        unsafe { bw_log(text.as_ptr()) }
    }
}

#[derive(Debug)]
struct TransportError(io::Error);

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl bitwarden_ipc::IpcErrorKind for TransportError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Fatal
    }
}

#[derive(Clone)]
struct NativeBackend {
    incoming: broadcast::Sender<IncomingMessage>,
    output: mpsc::Sender<Vec<u8>>,
}

struct NativeReceiver(tokio::sync::Mutex<broadcast::Receiver<IncomingMessage>>);

impl CommunicationBackend for NativeBackend {
    type SendError = TransportError;
    type Receiver = NativeReceiver;

    async fn send(&self, message: OutgoingMessage) -> Result<(), TransportError> {
        // Only the extension background may receive messages on this native connection.
        if message.destination != (Endpoint::BrowserBackground { id: HostId::Own }) {
            return Err(TransportError(io::Error::new(io::ErrorKind::InvalidInput, "invalid destination")));
        }
        let envelope = ForwardedEnvelope {
            kind: "forwarded-bitwarden-ipc-message",
            original_source: Source::DesktopRenderer,
            message,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(io::Error::other).map_err(TransportError)?;
        if encoded.len() > MAX_FRAME {
            return Err(TransportError(io::ErrorKind::InvalidData.into()));
        }
        self.output.try_send(encoded).map_err(|_| TransportError(io::ErrorKind::BrokenPipe.into()))
    }

    async fn subscribe(&self) -> NativeReceiver {
        NativeReceiver(tokio::sync::Mutex::new(self.incoming.subscribe()))
    }
}

impl CommunicationBackendReceiver for NativeReceiver {
    type ReceiveError = TransportError;

    async fn receive(&self) -> Result<IncomingMessage, TransportError> {
        self.0.lock().await.recv().await.map_err(|error| {
            let kind = match error {
                broadcast::error::RecvError::Closed => io::ErrorKind::BrokenPipe,
                broadcast::error::RecvError::Lagged(_) => io::ErrorKind::InvalidData,
            };
            TransportError(io::Error::new(kind, error))
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForwardedEnvelope {
    #[serde(rename = "type")]
    kind: &'static str,
    original_source: Source,
    message: OutgoingMessage,
}

#[derive(Deserialize)]
struct BrowserEnvelope {
    #[serde(rename = "type")]
    kind: String,
    message: Option<BrowserMessage>,
}

#[derive(Deserialize)]
struct BrowserMessage {
    destination: Endpoint,
    payload: Vec<u8>,
    topic: Option<String>,
}

#[derive(Deserialize)]
struct FrameShape<'a> {
    #[serde(rename = "type")]
    kind: Option<&'a str>,
    #[serde(rename = "appId")]
    app_id: Option<&'a str>,
    message: Option<serde::de::IgnoredAny>,
}

fn write_frame(output: &mut impl Write, content: &[u8]) -> io::Result<()> {
    let size: u32 = content.len().try_into().map_err(|_| io::ErrorKind::InvalidData)?;
    if content.len() > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    output.write_all(&size.to_le_bytes())?;
    output.write_all(content)?;
    output.flush()
}

fn read_frame(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut size = [0_u8; 4];
    let mut first = [0_u8; 1];
    if input.read(&mut first)? == 0 {
        return Ok(None);
    }
    size[0] = first[0];
    input.read_exact(&mut size[1..])?;
    let count = u32::from_le_bytes(size) as usize;
    if count == 0 || count > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut content = vec![0; count];
    input.read_exact(&mut content)?;
    Ok(Some(content))
}

fn parse_incoming(frame: &[u8]) -> io::Result<Option<IncomingMessage>> {
    let envelope: BrowserEnvelope = serde_json::from_slice(frame).map_err(io::Error::other)?;
    if envelope.kind != "bitwarden-ipc-message" {
        return Ok(None);
    }
    let message = envelope.message.ok_or(io::ErrorKind::InvalidData)?;
    if message.destination != Endpoint::DesktopRenderer
        || message.payload.is_empty()
        || message.topic.as_ref().is_some_and(|topic| topic.len() > 256)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(IncomingMessage {
        destination: message.destination,
        payload: message.payload,
        topic: message.topic,
        source: Source::BrowserBackground { id: HostId::Own },
    }))
}

fn is_legacy(frame: &[u8]) -> io::Result<bool> {
    let shape: FrameShape<'_> = serde_json::from_slice(frame).map_err(io::Error::other)?;
    Ok(shape.kind.is_none() && shape.app_id.is_some() && shape.message.is_some())
}

// These types intentionally mirror bitwarden-shared-unlock/src/wasm/biometrics.rs at the
// pinned SDK revision; that module is wasm-only and cannot be imported into a native crate.
#[derive(Serialize, Deserialize)]
struct GetBiometricsStatusRequest {
    user_id: String,
}
impl RpcRequest for GetBiometricsStatusRequest {
    type Response = BiometricsStatus;
    const NAME: &'static str = "GetBiometricsStatus";
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum BiometricsStatus {
    Available,
    UnlockNeeded,
    HardwareUnavailable,
    NotEnabled,
}

#[derive(Serialize, Deserialize)]
struct AuthenticateBiometricsRequest;
impl RpcRequest for AuthenticateBiometricsRequest {
    type Response = bool;
    const NAME: &'static str = "AuthenticateBiometrics";
}

#[derive(Serialize, Deserialize)]
struct UnlockBiometricsRequest {
    user_id: String,
}
impl RpcRequest for UnlockBiometricsRequest {
    type Response = UnlockBiometricsResponse;
    const NAME: &'static str = "UnlockBiometrics";
}

#[derive(Serialize, Deserialize)]
struct UnlockBiometricsResponse {
    user_key: Option<SymmetricCryptoKey>,
}

fn valid_user(user_id: &str) -> Option<CString> {
    let uuid = uuid::Uuid::parse_str(user_id).ok()?;
    // Only canonical UUID strings are accepted. This prevents selecting arbitrary credentials.
    let canonical = uuid.to_string();
    if canonical != user_id.to_ascii_lowercase() {
        return None;
    }
    CString::new(canonical).ok()
}

#[derive(Clone)]
struct BiometricHandler {
    connection_id: u64,
    cancellation: CancellationToken,
}

impl BiometricHandler {
    async fn call(&self, action: i32, user: Option<CString>) -> Option<(i32, Zeroizing<Vec<u8>>)> {
        let deadline = tokio::time::Instant::now()
            + if action == 0 { Duration::from_millis(450) } else { Duration::from_secs(55) };
        let generation = unsafe { bw_app_generation() };
        let permit = tokio::select! {
            result = tokio::time::timeout_at(deadline, BIOMETRIC_WORKERS.clone().acquire_owned()) =>
                result.ok()?.ok()?,
            _ = self.cancellation.cancelled() => return None,
        };
        let cancellation = self.cancellation.clone();
        let connection_id = self.connection_id;
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut key = Zeroizing::new(vec![0u8; if action == 2 { MAX_KEY_B64 } else { 0 }]);
            if cancellation.is_cancelled() || unsafe { bw_app_generation() } != generation {
                return None;
            }
            let count = unsafe {
                bw_biometric(connection_id, request_id, generation, action,
                    user.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                    key.as_mut_ptr(), key.len())
            };
            if cancellation.is_cancelled() || unsafe { bw_app_generation() } != generation {
                return None;
            }
            Some((count, key))
        });
        tokio::select! {
            result = tokio::time::timeout_at(deadline, worker) => result.ok()?.ok()?,
            _ = self.cancellation.cancelled() => None,
        }
    }
}

struct StatusHandler(BiometricHandler);
impl RpcHandler for StatusHandler {
    type Request = GetBiometricsStatusRequest;
    async fn handle(&self, request: Self::Request) -> BiometricsStatus {
        let Some(user) = valid_user(&request.user_id) else { return BiometricsStatus::NotEnabled };
        match self.0.call(0, Some(user)).await.map(|reply| reply.0) {
            Some(0) => BiometricsStatus::Available,
            Some(1) => BiometricsStatus::UnlockNeeded,
            Some(2) => BiometricsStatus::HardwareUnavailable,
            _ => BiometricsStatus::NotEnabled,
        }
    }
}

struct AuthenticateHandler(BiometricHandler);
impl RpcHandler for AuthenticateHandler {
    type Request = AuthenticateBiometricsRequest;
    async fn handle(&self, _: Self::Request) -> bool {
        matches!(self.0.call(1, None).await, Some((1, _)))
    }
}

struct UnlockHandler(BiometricHandler);
impl RpcHandler for UnlockHandler {
    type Request = UnlockBiometricsRequest;
    async fn handle(&self, request: Self::Request) -> UnlockBiometricsResponse {
        let user_key = if let Some(user) = valid_user(&request.user_id) {
            match self.0.call(2, Some(user)).await {
                Some((count, key)) if count > 0 && (count as usize) <= key.len() =>
                    std::str::from_utf8(&key[..count as usize]).ok()
                        .and_then(|text| text.parse::<SymmetricCryptoKey>().ok()),
                _ => None,
            }
        } else { None };
        UnlockBiometricsResponse { user_key }
    }
}

async fn process_legacy(connection_id: u64, bytes: Vec<u8>,
    cancellation: CancellationToken, output: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    let permit = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(55), LEGACY_WORKERS.clone().acquire_owned()) =>
            result.map_err(|_| io::ErrorKind::TimedOut)?.map_err(io::Error::other)?,
        _ = cancellation.cancelled() => return Ok(()),
    };
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut response = Zeroizing::new(vec![0u8; MAX_FRAME]);
        let count = unsafe {
            bw_legacy_process(connection_id, bytes.as_ptr(), bytes.len(), response.as_mut_ptr(), response.len())
        };
        if count < 0 || count as usize > response.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(if count == 0 { None } else { Some(response[..count as usize].to_vec()) })
    });
    let reply: Option<Vec<u8>> = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(55), worker) =>
            result.map_err(|_| io::ErrorKind::TimedOut)?.map_err(io::Error::other)??,
        _ = cancellation.cancelled() => return Ok(()),
    };
    if !cancellation.is_cancelled() {
        if let Some(reply) = reply {
            output.try_send(reply).map_err(|_| io::ErrorKind::BrokenPipe)?;
        }
    }
    Ok(())
}

async fn run_port(stream: UnixStream, connection_id: u64) -> io::Result<()> {
    let control = stream.try_clone()?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let (output, mut outgoing) = mpsc::channel::<Vec<u8>>(MAX_QUEUED);
    let writer_task = tokio::task::spawn_blocking(move || {
        while let Some(frame) = outgoing.blocking_recv() {
            write_frame(&mut writer, &frame)?;
        }
        Ok::<(), io::Error>(())
    });
    let (incoming, _) = broadcast::channel(16);
    let backend = NativeBackend { incoming: incoming.clone(), output: output.clone() };
    let client = IpcClientImpl::new(
        NoiseCryptoProvider::new(), backend,
        InMemorySessionRepository::<NoiseCryptoProviderState>::default(),
    );
    let cancellation = CancellationToken::new();
    let handler = BiometricHandler { connection_id, cancellation: cancellation.clone() };
    client.register_rpc_handler(DiscoverHandler::new(DiscoverResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })).await;
    client.register_rpc_handler(StatusHandler(handler.clone())).await;
    client.register_rpc_handler(AuthenticateHandler(handler.clone())).await;
    client.register_rpc_handler(UnlockHandler(handler)).await;
    client.start(Some(cancellation.clone())).await.map_err(io::Error::other)?;
    output.try_send(br#"{"command":"connected"}"#.to_vec())
        .map_err(|_| io::ErrorKind::BrokenPipe)?;

    let (frames, mut received) = mpsc::channel::<io::Result<Option<Vec<u8>>>>(MAX_QUEUED);
    let reader_task = std::thread::spawn(move || {
        loop {
            let frame = read_frame(&mut reader);
            let done = !matches!(&frame, Ok(Some(_)));
            if frames.try_send(frame).is_err() {
                log_line(&format!("Browser connection {connection_id}: too many queued requests; closing"));
                break;
            }
            if done { break; }
        }
    });
    log_line(&format!("Browser connection {connection_id} opened"));
    let result = async {
        while let Some(frame) = received.recv().await {
            let Some(frame) = frame? else { break };
            if is_legacy(&frame)? {
                process_legacy(connection_id, frame, cancellation.clone(), output.clone()).await?;
            } else if let Some(message) = parse_incoming(&frame)? {
                log_line(&format!("Browser connection {connection_id}: SDK IPC message, topic {:?}", message.topic));
                let _ = incoming.send(message);
            } else {
                log_line(&format!("Browser connection {connection_id}: ignored a frame of another kind"));
            }
        }
        Ok(())
    }.await;
    match &result {
        Ok(()) => log_line(&format!("Browser connection {connection_id} closed")),
        Err(error) => log_line(&format!("Browser connection {connection_id} closed with error: {error}")),
    }
    cancellation.cancel();
    unsafe { bw_connection_cancel(connection_id) };
    let _ = control.shutdown(std::net::Shutdown::Both);
    drop(output);
    drop(client);
    drop(reader_task);
    drop(writer_task);
    result
}

/// Takes ownership of an authenticated, connected AF_UNIX descriptor.
#[unsafe(no_mangle)]
pub extern "C" fn bw_ipc_run_fd(fd: RawFd, connection_id: u64) -> i32 {
    if fd < 0 { return 1 }
    // SAFETY: ownership of a valid descriptor transfers to this function unconditionally.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if ACTIVE_PORTS.try_update(Ordering::AcqRel, Ordering::Acquire,
        |count| (count < MAX_PORTS).then_some(count + 1)).is_err() {
        return 1;
    }
    let result = std::panic::catch_unwind(|| RUNTIME.block_on(run_port(stream, connection_id)));
    ACTIVE_PORTS.fetch_sub(1, Ordering::AcqRel);
    match result { Ok(Ok(())) => 0, _ => 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_native_frames_do_not_reach_ipc() {
        for bytes in [
            (MAX_FRAME as u32 + 1).to_le_bytes().to_vec(),
            vec![3, 0],
            vec![3, 0, 0, 0, b'{'],
        ] {
            assert!(read_frame(&mut bytes.as_slice()).is_err());
        }
        let wrong_destination = serde_json::to_vec(&serde_json::json!({
            "type": "bitwarden-ipc-message",
            "message": {
                "destination": Endpoint::BrowserBackground { id: HostId::Own },
                "payload": [1, 2, 3]
            }
        })).unwrap();
        assert!(parse_incoming(&wrong_destination).is_err());
    }
}
