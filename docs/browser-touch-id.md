# Browser connection

[← Keywarden](../README.md)

Touch ID unlock for the official Bitwarden extension, without Bitwarden Desktop. The extension and Keywarden must use the **same account on the same server**. Keywarden's own vault can remain locked.

## Connect

With the vault unlocked, enable **Settings › Browsers › Unlock browsers with Touch ID**, then **Connect** the browser. Use **Replace…** if its connection belongs to another app. In the Bitwarden extension, enable **Unlock with biometrics**.

Supported: Firefox, Zen, Chrome, Edge, Chromium, Brave, Arc, Vivaldi, Opera and Helium, including Firefox Developer Edition/Nightly and Chrome/Edge Beta, Dev and Canary. A browser needs a verifiable signature to connect. Firefox-family browsers can share Firefox's registration; Settings shows which connection takes precedence.

## Keep or remove the connection

- **Replace** saves the previous native-host registration; **Disconnect** restores it. Disconnect before uninstalling Keywarden.
- **Update** points connected browsers at the current build. **Use This Copy** switches connections from another copy of the app.
- Apps in `/Applications` or `~/Applications` are registered in place. Builds elsewhere use a stable copy in `~/Library/Application Support/Keywarden/`.
- Keywarden keeps connected browsers assigned to its host until disconnected, reclaiming registrations changed by another app.

The host name remains `com.8bit.bitwarden`. Both the legacy encrypted protocol and SDK Noise IPC are supported. Each Touch ID request names the browser and account; browser and helper signatures are checked before key access. [Security details](security.md).
