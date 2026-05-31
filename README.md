# Wormhole

Wormhole is a macOS SSH tunnel manager built with Tauri and vanilla TypeScript.

## Features

- Save SSH tunnel profiles locally.
- Store passwords and key passphrases in the macOS keychain.
- Start and stop local, remote, and dynamic SOCKS forwarding with the system `ssh` command.
- Show live tunnel process state in the desktop UI.
- Control the app from the macOS menu bar.
- Show the current local client count in the macOS menu bar.
- Start or stop the service, which starts or stops all saved tunnel profiles.

## Development

```sh
npm install
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

## Notes

Wormhole delegates forwarding to OpenSSH. Key authentication works with private key files and the local SSH agent. Password authentication and encrypted key passphrases are provided to `ssh` through an askpass helper generated in the app config directory.

Closing the main window hides it so tunnels can continue running. Use the menu bar icon to show the window again or quit the app.

The menu bar client count is calculated from local established TCP sockets connected to local and SOCKS forwarding ports. Remote forwarding clients connect on the remote host and are not visible to this local counter.
