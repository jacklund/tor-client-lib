# Tor Client Library

This is a client library for Tor, which allows you to interact programmatically with a Tor server, using its API.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE-APACHE)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE-MIT)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/jacklund/tor-client-lib/rust.yml)

## Installation

To add it to your existing project:

```bash
cargo add tor_client_lib
```

## Commands Supported

This library currently supports a small (but useful) subset of the full [API](https://github.com/torproject/torspec/blob/main/control-spec.txt), namely:

- `AUTHENTICATE`
- `AUTHCHALLENGE`
- `GETINFO`
- `PROTOCOLINFO`
- `ADD_ONION`
- `DEL_ONION`

If you’d like to see more functions supported, please either submit an issue request or a PR.

## Example Code

```rustuse tor_client_lib::{
use tor_client_lib::{
	control_connection::TorControlConnection,
    error::TorError,
    auth::TorAuthentication
};

// Connect to the Tor service running locally
let mut control_connection = TorControlConnection::connect("127.0.0.1:9051").await?;

// Authenticate to the Tor server
control_connection.authenticate(TorAuthentication::SafeCookie(None)).await?;

// Call the "GETINFO" command to get the Tor version number
let tor_version = control_connection.get_info("version").await?;
```

## CLI

The repo includes a simple CLI for sending commands to Tor. To use it, run:

```bash
cargo run
```

For example:

```bash
% cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/tor-cli`
Welcome to Tor CLI v0.1.0
Tor CLI> connect
Connected to localhost:9051
Tor CLI> authenticate cookie
Authenticated
Tor CLI> get_info version
["0.4.6.10"]
```
