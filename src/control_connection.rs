use crate::{
    auth::TorAuthentication,
    error::TorError,
    key::{TorEd25519SigningKey, TorServiceId},
};
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use log::info;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Error, Formatter};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddr as TcpSocketAddr};
use std::os::unix::net::SocketAddr as UnixSocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream, ToSocketAddrs, UnixListener, UnixStream},
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};

/// Generalization of the [std::net::SocketAddr] for Tor communication.
/// Clients can communicate with the Tor server either through the standard TCP connection, or
/// through a Unix socket.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SocketAddr {
    Tcp(TcpSocketAddr),
    Unix(String),
}

impl SocketAddr {
    /// Create the socket address from a TCP address string of the form "<ip>:<port>"
    fn from_tcp_string(address: &str) -> Result<Self, AddrParseError> {
        Ok(Self::Tcp(TcpSocketAddr::from_str(address)?))
    }

    /// Create the socket address from the path to the unix socket
    fn from_unix_string<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        Ok(Self::Unix(
            UnixSocketAddr::from_pathname(path)?
                .as_pathname()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        ))
    }
}

/// Convert from a [std::net::SocketAddr] to this
impl From<TcpSocketAddr> for SocketAddr {
    fn from(socket_addr: TcpSocketAddr) -> SocketAddr {
        Self::Tcp(socket_addr)
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            Self::Tcp(sock_addr) => write!(f, "{}", sock_addr),
            Self::Unix(sock_addr) => write!(f, "unix:{:?}", sock_addr),
        }
    }
}

impl Default for SocketAddr {
    fn default() -> Self {
        SocketAddr::Tcp(TcpSocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9051,
        ))
    }
}

/// Error returned when a given listen address type has a parse error
#[derive(Debug)]
pub enum ListenAddressParseError {
    TcpParseError(AddrParseError),
    UnixParseError(std::io::Error),
}

impl std::error::Error for ListenAddressParseError {}

impl Display for ListenAddressParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            Self::TcpParseError(error) => write!(f, "Error parsing TCP address: {}", error),
            Self::UnixParseError(error) => write!(f, "Error parsing Unix address:{}", error),
        }
    }
}

impl From<AddrParseError> for ListenAddressParseError {
    fn from(err: AddrParseError) -> Self {
        Self::TcpParseError(err)
    }
}

impl From<std::io::Error> for ListenAddressParseError {
    fn from(err: std::io::Error) -> Self {
        Self::UnixParseError(err)
    }
}

impl FromStr for SocketAddr {
    type Err = ListenAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix("unix:") {
            Ok(Self::from_unix_string(path)?)
        } else {
            Ok(Self::from_tcp_string(s)?)
        }
    }
}

/// You can listen for data for an onion service either through TCP or a unix socket
pub enum OnionServiceListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl OnionServiceListener {
    /// Bind to the given socket address for listening
    pub async fn bind(socket_addr: SocketAddr) -> Result<OnionServiceListener, std::io::Error> {
        match socket_addr {
            SocketAddr::Tcp(socket_addr) => Ok(OnionServiceListener::Tcp(
                TcpListener::bind(socket_addr).await?,
            )),
            SocketAddr::Unix(path) => Ok(OnionServiceListener::Unix(UnixListener::bind(path)?)),
        }
    }

    /// Accept an incoming connection from the listener
    pub async fn accept(&self) -> Result<(OnionServiceStream, SocketAddr), std::io::Error> {
        match self {
            Self::Tcp(listener) => {
                let (stream, socket) = listener.accept().await?;
                Ok((OnionServiceStream::Tcp(stream), socket.into()))
            }
            Self::Unix(listener) => {
                let (stream, socket) = listener.accept().await?;
                Ok((
                    OnionServiceStream::Unix(stream),
                    SocketAddr::Unix(socket.as_pathname().unwrap().to_string_lossy().to_string()),
                ))
            }
        }
    }
}

/// A stream of data from an accepted listener socket
pub enum OnionServiceStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for OnionServiceStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::into_inner(self) {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OnionServiceStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::into_inner(self) {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match Pin::into_inner(self) {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::into_inner(self) {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Mapping from an Onion service virtual port to a local listen address
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct OnionServiceMapping {
    virt_port: u16,
    listen_address: SocketAddr,
}

impl OnionServiceMapping {
    pub fn new(virt_port: u16, listen_address: Option<SocketAddr>) -> Self {
        Self {
            virt_port,
            listen_address: match listen_address {
                None => SocketAddr::from_tcp_string(&format!("127.0.0.1:{}", virt_port)).unwrap(),
                Some(a) => a,
            },
        }
    }

    pub fn virt_port(&self) -> u16 {
        self.virt_port
    }

    pub fn listen_address(&self) -> &SocketAddr {
        &self.listen_address
    }
}

/// Onion address, containing a [TorServiceId] and a service port
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAddress {
    service_id: TorServiceId,
    service_port: u16,
}

impl OnionAddress {
    pub fn new(service_id: TorServiceId, port: u16) -> Self {
        Self {
            service_id,
            service_port: port,
        }
    }

    pub fn service_id(&self) -> &TorServiceId {
        &self.service_id
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }
}

impl FromStr for OnionAddress {
    type Err = TorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let values = s.split(':').collect::<Vec<&str>>();
        if values.len() != 2 {
            return Err(TorError::protocol_error("Bad onion address"));
        }
        let host_values = values[0].split('.').collect::<Vec<&str>>();
        if host_values.len() != 2 || host_values[1] != "onion" {
            return Err(TorError::protocol_error("Bad onion address"));
        }
        let service_id = match TorServiceId::from_str(host_values[0]) {
            Ok(id) => id,
            Err(error) => {
                return Err(TorError::protocol_error(&format!(
                    "Error parsing host field in onion address: {}",
                    error
                )));
            }
        };
        let service_port = match values[1].parse::<u16>() {
            Ok(port) => port,
            Err(error) => {
                return Err(TorError::protocol_error(&format!(
                    "Error parsing port field in onion address: {}",
                    error
                )));
            }
        };
        Ok(Self {
            service_id,
            service_port,
        })
    }
}

impl Display for OnionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}.onion:{}", self.service_id, self.service_port)
    }
}

/// Definition of a Tor Onion service (AKA "hidden service").
///
/// An onion service can be thought of as an encrypted load balancer, which presents itself as a
/// virtual host in the Tor network, and which maps virtual ports on that virtual host to service
/// ports running on your local machine. While, in practice, most onion services map a single
/// virtual port to a service port, say, 443 to 443, you can map multiple virtual ports to a single
/// service port, or a single virtual port to multiple service ports (in which case Tor will load
/// balance the traffic coming in on the virtual port across the corresponding service ports).
///
/// Each onion service has the following:
/// - The service ID contains all the information for the public key (see [TorServiceId] for
/// details).
/// - The signing, i.e, private, key for the onion service
/// - The mapping from the virtual port(s) to the service port(s)
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct OnionService {
    ports: Vec<OnionServiceMapping>,
    service_id: TorServiceId,
    signing_key: TorEd25519SigningKey,
}

impl OnionService {
    /// Create a new `OnionService` object
    pub fn new<S, K>(id: S, key: K, ports: &[OnionServiceMapping]) -> Self
    where
        TorServiceId: From<S>,
        TorEd25519SigningKey: From<K>,
    {
        Self {
            ports: ports.to_vec(),
            service_id: id.into(),
            signing_key: key.into(),
        }
    }

    /// Return all the listen addresses for a given onion address (including virtual port)
    /// `onion_address` should be formatted as `<onion-address>:<port>`, e.g.
    /// `joikeok6el5h5sbrojo2h3afw63lmfm7huvwtziacl34wjrx7n62gsad.onion:443`
    pub fn listen_addresses_for_onion_address(&self, onion_address: &str) -> Vec<SocketAddr> {
        self.ports
            .iter()
            .map(|p| (p, format!("{}.onion:{}", self.service_id, p.virt_port)))
            .filter(|(_p, a)| a == onion_address)
            .map(|(p, _a)| p.listen_address.clone())
            .collect()
    }

    /// Return all the listen addresses for the given local service port
    pub fn listen_addresses_for_port(&self, service_port: u16) -> Vec<SocketAddr> {
        self.ports
            .iter()
            .filter(|p| p.virt_port == service_port)
            .map(|p| p.listen_address.clone())
            .collect()
    }

    /// Return the onion address (i.e., the onion hostname and virtual port) which maps to the
    /// given local service port
    pub fn onion_address(&self, service_port: u16) -> Result<OnionAddress, TorError> {
        if self.ports.iter().any(|p| p.virt_port == service_port) {
            Ok(OnionAddress {
                service_id: self.service_id.clone(),
                service_port,
            })
        } else {
            Err(TorError::protocol_error(&format!(
                "No Onion Service Port {} found for onion service {}",
                service_port, self.service_id
            )))
        }
    }

    /// Return a list of all the onion addresses for this onion service
    pub fn onion_addresses(&self) -> Vec<OnionAddress> {
        self.ports
            .iter()
            .map(|p| OnionAddress::new(self.service_id.clone(), p.virt_port))
            .collect()
    }

    /// Return the [TorServiceId] for this onion service
    pub fn service_id(&self) -> &TorServiceId {
        &self.service_id
    }

    /// Return the Tor signing key for this onion service
    pub fn signing_key(&self) -> &TorEd25519SigningKey {
        &self.signing_key
    }

    /// Return the list of virtual to service port mappings for this onion service
    pub fn ports(&self) -> &Vec<OnionServiceMapping> {
        &self.ports
    }
}

/// Response returned by the Tor server in response to a command
#[derive(Debug)]
pub struct ControlResponse {
    pub status_code: u16,
    pub reply: String,
}

impl ControlResponse {
    fn new() -> Self {
        Self {
            status_code: 0,
            reply: String::new(),
        }
    }
}

fn parse_status_code(code_str: &str) -> Result<u16, TorError> {
    match code_str.parse::<u16>() {
        Ok(status_code) => Ok(status_code),
        Err(error) => Err(TorError::protocol_error(&format!(
            "Error parsing response status code: {}",
            error
        ))),
    }
}

/// Read a response to a controller command
async fn read_control_response<S: StreamExt<Item = Result<String, LinesCodecError>> + Unpin>(
    reader: &mut S,
) -> Result<ControlResponse, TorError> {
    lazy_static! {
        // Mid reply
        static ref MID_REGEX: Regex = Regex::new(r"^(?P<code>\d{3})-(?P<reply_line>.*)$").unwrap();

        // Data reply
        static ref DATA_REGEX: Regex =
            Regex::new(r"^(?P<code>\d{3})\+(?P<reply_line>.*)$").unwrap();

        // End of reply message
        static ref END_REGEX: Regex = Regex::new(r"^(?P<code>\d{3}) (?P<reply_line>.*)$").unwrap();
    }

    let mut control_response = ControlResponse::new();
    loop {
        let mut line = read_line(reader).await?;
        info!("<= {}", line);
        match MID_REGEX.captures(&line) {
            // Read Mid replies line-by-line, and append their reply lines to the reply
            Some(captures) => {
                control_response.status_code = parse_status_code(&captures["code"])?;
                control_response
                    .reply
                    .push_str(&format!("{}\n", &captures["reply_line"]));
            }
            None => match DATA_REGEX.captures(&line.clone()) {
                // For Data replies, append everything between the initial line and the "." to the reply line
                Some(captures) => {
                    control_response.status_code = parse_status_code(&captures["code"])?;
                    let mut reply_line = captures["reply_line"].to_string();
                    reply_line.push('\n');
                    loop {
                        line = read_line(reader).await?;
                        if line == "." {
                            break;
                        }
                        reply_line.push_str(&line);
                        reply_line.push('\n');
                    }
                    control_response.reply = reply_line;
                    // Read the final "250 OK"
                    read_line(reader).await?;
                    return Ok(control_response);
                }
                None => match END_REGEX.captures(&line) {
                    Some(captures) => {
                        control_response.status_code = parse_status_code(&captures["code"])?;
                        // If we haven't gotten any other replies, use this one as the message
                        if control_response.reply.is_empty() {
                            control_response.reply.push_str(&captures["reply_line"]);
                        }
                        return Ok(control_response);
                    }
                    None => {
                        return Err(TorError::ProtocolError(format!(
                            "Unknown response: {}",
                            line
                        )))
                    }
                },
            },
        }
    }
}

/// Read a response line
async fn read_line<S: StreamExt<Item = Result<String, LinesCodecError>> + Unpin>(
    reader: &mut S,
) -> Result<String, TorError> {
    match reader.next().await {
        Some(Ok(line)) => Ok(line),
        Some(Err(error)) => Err(error.into()),
        None => Err(TorError::protocol_error("Unexpected EOF on stream")),
    }
}

/// Format the ADD_ONION request arguments
fn format_onion_service_request_string(
    key_type: &str,
    key_blob: &str,
    ports: &[OnionServiceMapping],
    transient: bool,
) -> String {
    let flags = if transient { "" } else { "Flags=Detach" };
    let port_string = ports
        .iter()
        .map(|p| format!("Port={},{}", p.virt_port, p.listen_address))
        .collect::<Vec<String>>()
        .join(" ");
    format!("{}:{} {} {}", key_type, key_blob, flags, port_string)
}

fn format_key_request_string(
    ports: &[OnionServiceMapping],
    transient: bool,
    signing_key: Option<&SigningKey>,
) -> String {
    match signing_key {
        Some(signing_key) => format_onion_service_request_string(
            "ED25519-V3",
            &TorEd25519SigningKey::from(signing_key).to_blob(),
            ports,
            transient,
        ),
        None => format_onion_service_request_string("NEW", "BEST", ports, transient),
    }
}

/// Parse a response field that is required, i.e., throw an error if it's not there
fn parse_required_response_field<'a>(
    captures: &Captures<'a>,
    field_name: &str,
    field_arg: &str,
    response_type: &str,
) -> Result<&'a str, TorError> {
    match captures.name(field_name) {
        Some(field) => Ok(field.as_str()),
        None => Err(TorError::protocol_error(&format!(
            "'{}' field not found in {} response",
            field_arg, response_type,
        ))),
    }
}

fn parse_add_onion_response(
    captures: &Captures<'_>,
    ports: &[OnionServiceMapping],
    signing_key: Option<&SigningKey>,
) -> Result<OnionService, TorError> {
    // Parse the Hash value
    let hash_string =
        parse_required_response_field(captures, "service_id", "ServiceID", "ADD_ONION")?;

    // Retrieve the key, either the one passed in or the one
    // returned from the controller
    let (returned_signing_key, verifying_key) = match signing_key {
        Some(signing_key) => (signing_key.into(), signing_key.verifying_key()),
        None => match captures.name("key_type") {
            Some(_) => {
                let signing_key =
                    TorEd25519SigningKey::from_blob(captures.name("key_blob").unwrap().as_str());
                let verifying_key = signing_key.verifying_key();
                (signing_key, verifying_key)
            }
            None => {
                return Err(TorError::protocol_error(
                    "Expected signing key to be returned by Tor",
                ));
            }
        },
    };

    let expected_service_id: TorServiceId = verifying_key.into();

    if expected_service_id.as_str() != hash_string {
        return Err(
            TorError::protocol_error(&format!(
                    "Service ID for onion service returned by tor ({}) doesn't match the service ID generated from verifying key ({})",
                    hash_string, expected_service_id.as_str())));
    }

    let service_id = match TorServiceId::from_str(hash_string) {
        Ok(id) => id,
        Err(error) => {
            return Err(TorError::protocol_error(&format!(
                "Error parsing Tor Service ID: {}",
                error
            )))
        }
    };

    // Return the Onion Service
    Ok(OnionService::new(service_id, returned_signing_key, ports))
}

/// ProtocolInfo struct, contains information from the response to the
/// PROTOCOLINFO command
#[derive(Clone, Debug)]
pub struct ProtocolInfo {
    pub auth_methods: Vec<String>,
    pub cookie_file: Option<String>,
    pub tor_version: String,
}

/// Control connection, used to send commands to and receive responses from
/// the Tor server
pub struct TorControlConnection {
    reader: FramedRead<ReadHalf<TcpStream>, LinesCodec>,
    writer: FramedWrite<WriteHalf<TcpStream>, LinesCodec>,
    protocol_info: Option<ProtocolInfo>,
}

impl TorControlConnection {
    /// Connect to the Tor server. This is generally how you create a connection to the server
    pub async fn connect<A: ToSocketAddrs>(addrs: A) -> Result<Self, TorError> {
        let this = Self::with_stream(TcpStream::connect(addrs).await?)?;
        Ok(this)
    }

    /// Convert an existing TCPStream into a connection object
    pub(crate) fn with_stream(stream: TcpStream) -> Result<Self, TorError> {
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: FramedRead::new(reader, LinesCodec::new()),
            writer: FramedWrite::new(writer, LinesCodec::new()),
            protocol_info: None,
        })
    }

    /// Write to the Tor Server
    async fn write(&mut self, data: &str) -> Result<(), TorError> {
        self.writer.send(data).await?;
        Ok(())
    }

    /// Send the PROTOCOLINFO command and parse the response
    pub async fn get_protocol_info(&mut self) -> Result<ProtocolInfo, TorError> {
        if self.protocol_info.is_some() {
            Ok(self.protocol_info.clone().unwrap())
        } else {
            let control_response = self.send_command("PROTOCOLINFO", Some("1")).await?;

            if control_response.status_code != 250 {
                return Err(TorError::protocol_error(&format!(
                    "Expected status code 250, got {}",
                    control_response.status_code
                )));
            }

            // Parse the controller response
            lazy_static! {
                static ref RE: Regex =
                    Regex::new(r"^PROTOCOLINFO 1\nAUTH METHODS=(?P<auth_methods>[^ ]*)( COOKIEFILE=(?P<cookie_file>.*))*\nVERSION Tor=(?P<tor_version>.*)\n")
                        .unwrap();
            }
            let captures = match RE.captures(&control_response.reply) {
                Some(captures) => captures,
                None => {
                    return Err(TorError::protocol_error(
                        "Error parsing PROTOCOLINFO response",
                    ))
                }
            };
            let auth_methods = parse_required_response_field(
                &captures,
                "auth_methods",
                "AUTH METHODS",
                "PROTOCOLINFO",
            )?
            .split(',')
            .map(|s| s.to_string())
            .collect();
            let tor_version =
                parse_required_response_field(&captures, "tor_version", "VERSION", "PROTOCOLINFO")?
                    .replace('"', "");
            let protocol_info = ProtocolInfo {
                auth_methods,
                cookie_file: captures
                    .name("cookie_file")
                    .map(|c| c.as_str().replace('"', "").to_string()),
                tor_version,
            };
            self.protocol_info = Some(protocol_info.clone());
            Ok(protocol_info)
        }
    }

    /// Send the GETINFO command and parse the response
    pub async fn get_info(&mut self, info: &str) -> Result<Vec<String>, TorError> {
        let control_response = self.send_command("GETINFO", Some(info)).await?;
        info!(
            "Send GETINFO command, got control response {:?}",
            control_response
        );
        if control_response.status_code != 250 {
            return Err(TorError::protocol_error(&format!(
                "Expected status code 250, got {}",
                control_response.status_code
            )));
        }
        let split_response = &control_response
            .reply
            .trim_end()
            .split('=')
            .collect::<Vec<&str>>();
        if split_response.len() <= 1 {
            return Err(TorError::protocol_error(&format!(
                "Got unexpected reply '{}', expected key/value pair",
                control_response.reply
            )));
        }

        let response = split_response[1].split('\n').collect::<Vec<&str>>();

        let mut ret = Vec::new();
        for value in response.iter() {
            if !value.is_empty() {
                ret.push(value.to_string());
            }
        }

        Ok(ret)
    }

    /// Authenticate to the Tor server using the passed-in method
    pub async fn authenticate(&mut self, method: TorAuthentication) -> Result<(), TorError> {
        method.authenticate(self).await?;
        Ok(())
    }

    /// Send a general command to the Tor server
    pub(crate) async fn send_command(
        &mut self,
        command: &str,
        arguments: Option<&str>,
    ) -> Result<ControlResponse, TorError> {
        let command_string = match arguments {
            None => command.to_string(),
            Some(arguments) => format!("{} {}", command, arguments),
        };
        info!("=> {}", command_string);
        self.write(&command_string).await?;
        match read_control_response(&mut self.reader).await {
            Ok(control_response) => match control_response.status_code {
                250 | 251 => Ok(control_response),
                _ => Err(TorError::ProtocolError(control_response.reply)),
            },
            Err(error) => Err(error),
        }
    }

    /// Create an onion service.
    pub async fn create_onion_service(
        &mut self,
        ports: &[OnionServiceMapping],
        transient: bool,
        signing_key: Option<&SigningKey>,
    ) -> Result<OnionService, TorError> {
        // Create the request string from the arguments
        let request_string = format_key_request_string(ports, transient, signing_key);

        // Send command to Tor controller
        let control_response = self
            .send_command("ADD_ONION", Some(&request_string))
            .await?;
        info!(
            "Sent ADD_ONION command, got control response {:?}",
            control_response
        );

        if control_response.status_code != 250 {
            return Err(TorError::protocol_error(&format!(
                "Expected status code 250, got {}",
                control_response.status_code
            )));
        }

        // Parse the controller response
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"(?m)^ServiceID=(?P<service_id>.*)\n(PrivateKey=(?P<key_type>[^:]*):(?<key_blob>.*)$)?$")
                    .unwrap();
        }
        match RE.captures(&control_response.reply) {
            Some(captures) => parse_add_onion_response(&captures, ports, signing_key),
            None => Err(TorError::ProtocolError(format!(
                "Unexpected response: {} {}",
                control_response.status_code, control_response.reply,
            ))),
        }
    }

    pub async fn delete_onion_service(&mut self, service_id: &str) -> Result<(), TorError> {
        // Just in case someone passes in the ".onion" part
        let service_id_string = service_id.replace(".onion", "");

        // Send command to Tor controller
        let control_response = self
            .send_command("DEL_ONION", Some(&service_id_string))
            .await?;
        info!(
            "Sent DEL_ONION command, got control response {:?}",
            control_response
        );

        if control_response.status_code != 250 {
            Err(TorError::protocol_error(&format!(
                "Expected status code 250, got {}",
                control_response.status_code
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use tokio;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::codec::{Framed, LinesCodec};

    async fn create_mock() -> Result<(TcpStream, TcpStream), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let join_handle = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpStream::connect(addr).await?;
        let (server_stream, _) = join_handle.await?;

        Ok((client, server_stream))
    }

    async fn create_framed_mock() -> Result<
        (Framed<TcpStream, LinesCodec>, Framed<TcpStream, LinesCodec>),
        Box<dyn std::error::Error>,
    > {
        let (client, server) = create_mock().await?;
        let reader = Framed::new(client, LinesCodec::new());
        let server = Framed::new(server, LinesCodec::new());

        Ok((reader, server))
    }

    #[tokio::test]
    async fn test_read_good_control_response() -> Result<(), Box<dyn std::error::Error>> {
        // 250 OK response
        let (mut client, mut server) = create_framed_mock().await?;
        server.send("250 OK").await?;
        let result = read_control_response(&mut client).await;
        assert!(result.is_ok());
        let control_response = result.unwrap();
        assert_eq!(250, control_response.status_code);
        assert_eq!("OK", control_response.reply);

        Ok(())
    }

    #[tokio::test]
    async fn test_read_garbled_control_response() -> Result<(), Box<dyn std::error::Error>> {
        // garbled response
        let (mut client, mut server) = create_framed_mock().await?;
        server.send("idon'tknowwhatthisis").await?;
        let result = read_control_response(&mut client).await;
        assert!(result.is_err());
        match result.err() {
            Some(TorError::ProtocolError(_)) => assert!(true),
            _ => assert!(false),
        }

        // Multiline response
        let (mut client, mut server) = create_framed_mock().await?;
        server
            .send("250-ServiceID=647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd")
            .await?;
        server.send("250-PrivateKey=ED25519-V3:yLSDc8b11PaIHTtNtvi9lNW99IME2mdrO4k381zDkHv//WRUGrkBALBQ9MbHy2SLA/NmfS7YxmcR/FY8ppRfIA==").await?;
        server.send("250 OK").await?;
        let result = read_control_response(&mut client).await;
        assert!(result.is_ok());
        let control_response = result.unwrap();
        assert_eq!(250, control_response.status_code);
        assert_eq!(
            "ServiceID=647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd\nPrivateKey=ED25519-V3:yLSDc8b11PaIHTtNtvi9lNW99IME2mdrO4k381zDkHv//WRUGrkBALBQ9MbHy2SLA/NmfS7YxmcR/FY8ppRfIA==\n",
            control_response.reply);

        Ok(())
    }

    #[tokio::test]
    async fn test_read_data_control_response() -> Result<(), Box<dyn std::error::Error>> {
        // Data response
        let (mut client, mut server) = create_framed_mock().await?;
        server.send("250+onions/current=").await?;
        server
            .send("647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd")
            .await?;
        server
            .send("yxq7fa63tthq3nd2ul52jjcdpblyai6k3cfmdkyw23ljsoob66z3ywid")
            .await?;
        server.send(".").await?;
        server.send("250 OK").await?;
        let result = read_control_response(&mut client).await;
        assert!(result.is_ok());
        let control_response = result.unwrap();
        assert_eq!(250, control_response.status_code);
        assert_eq!("onions/current=\n647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd\nyxq7fa63tthq3nd2ul52jjcdpblyai6k3cfmdkyw23ljsoob66z3ywid\n",
            control_response.reply,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_authenticate() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = create_mock().await?;
        let mut server = Framed::new(server, LinesCodec::new());
        server
            .send("250-PROTOCOLINFO 1\n250-AUTH METHODS=NULL\n250-VERSION Tor=1\n250 OK")
            .await?;
        server.send("250 OK").await?;
        let mut tor = TorControlConnection::with_stream(client)?;
        let result = tor.authenticate(TorAuthentication::Null).await;
        assert!(result.is_ok());

        let (client, server) = create_mock().await?;
        let mut server = Framed::new(server, LinesCodec::new());
        server.send("551 Oops").await?;
        let mut tor = TorControlConnection::with_stream(client)?;
        let result = tor.authenticate(TorAuthentication::Null).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_create_onion_service() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = create_mock().await?;
        let mut server = Framed::new(server, LinesCodec::new());
        server
            .send("250-ServiceID=vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad")
            .await?;
        server
            .send("250-PrivateKey=ED25519-V3:0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==")
            .await?;
        server.send("250 OK").await?;
        let mut tor = TorControlConnection::with_stream(client)?;
        let onion_service = tor
            .create_onion_service(&[OnionServiceMapping::new(8080, None)], true, None)
            .await?;
        assert_eq!(8080, onion_service.ports[0].virt_port);
        assert_eq!(
            SocketAddr::from_tcp_string("127.0.0.1:8080"),
            Ok(onion_service.ports[0].clone().listen_address)
        );
        assert_eq!(
            "vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad",
            onion_service.service_id.as_str()
        );
        assert_eq!(
            OnionAddress::from_str(
                "vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad.onion:8080"
            )?,
            onion_service.onion_address(8080).unwrap()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_protocol_info() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = create_mock().await?;
        let mut server = Framed::new(server, LinesCodec::new());
        server.send("250-PROTOCOLINFO 1").await?;
        server.send("250-AUTH METHODS=NULL,FOO").await?;
        server.send("250-VERSION Tor=\"0.4.7.13\"").await?;
        server.send("250 OK").await?;
        let mut tor = TorControlConnection::with_stream(client)?;
        tor.get_protocol_info().await?;

        Ok(())
    }

    #[test]
    fn test_parse_onion_address() -> Result<(), Box<dyn std::error::Error>> {
        let address = OnionAddress::from_str(
            "647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd.onion:80",
        )?;
        assert_eq!(
            TorServiceId::from_str("647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd")?,
            address.service_id
        );
        assert_eq!(80, address.service_port);

        if let Ok(_) = OnionAddress::from_str("foobar:27") {
            assert!(false);
        }

        if let Ok(_) = OnionAddress::from_str(
            "647qjf6w3evdbdpy7oidf5vda6rsjzsl5a6ofsaou2v77hj7dmn2spqd.onion:abcd",
        ) {
            assert!(false);
        }

        Ok(())
    }
}
