use crate::{
    auth::TorAuthentication,
    error::TorError,
    key::{KeyRequest, PrivateKey},
};
use futures::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use log::debug;
use regex::Regex;
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};

#[derive(Clone, Debug)]
pub struct OnionService {
    pub virt_port: u16,
    pub listen_address: String,
    pub service_id: String,
    pub address: String,
    pub private_key: PrivateKey,
}

#[derive(Debug)]
pub struct ControlResponse {
    status_code: u16,
    reply: String,
}

impl ControlResponse {
    fn new() -> Self {
        Self {
            status_code: 0,
            reply: String::new(),
        }
    }
}

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
        match MID_REGEX.captures(&line) {
            // Read Mid replies line-by-line, and append their reply lines to the reply
            Some(captures) => {
                control_response.status_code = captures["code"].parse::<u16>().unwrap();
                control_response
                    .reply
                    .push_str(&format!("{}\n", &captures["reply_line"]));
            }
            None => match DATA_REGEX.captures(&line.clone()) {
                // For Data replies, append everything between the initial line and the "." to the reply line
                Some(captures) => {
                    control_response.status_code = captures["code"].parse::<u16>().unwrap();
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
                    return Ok(control_response);
                }
                None => match END_REGEX.captures(&line) {
                    Some(captures) => {
                        control_response.status_code = captures["code"].parse::<u16>().unwrap();
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

pub(crate) async fn read_line<S: StreamExt<Item = Result<String, LinesCodecError>> + Unpin>(
    reader: &mut S,
) -> Result<String, TorError> {
    match reader.next().await {
        Some(Ok(line)) => Ok(line),
        Some(Err(error)) => Err(error.into()),
        None => Err(TorError::protocol_error("Unexpected EOF on stream")),
    }
}

fn format_onion_service_request_string(
    key_type: &str,
    key_blob: &str,
    virt_port: u16,
    listen_address: &str,
    transient: bool,
) -> String {
    let flags = if transient { "Flags=Detach" } else { "" };
    format!(
        "{}:{} {}, Port={},{}",
        key_type, key_blob, flags, virt_port, listen_address
    )
}

#[derive(Clone, Debug)]
pub struct ProtocolInfo {
    auth_methods: Vec<String>,
    cookie_file: Option<String>,
    tor_version: String,
}

pub struct TorControlConnection {
    reader: FramedRead<ReadHalf<TcpStream>, LinesCodec>,
    writer: FramedWrite<WriteHalf<TcpStream>, LinesCodec>,
    protocol_info: Option<ProtocolInfo>,
}

impl TorControlConnection {
    pub async fn connect<A: ToSocketAddrs>(addrs: A) -> Result<Self, TorError> {
        let this = Self::with_stream(TcpStream::connect(addrs).await?)?;
        Ok(this)
    }

    pub fn with_stream(stream: TcpStream) -> Result<Self, TorError> {
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: FramedRead::new(reader, LinesCodec::new()),
            writer: FramedWrite::new(writer, LinesCodec::new()),
            protocol_info: None,
        })
    }

    async fn write(&mut self, data: &str) -> Result<(), TorError> {
        self.writer.send(data).await?;
        Ok(())
    }

    async fn get_protocol_info(&mut self) -> Result<ProtocolInfo, TorError> {
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
            let captures = RE.captures(&control_response.reply).unwrap();
            let protocol_info = ProtocolInfo {
                auth_methods: captures
                    .name("auth_methods")
                    .unwrap()
                    .as_str()
                    .split(",")
                    .map(|s| s.to_string())
                    .collect(),
                cookie_file: captures.name("cookie_file").map(|c| c.as_str().to_string()),
                tor_version: captures
                    .name("tor_version")
                    .unwrap()
                    .as_str()
                    .replace("\"", ""),
            };
            self.protocol_info = Some(protocol_info.clone());
            Ok(protocol_info)
        }
    }

    pub async fn authenticate(&mut self, method: TorAuthentication) -> Result<(), TorError> {
        method.authenticate(self).await?;
        Ok(())
    }

    pub async fn send_command(
        &mut self,
        command: &str,
        arguments: Option<&str>,
    ) -> Result<ControlResponse, TorError> {
        match arguments {
            None => self.write(command).await?,
            Some(arguments) => self.write(&format!("{} {}", command, arguments)).await?,
        };
        match read_control_response(&mut self.reader).await {
            Ok(control_response) => match control_response.status_code {
                250 | 251 => Ok(control_response),
                _ => Err(TorError::ProtocolError(control_response.reply)),
            },
            Err(error) => Err(error),
        }
    }

    pub async fn create_onion_service(
        &mut self,
        virt_port: u16,
        listen_address: &str,
        transient: bool,
        key_request: KeyRequest,
    ) -> Result<OnionService, TorError> {
        // Create the request string from the arguments
        let request_string = match key_request {
            KeyRequest::RSA1024 => format_onion_service_request_string(
                "NEW",
                "RSA1024",
                virt_port,
                listen_address,
                transient,
            ),
            KeyRequest::ED25519V3 => format_onion_service_request_string(
                "NEW",
                "ED25519-V3",
                virt_port,
                listen_address,
                transient,
            ),
            KeyRequest::Best => format_onion_service_request_string(
                "NEW",
                "BEST",
                virt_port,
                listen_address,
                transient,
            ),
            KeyRequest::PrivateKey(ref private_key) => {
                let (key_type, blob) = match **private_key {
                    PrivateKey::RSA1024(_) => ("RSA1024", private_key.to_blob()),
                    PrivateKey::ED25519V3(_) => ("ED25519-V3", private_key.to_blob()),
                };
                format_onion_service_request_string(
                    key_type,
                    &blob,
                    virt_port,
                    listen_address,
                    transient,
                )
            }
        };

        // Send command to Tor controller
        let control_response = self
            .send_command("ADD_ONION", Some(&request_string))
            .await?;
        debug!(
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
            Some(captures) => {
                // Parse the Hash value
                let hash_string = &captures.name("service_id").unwrap().as_str();

                // Retrieve the key, either the one passed in or the one
                // returned from the controller
                let key = match captures.name("key_type") {
                    Some(m) => PrivateKey::from_blob(
                        m.as_str(),
                        captures.name("key_blob").unwrap().as_str(),
                    )?,
                    None => match key_request {
                        KeyRequest::PrivateKey(key) => *key,
                        _ => {
                            return Err(TorError::protocol_error(
                                "Expected key to be returned by Tor",
                            ))
                        }
                    },
                };

                // Return the Onion Service
                Ok(OnionService {
                    virt_port,
                    listen_address: listen_address.to_string(),
                    service_id: hash_string.to_string(),
                    address: format!("{}:{}", hash_string, virt_port),
                    private_key: key,
                })
            }
            None => Err(TorError::ProtocolError(format!(
                "Unexpected response: {} {}",
                control_response.status_code, control_response.reply,
            ))),
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
        // TODO: Fix this!!!
        // assert_eq!(
        //     TorError::AuthenticationError("Oops".into()),
        //     result.unwrap_err()
        // );

        Ok(())
    }

    #[tokio::test]
    async fn test_create_onion_service() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = create_mock().await?;
        let mut server = Framed::new(server, LinesCodec::new());
        server.send("250-ServiceID=foobar").await?;
        server
            .send("250-PrivateKey=ED25519-V3:VEhJU0lTTVlOSUZUWUNPT09MU1VQRVJTRUNSRVRLRVk=")
            .await?;
        server.send("250 OK").await?;
        let mut tor = TorControlConnection::with_stream(client)?;
        let onion_service = tor
            .create_onion_service(8080, "localhost:8080", true, KeyRequest::Best)
            .await?;
        assert_eq!(8080, onion_service.virt_port);
        assert_eq!("localhost:8080", onion_service.listen_address);
        assert_eq!("foobar", onion_service.service_id);
        assert_eq!("foobar:8080", onion_service.address);
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
}
