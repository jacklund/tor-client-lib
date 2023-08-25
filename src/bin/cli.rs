use lazy_static::lazy_static;
use repl_rs::{Command, Parameter, Result, Value};
use repl_rs::{Convert, Repl};
use rpassword;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tor_client_lib::{auth::TorAuthentication, control_connection::TorControlConnection};

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[derive(Default)]
struct Context {
    connection: Option<TorControlConnection>,
}

// Connect to the Tor server
fn connect(args: HashMap<String, Value>, context: &mut Context) -> Result<Option<String>> {
    let host_port: String = args.get("host_port").unwrap().convert()?;
    match RUNTIME.block_on(TorControlConnection::connect(host_port.clone())) {
        Ok(connection) => {
            context.connection = Some(connection);
            Ok(Some(format!("Connected to {}", host_port)))
        }
        Err(error) => Ok(Some(format!(
            "Error connecting to {}: {}",
            host_port, error
        ))),
    }
}

fn authenticate(args: HashMap<String, Value>, context: &mut Context) -> Result<Option<String>> {
    let connection: &mut TorControlConnection = match &mut context.connection {
        Some(connection) => connection,
        None => {
            return Ok(Some(
                "Error: you must connect first with the 'connect' command".to_string(),
            ))
        }
    };
    let auth_type: String = args.get("auth_type").unwrap().convert()?;
    match auth_type.as_str() {
        "null" => match RUNTIME.block_on(connection.authenticate(TorAuthentication::Null)) {
            Ok(()) => Ok(Some("Authenticated".to_string())),
            Err(error) => Ok(Some(format!("Authentication error: {}", error))),
        },
        "password" => {
            let password = rpassword::prompt_password("Tor password: ").unwrap();
            match RUNTIME
                .block_on(connection.authenticate(TorAuthentication::HashedPassword(password)))
            {
                Ok(()) => Ok(Some("Authenticated".to_string())),
                Err(error) => Ok(Some(format!("Authentication error: {}", error))),
            }
        }
        "cookie" => {
            match RUNTIME.block_on(connection.authenticate(TorAuthentication::SafeCookie(None))) {
                Ok(()) => Ok(Some("Authenticated".to_string())),
                Err(error) => Ok(Some(format!("Authentication error: {}", error))),
            }
        }
        _ => Ok(Some(format!("Unknown auth type '{}'", auth_type))),
    }
}

pub fn main() -> Result<()> {
    env_logger::init();
    let mut repl = Repl::new(Context::default())
        .with_name("Tor CLI")
        .with_version("v0.1.0")
        .with_description("Run commands on a Tor server from the command line")
        .add_command(
            Command::new("connect", connect)
                .with_parameter(Parameter::new("host_port").set_required(true)?)?
                .with_help("Connect to the Tor server at the given host and port"),
        )
        .add_command(
            Command::new("authenticate", authenticate)
                .with_parameter(Parameter::new("auth_type").set_required(true)?)?
                .with_help("Authenticate to the Tor server using the specified auth method"),
        );

    repl.run()
}
