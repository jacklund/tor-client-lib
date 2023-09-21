use lazy_static::lazy_static;
use repl_rs::{Command, Parameter, Result, Value};
use repl_rs::{Convert, Repl};
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tor_client_lib::{
    auth::TorAuthentication, control_connection::TorControlConnection, key::KeyRequest,
};

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

fn protocol_info(_args: HashMap<String, Value>, context: &mut Context) -> Result<Option<String>> {
    let connection: &mut TorControlConnection = match &mut context.connection {
        Some(connection) => connection,
        None => {
            return Ok(Some(
                "Error: you must connect first with the 'connect' command".to_string(),
            ))
        }
    };

    match RUNTIME.block_on(connection.get_protocol_info()) {
        Ok(protocol_info) => {
            let auth_methods = protocol_info.auth_methods.join(", ");
            let cookie_file_string = match protocol_info.cookie_file {
                Some(cookie_file) => {
                    format!("Cookie file location: {}\n", cookie_file)
                }
                None => String::new(),
            };
            let tor_version = protocol_info.tor_version;
            Ok(Some(format!(
                "Allowed authentication methods: {}\n{}TOR version: {}",
                auth_methods, cookie_file_string, tor_version,
            )))
        }
        Err(error) => Ok(Some(format!("Error getting protocol info: {}", error))),
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

fn add_onion_service(
    args: HashMap<String, Value>,
    context: &mut Context,
) -> Result<Option<String>> {
    let connection: &mut TorControlConnection = match &mut context.connection {
        Some(connection) => connection,
        None => {
            return Ok(Some(
                "Error: you must connect first with the 'connect' command".to_string(),
            ))
        }
    };

    let virt_port = args.get("virt_port").unwrap().convert()?;
    let listen_address = args.get("listen_address").unwrap().to_string();
    let transient = match args.get("transient") {
        Some(value) => match value.to_string().parse::<bool>() {
            Ok(transient) => transient,
            Err(error) => return Ok(Some(format!("Error parsing transient value: {}", error))),
        },
        None => true,
    };

    match RUNTIME.block_on(connection.create_onion_service(
        virt_port,
        &listen_address,
        transient,
        KeyRequest::Best,
    )) {
        Ok(service) => {
            println!(
                "public key: {}",
                hex::encode(service.private_key.public_key().to_vec().unwrap())
            );
            Ok(Some(format!(
                "Onion service with service ID '{}' created",
                service.service_id
            )))
        }
        Err(error) => Ok(Some(format!("Error creating onion service: {}", error))),
    }
}

fn delete_onion_service(
    args: HashMap<String, Value>,
    context: &mut Context,
) -> Result<Option<String>> {
    let connection: &mut TorControlConnection = match &mut context.connection {
        Some(connection) => connection,
        None => {
            return Ok(Some(
                "Error: you must connect first with the 'connect' command".to_string(),
            ))
        }
    };

    let service_id = args.get("service_id").unwrap().to_string();

    match RUNTIME.block_on(connection.delete_onion_service(&service_id)) {
        Ok(_) => Ok(Some(format!(
            "Onion service with service ID '{}' deleted",
            service_id
        ))),
        Err(error) => Ok(Some(format!("Error deleting onion service: {}", error))),
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
        )
        .add_command(Command::new("protocol_info", protocol_info).with_help("Get protocol info"))
        .add_command(
            Command::new("add_onion_service", add_onion_service)
                .with_parameter(Parameter::new("virt_port").set_required(true)?)?
                .with_parameter(Parameter::new("listen_address").set_required(true)?)?
                .with_parameter(Parameter::new("transient").set_default("true")?)?
                .with_help("Create an onion service"),
        )
        .add_command(
            Command::new("delete_onion_service", delete_onion_service)
                .with_parameter(Parameter::new("service_id").set_required(true)?)?
                .with_help("Delete an onion service"),
        );

    repl.run()
}
