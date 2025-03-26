use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tor_client_lib::{
    control_connection::OnionServiceMapping, TorAuthentication, TorControlConnection,
    TorEd25519SigningKey, TorServiceId,
};

#[tokio::test]
async fn test_create_onion_service_from_ed25519_key() -> Result<()> {
    let mut connection = TorControlConnection::connect("127.0.0.1:9051").await?;
    connection.authenticate(&TorAuthentication::Null).await?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let tor_signing_key: TorEd25519SigningKey = signing_key.clone().into();
    let verifying_key = tor_signing_key.verifying_key();
    let onion_service = connection
        .create_onion_service(
            &[OnionServiceMapping::new(3000, None)],
            true,
            Some(tor_signing_key),
        )
        .await?;

    assert_eq!(signing_key.verifying_key(), verifying_key);
    let signing_key_service_id: TorServiceId = signing_key.verifying_key().into();
    assert_eq!(onion_service.service_id(), &signing_key_service_id);

    Ok(())
}

#[tokio::test]
async fn test_create_onion_service_no_key() -> Result<()> {
    let mut connection = TorControlConnection::connect("127.0.0.1:9051").await?;
    connection.authenticate(&TorAuthentication::Null).await?;
    connection
        .create_onion_service(&[OnionServiceMapping::new(3000, None)], true, None)
        .await?;

    Ok(())
}
