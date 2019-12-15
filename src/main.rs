pub(crate) mod cert;
pub(crate) mod verifier;
pub(crate) mod endpoint;

use endpoint::EndpointError;

use futures::{future::TryFutureExt, stream::StreamExt};

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
};

const SERVER_PORT: u16 = 5000;

async fn run_server<A: ToSocketAddrs>(addr: A) -> Result<(), Box<dyn Error>> {
    use EndpointError::*;

    let (driver, mut incoming) = endpoint::make_server_endpoint(addr)?;

    // drive UDP socket
    tokio::spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));

    // accept a single connection
    let incoming_conn = incoming.next().await.ok_or(NoConnection)?;
    let new_conn = incoming_conn.await?;

    println!(
        "[server] connection accepted: id={} addr={}",
        new_conn.connection.remote_id(),
        new_conn.connection.remote_address()
    );

    let peer_certs = new_conn.connection.peer_der_certificates().ok_or(NoPeerCertificates)?;
    let peer_pk =  cert::verify_cert_ext(&peer_certs[0])?;
    println!("[server] peer public key: {:?}", peer_pk);

    // Drive the connection to completion
    if let Err(e) = new_conn.driver.await {
        println!("[server] connection lost: {}", e);
    }

    Ok(())
}

async fn run_client<A: ToSocketAddrs>(addr: A, server_port: u16) -> Result<(), Box<dyn Error>> {
    use EndpointError::*;

    let (driver, endpoint) = endpoint::make_client_endpoint(addr)?;

    // drive UDP socket
    tokio::spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), server_port));

    // connect to server
    let new_conn = endpoint.connect(&server_addr, "localhost")?.await?;

    println!(
        "[client] connected: id={}, addr={}",
        new_conn.connection.remote_id(),
        new_conn.connection.remote_address()
    );

    let peer_certs = new_conn.connection.peer_der_certificates().ok_or(NoPeerCertificates)?;
    let peer_pk =  cert::verify_cert_ext(&peer_certs[0])?;
    println!("[client] peer public key: {:?}", peer_pk);

    // Dropping handles allows the corresponding objects to automatically shut down
    drop((endpoint, new_conn.connection));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // server and client are running on the same thread asynchronously
    let handle = tokio::spawn(async move {
        if let Err(err) = run_server(("0.0.0.0", SERVER_PORT)).await {
            println!("server error: {}", err);
        }

        Ok::<(), ()>(())
    });

    run_client(("0.0.0.0", 0), SERVER_PORT).await?;

    if let Err(err) = handle.await? {
        println!("spawn error {:?}", err);
    }

    Ok(())
}

