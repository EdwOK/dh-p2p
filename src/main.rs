use clap::Parser;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot},
    time::{timeout, Duration},
};

use crate::{
    dh::p2p_handshake,
    process::{dh_reader, dh_writer, process_reader, process_writer},
    ptcp::PTCPEvent,
};

mod dh;
mod process;
mod ptcp;

/// Give up on the P2P handshake after this long (it has no timeout of its own).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// Exit when nothing has been received from the device for this long.
const SESSION_TIMEOUT_SECS: u64 = 30;
/// Give up on a single connection's Bind after this long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(about = "A PoC implementation of TCP tunneling over Dahua P2P protocol.", long_about = None)]
struct Cli {
    /// Bind address, port and remote port; repeat for several ports over one
    /// session. Default: 127.0.0.1:1554:554
    #[arg(short, long, value_name = "[bind_address:]port:remote_port")]
    port: Vec<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Serial number of the camera
    serial: String,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_port(port: &str) -> (String, u16, u16) {
    let parts: Vec<&str> = port.split(':').collect();
    match parts.len() {
        2 => (
            "127.0.0.1".to_string(),
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
        ),
        3 => (
            parts[0].to_string(),
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        ),
        _ => panic!("Invalid port specification"),
    }
}

type Channels = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;
type ConnChannels = Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>;

async fn accept_loop(
    listener: TcpListener,
    remote_port: u16,
    dh_tx: mpsc::Sender<PTCPEvent>,
    channels: Channels,
    conn_channels: ConnChannels,
) {
    loop {
        let (client, addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                println!("Accept failed: {}", e);
                continue;
            }
        };
        println!("Accepted connection from {} for port {}", addr, remote_port);

        let dh_tx = dh_tx.clone();
        let channels = channels.clone();
        let conn_channels = conn_channels.clone();

        // Set up each connection in its own task so a slow Bind never blocks
        // other connections.
        tokio::spawn(async move {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
            let (conn_tx, conn_rx) = oneshot::channel::<bool>();

            let realm_id = rand::random::<u32>();

            channels.lock().unwrap().insert(realm_id, tx);
            conn_channels.lock().unwrap().insert(realm_id, conn_tx);

            if dh_tx
                .send(PTCPEvent::Connect(realm_id, remote_port.into()))
                .await
                .is_err()
            {
                return;
            }

            if !matches!(timeout(CONNECT_TIMEOUT, conn_rx).await, Ok(Ok(true))) {
                println!(
                    "Realm {:08x}: device did not accept port {}",
                    realm_id, remote_port
                );
                channels.lock().unwrap().remove(&realm_id);
                conn_channels.lock().unwrap().remove(&realm_id);
                return;
            }

            let (reader, writer) = client.into_split();

            tokio::spawn(async move {
                process_reader(reader, realm_id, dh_tx).await;
            });

            process_writer(writer, rx).await;
        });
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let serial = args.serial;
    let ports = if args.port.is_empty() {
        vec!["127.0.0.1:1554:554".to_string()]
    } else {
        args.port
    };

    // Bind every listener before the handshake so a port clash fails fast.
    let mut listeners = Vec::new();
    for port in &ports {
        let (bind_address, bind_port, remote_port) = parse_port(port);
        let listener = TcpListener::bind(format!("{}:{}", bind_address, bind_port))
            .await
            .unwrap();
        listeners.push((listener, bind_address, bind_port, remote_port));
    }

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    let (socket, session) =
        match timeout(HANDSHAKE_TIMEOUT, p2p_handshake(socket, serial, args.relay)).await {
            Ok(r) => r,
            Err(_) => {
                println!("P2P handshake timed out");
                std::process::exit(1);
            }
        };

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let session = Arc::new(Mutex::new(session));

    let channels: Channels = Arc::new(Mutex::new(HashMap::new()));
    let conn_channels: ConnChannels = Arc::new(Mutex::new(HashMap::new()));
    let last_rx = Arc::new(AtomicU64::new(now_secs()));

    println!("PTCP session established");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();

    let session2 = session.clone();
    let channels2 = channels.clone();
    let conn_channels2 = conn_channels.clone();
    let last_rx2 = last_rx.clone();

    let hb_tx = dh_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let idle = now_secs().saturating_sub(last_rx2.load(Ordering::Relaxed));
            if idle > SESSION_TIMEOUT_SECS {
                println!("No data from device for {}s, session lost", idle);
                std::process::exit(2);
            }

            if hb_tx.send(PTCPEvent::Heartbeat).await.is_err() {
                println!("Writer stopped, session lost");
                std::process::exit(2);
            }
        }
    });

    tokio::spawn(async move {
        dh_writer(session, writer, dh_rx).await;
    });

    tokio::spawn(async move {
        dh_reader(session2, reader, channels, conn_channels, last_rx).await;
        println!("Reader stopped, session lost");
        std::process::exit(2);
    });

    println!("Ready to connect!");

    let mut tasks = Vec::new();
    for (listener, bind_address, bind_port, remote_port) in listeners {
        println!("Forwarding {}:{} -> device:{}", bind_address, bind_port, remote_port);
        if remote_port == 554 {
            println!(
                "RTSP URL: rtsp://127.0.0.1{}/cam/realmonitor?channel=1&subtype=0",
                if bind_port != 554 {
                    format!(":{}", bind_port)
                } else {
                    String::new()
                }
            );
        }
        tasks.push(tokio::spawn(accept_loop(
            listener,
            remote_port,
            dh_tx.clone(),
            channels2.clone(),
            conn_channels2.clone(),
        )));
    }

    for task in tasks {
        let _ = task.await;
    }
}
