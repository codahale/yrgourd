use std::time::Duration;

use clap::Parser;
use futures::{future, FutureExt, SinkExt, StreamExt};
use rand::rngs::OsRng;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};
use yrgourd::{AllowPolicy, Initiator, PrivateKey, PublicKey, Responder};

#[derive(Debug, Parser)]
struct CliOpts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Generate a private/public key pair.
    GenerateKey,
    /// Run a plaintext echo server.
    Echo(EchoOpts),
    /// Run a plaintext connect client.
    Connect(ConnectOpts),
    /// Run a proxy which accepts plaintext clients and makes encrypted connections.
    Proxy(ProxyOpts),
    /// Run a proxy which accepts encrypted clients and makes plaintext connections.
    ReverseProxy(ReverseProxyOpts),
    /// Run a client which connects to an encrypted server and writes N bytes.
    Stream(StreamOpts),
    /// Run a server which accepts encrypted clients and reads everything.
    Sink(SinkOpts),
}

#[derive(Debug, Parser)]
struct EchoOpts {
    #[arg(long, default_value = "127.0.0.1:4040")]
    addr: String,
}

#[derive(Debug, Parser)]
struct ConnectOpts {
    #[arg(long, default_value = "127.0.0.1:6060")]
    addr: String,
}

#[derive(Debug, Parser)]
struct ProxyOpts {
    #[arg(long, default_value = "127.0.0.1:6060")]
    from: String,

    #[arg(
        long,
        default_value = "edfd7934e4d7c02d963d7ad69780e9bd1688c2a361a75b26c8ba192d0acd950d"
    )]
    private_key: PrivateKey,

    #[arg(
        long,
        default_value = "986993a6d9e6edf46877349e84ec0241ba1135c4113ac99a4dfb6e61b8c76002"
    )]
    server_public_key: PublicKey,

    #[arg(long, value_parser = humantime::parse_duration, default_value = "2m")]
    max_ratchet_time: Duration,

    #[arg(long, default_value = "104857600")]
    max_ratchet_bytes: u64,

    #[arg(long, default_value = "127.0.0.1:5050")]
    to: String,
}

#[derive(Debug, Parser)]
struct ReverseProxyOpts {
    #[arg(long, default_value = "127.0.0.1:5050")]
    from: String,

    #[arg(
        long,
        default_value = "d921552a6bc27229935a77a2b3316f624aaea9b9201876c7f4a85bb6eb929408"
    )]
    private_key: PrivateKey,

    #[arg(long)]
    allowed_clients: Vec<PublicKey>,

    #[arg(long, value_parser = humantime::parse_duration, default_value = "2m")]
    max_ratchet_time: Duration,

    #[arg(long, default_value = "104857600")]
    max_ratchet_bytes: u64,

    #[arg(long, default_value = "127.0.0.1:4040")]
    to: String,
}

#[derive(Debug, Parser)]
struct StreamOpts {
    #[arg(long, default_value = "127.0.0.1:5050")]
    addr: String,

    #[arg(default_value = "104857600")]
    n: u64,

    #[arg(
        long,
        default_value = "edfd7934e4d7c02d963d7ad69780e9bd1688c2a361a75b26c8ba192d0acd950d"
    )]
    private_key: PrivateKey,

    #[arg(
        long,
        default_value = "986993a6d9e6edf46877349e84ec0241ba1135c4113ac99a4dfb6e61b8c76002"
    )]
    server_public_key: PublicKey,

    #[arg(long, value_parser = humantime::parse_duration, default_value = "2m")]
    max_ratchet_time: Duration,

    #[arg(long, default_value = "104857600")]
    max_ratchet_bytes: u64,
}

#[derive(Debug, Parser)]
struct SinkOpts {
    #[arg(long, default_value = "127.0.0.1:5050")]
    addr: String,

    #[arg(
        long,
        default_value = "d921552a6bc27229935a77a2b3316f624aaea9b9201876c7f4a85bb6eb929408"
    )]
    private_key: PrivateKey,

    #[arg(long)]
    allowed_clients: Vec<PublicKey>,

    #[arg(long, value_parser = humantime::parse_duration, default_value = "2m")]
    max_ratchet_time: Duration,

    #[arg(long, default_value = "104857600")]
    max_ratchet_bytes: u64,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let opts = CliOpts::parse();
    match opts.cmd {
        Command::GenerateKey => generate_key(),
        Command::Echo(args) => echo(&args.addr).await,
        Command::Connect(args) => connect(&args.addr).await,
        Command::Proxy(args) => {
            proxy(
                &args.from,
                &args.to,
                args.private_key,
                args.server_public_key,
                args.max_ratchet_time,
                args.max_ratchet_bytes,
            )
            .await
        }
        Command::ReverseProxy(args) => {
            reverse_proxy(
                &args.from,
                &args.to,
                args.private_key,
                &args.allowed_clients,
                args.max_ratchet_time,
                args.max_ratchet_bytes,
            )
            .await
        }
        Command::Stream(args) => {
            stream(
                &args.addr,
                args.n,
                args.private_key,
                args.server_public_key,
                args.max_ratchet_time,
                args.max_ratchet_bytes,
            )
            .await
        }
        Command::Sink(args) => {
            sink(
                &args.addr,
                args.private_key,
                &args.allowed_clients,
                args.max_ratchet_time,
                args.max_ratchet_bytes,
            )
            .await
        }
    }
}

fn generate_key() -> io::Result<()> {
    let private_key = PrivateKey::random(OsRng);
    println!("private key = {}", private_key);
    println!("public key = {}", private_key.public_key);
    Ok(())
}

/// Listen for plaintext connections to `from` and make encrypted connections to `to`.
async fn proxy(
    from: impl ToSocketAddrs,
    to: impl ToSocketAddrs + Clone,
    client_key: PrivateKey,
    server_public_key: PublicKey,
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
) -> io::Result<()> {
    let mut initiator = Initiator::new(client_key);
    initiator.max_ratchet_time = max_ratchet_time;
    initiator.max_ratchet_bytes = max_ratchet_bytes;
    let listener = TcpListener::bind(from).await?;
    while let Ok((mut inbound, _)) = listener.accept().await {
        let outbound = TcpStream::connect(to.clone()).await?;
        let mut outbound = initiator.handshake(OsRng, outbound, server_public_key.clone()).await?;
        tokio::spawn(async move {
            io::copy_bidirectional(&mut inbound, &mut outbound)
                .map(|r| {
                    if let Err(e) = r {
                        println!("Failed to transfer; error={}", e);
                    }
                })
                .await;
        });
    }
    Ok(())
}

/// Listen for encrypted connections to `from` and make plaintext connections to `to`.
async fn reverse_proxy(
    from: impl ToSocketAddrs,
    to: impl ToSocketAddrs + Clone,
    server_key: PrivateKey,
    allowed_clients: &[PublicKey],
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
) -> io::Result<()> {
    let mut responder = Responder::new(server_key);
    responder.max_ratchet_time = max_ratchet_time;
    responder.max_ratchet_bytes = max_ratchet_bytes;

    if !allowed_clients.is_empty() {
        responder.allow_policy =
            AllowPolicy::AllowedInitiators(allowed_clients.iter().cloned().collect());
    }

    let listener = TcpListener::bind(from).await?;
    while let Ok((inbound, _)) = listener.accept().await {
        let mut inbound = responder.handshake(OsRng, inbound).await?;
        let mut outbound = TcpStream::connect(to.clone()).await?;
        tokio::spawn(async move {
            io::copy_bidirectional(&mut inbound, &mut outbound)
                .map(|r| {
                    if let Err(e) = r {
                        println!("Failed to transfer; error={}", e);
                    }
                })
                .await;
        });
    }
    Ok(())
}

/// Listen for TCP connections to the given address and echo back all received data.
async fn echo(addr: impl ToSocketAddrs) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let n = socket.read(&mut buf).await.expect("should read data from socket");
                if n == 0 {
                    return;
                }
                println!("echoing {:?}", &buf[..n]);
                socket.write_all(&buf[..n]).await.expect("should write data to socket");
            }
        });
    }
}

/// Listen for TCP connections to the given address and read all data.
async fn sink(
    addr: impl ToSocketAddrs,
    server_key: PrivateKey,
    allowed_clients: &[PublicKey],
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let mut responder = Responder::new(server_key);
    responder.max_ratchet_time = max_ratchet_time;
    responder.max_ratchet_bytes = max_ratchet_bytes;
    if !allowed_clients.is_empty() {
        responder.allow_policy =
            AllowPolicy::AllowedInitiators(allowed_clients.iter().cloned().collect());
    }
    loop {
        let (socket, _) = listener.accept().await?;
        let mut conn = responder.handshake(OsRng, socket).await?;
        tokio::spawn(async move {
            io::copy(&mut conn, &mut io::sink()).await.expect("should copy everything");
            conn.shutdown().await.expect("should close the socket");
        });
    }
}

/// Connect to the given address and write the given number of bytes to it.
async fn stream(
    addr: impl ToSocketAddrs,
    n: u64,
    client_key: PrivateKey,
    server_public_key: PublicKey,
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
) -> io::Result<()> {
    let mut initiator = Initiator::new(client_key);
    initiator.max_ratchet_time = max_ratchet_time;
    initiator.max_ratchet_bytes = max_ratchet_bytes;
    let socket = TcpStream::connect(addr).await?;
    let mut conn = initiator.handshake(OsRng, socket, server_public_key).await?;
    io::copy_buf(&mut BufReader::with_capacity(64 * 1024, io::repeat(0x4f).take(n)), &mut conn)
        .await?;
    conn.shutdown().await
}

/// Connect to the given TCP address and pipe stdin/stdout.
async fn connect(addr: impl ToSocketAddrs) -> io::Result<()> {
    let stdin = FramedRead::new(io::stdin(), BytesCodec::new());
    let mut stdin = stdin.map(|i| i.map(|bytes| bytes.freeze()));
    let mut stdout = FramedWrite::new(io::stdout(), BytesCodec::new());

    let mut stream = TcpStream::connect(addr).await?;
    let (r, w) = stream.split();
    let mut sink = FramedWrite::new(w, BytesCodec::new());
    let mut stream = FramedRead::new(r, BytesCodec::new())
        .filter_map(|i| match i {
            Ok(i) => future::ready(Some(i.freeze())),
            Err(e) => {
                println!("failed to read from socket; error={}", e);
                future::ready(None)
            }
        })
        .map(Ok);
    match future::join(sink.send_all(&mut stdin), stdout.send_all(&mut stream)).await {
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}
