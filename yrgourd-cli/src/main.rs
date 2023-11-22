use clap::Parser;
use futures::{future, FutureExt, SinkExt, StreamExt};
use rand_chacha::rand_core::{OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;
use yrgourd::curve25519_dalek::{RistrettoPoint, Scalar};
use yrgourd::Transport;

#[derive(Debug, Parser)]
struct CliOpts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Run a plaintext echo server.
    Echo(EchoOpts),
    /// Run a plaintext connect client.
    Connect(ConnectOpts),
    /// Run a proxy which accepts plaintext clients and makes encrypted connections.
    Proxy(ProxyOpts),
    /// Run a proxy which accepts encrypted clients and makes plaintext connections.
    ReverseProxy(ReverseProxyOpts),
}

#[derive(Debug, Parser)]
struct EchoOpts {
    #[clap(long, default_value = "127.0.0.1:4040")]
    addr: String,
}

#[derive(Debug, Parser)]
struct ConnectOpts {
    #[clap(long, default_value = "127.0.0.1:6060")]
    addr: String,
}

#[derive(Debug, Parser)]
struct ProxyOpts {
    #[clap(long, default_value = "127.0.0.1:6060")]
    from: String,

    #[clap(long, default_value = "127.0.0.1:5050")]
    to: String,
}

#[derive(Debug, Parser)]
struct ReverseProxyOpts {
    #[clap(long, default_value = "127.0.0.1:5050")]
    from: String,

    #[clap(long, default_value = "127.0.0.1:4040")]
    to: String,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let opts = CliOpts::parse();
    match opts.cmd {
        Command::Echo(args) => echo(&args.addr).await,
        Command::Connect(args) => connect(&args.addr).await,
        Command::Proxy(args) => proxy(&args.from, &args.to).await,
        Command::ReverseProxy(args) => reverse_proxy(&args.from, &args.to).await,
    }
}

async fn _demo() -> io::Result<()> {
    let addr = "127.0.0.1:4040".to_string();
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    // Generate some key pairs.
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
    let server_static_priv = Scalar::random(&mut rng);
    let server_static_pub = RistrettoPoint::mul_base(&server_static_priv);
    let client_static_priv = Scalar::random(&mut rng);

    tokio::spawn(async move {
        // Connect to the server.
        let conn = TcpStream::connect(&addr).await.unwrap();

        // Initiate a handshake.
        let mut client =
            Transport::initiate_handshake(conn, OsRng, client_static_priv, server_static_pub)
                .await
                .unwrap();

        // Send a stupid message.
        client.send(Bytes::from_static(b"hey man, I'm a client")).await.unwrap();

        // Receive a stupid message;
        if let Some(Ok(packet)) = client.next().await {
            dbg!(packet);
        }

        // Disconnect.
        client.shutdown().await.unwrap()
    });
    let listening = CancellationToken::new();
    loop {
        // Wait for an incoming connection.
        tokio::select! {
            Ok((socket, _)) = listener.accept() => {
                let listening = listening.clone();
                tokio::spawn(async move {
                    // Accept the client's handshake.
                    let mut server =
                        Transport::accept_handshake(socket, OsRng, server_static_priv)
                            .await
                            .unwrap();

                    // Send a stupid message.
                    server.send(Bytes::from_static(b"it's me, a server")).await.unwrap();

                    // Receive a stream of stupid messages.
                    if let Some(Ok(packet)) = server.next().await {
                        dbg!(packet);
                    }

                    // Shut down the server.
                    listening.cancel();
                });
            },
            _ = listening.cancelled() => {
                break;
            }
        };
    }

    Ok(())
}

/// Listen for plaintext connections to `from` and make encrypted connections to `to`.
async fn proxy(from: impl ToSocketAddrs, to: impl ToSocketAddrs + Clone) -> io::Result<()> {
    // TODO add key management
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
    let server_static_priv = Scalar::random(&mut rng);
    let server_static_pub = RistrettoPoint::mul_base(&server_static_priv);
    let client_static_priv = Scalar::random(&mut rng);

    let listener = TcpListener::bind(from).await?;
    while let Ok((mut inbound, _)) = listener.accept().await {
        let outbound = TcpStream::connect(to.clone()).await?;
        let mut outbound =
            Transport::initiate_handshake(outbound, OsRng, client_static_priv, server_static_pub)
                .await?;
        tokio::spawn(async move {
            io::copy_bidirectional(&mut inbound, &mut outbound)
                .map(|r| {
                    if let Err(e) = r {
                        println!("Failed to transfer; error={}", e);
                    }
                })
                .await
        });
    }
    Ok(())
}

/// Listen for encrypted connections to `from` and make plaintext connections to `to`.
async fn reverse_proxy(from: impl ToSocketAddrs, to: impl ToSocketAddrs + Clone) -> io::Result<()> {
    // TODO add key management
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
    let server_static_priv = Scalar::random(&mut rng);

    let listener = TcpListener::bind(from).await?;
    while let Ok((inbound, _)) = listener.accept().await {
        let mut inbound = Transport::accept_handshake(inbound, OsRng, server_static_priv).await?;
        let mut outbound = TcpStream::connect(to.clone()).await?;
        tokio::spawn(async move {
            io::copy_bidirectional(&mut inbound, &mut outbound)
                .map(|r| {
                    if let Err(e) = r {
                        println!("Failed to transfer; error={}", e);
                    }
                })
                .await
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
