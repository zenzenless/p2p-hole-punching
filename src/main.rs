use async_std::io;
use clap::Parser;
use futures::{executor::block_on, future::Either, prelude::*, select};
use libp2p::{
    core::{multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::OrTransport, upgrade},
    dcutr,
    dns::DnsConfig,
    gossipsub, identify, identity,
    kad::{store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent},
    mdns,
    autonat,
    multiaddr::Protocol,
    noise, quic, relay,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Transport,
};
use log::info;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use std::{collections::hash_map::DefaultHasher, str::FromStr};
// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: Kademlia<MemoryStore>,
    // mdns: mdns::async_io::Behaviour,
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    relay_client: relay::client::Behaviour,
    auto_nat: autonat::Behaviour,
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // env_logger::builder().filter_level(log::LevelFilter::Info).default_format()
    //   .format(|b, r| writeln!(b, "{}:{} {}: {}", r.file().unwrap_or(""),r.line().unwrap_or(0), r.level(), r.args())).init();
    tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        .compact()
        .init();

    let opts = Opts::parse();
    // Create a random PeerId
    let id_keys = generate_ed25519(opts.secret_key_seed);
    let local_peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {local_peer_id}");
    info!("start");


    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };
    let (relay_transport, client) = relay::client::new(local_peer_id);

    let transport = {
        let relay_tcp_quic_transport = relay_transport
            .or_transport(tcp::async_io::Transport::new(
                tcp::Config::default().port_reuse(true),
            ))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&id_keys).unwrap())
            .multiplex(yamux::Config::default())
            .or_transport(quic::async_std::Transport::new(quic::Config::new(&id_keys)));
        block_on(DnsConfig::system(relay_tcp_quic_transport))
            .unwrap()
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            })
            .boxed()
    };
    // Set a custom gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
        .build()
        .expect("Valid config");

    // build a gossipsub network behaviour
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_config,
    )
    .expect("Correct configuration");
    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    gossipsub.subscribe(&topic)?;

    //set kad
    let mut cfg = KademliaConfig::default();
    cfg.set_query_timeout(Duration::from_secs(5 * 60));
    let store = MemoryStore::new(local_peer_id);
    // Create a Swarm to manage peers and events
    let mut swarm = {
        let mdns = mdns::async_io::Behaviour::new(mdns::Config::default(), local_peer_id)?;
        let behaviour = MyBehaviour {
            gossipsub,
            kad: Kademlia::with_config(local_peer_id, store, cfg),
            // mdns,
            relay: relay::Behaviour::new(local_peer_id, Default::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/TODO/0.0.1".to_string(),
                id_keys.public(),
            )),
            dcutr: dcutr::Behaviour::new(local_peer_id),
            relay_client: client,
            auto_nat:autonat::Behaviour::new(local_peer_id, Default::default()),
        };
        SwarmBuilder::with_async_std_executor(transport, behaviour, local_peer_id).build()
    };
    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    // Listen on all interfaces and whatever port the OS assigns
    if let Some(port) = opts.port {
        swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse()?)?;
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port + 1).parse()?)?;
    } else {
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    }
    // Wait to listen on all interfaces.
    block_on(async {
        let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
        loop {
            futures::select! {
                event = swarm.next() => {
                    match event.unwrap() {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {:?}", address);
                        }
                        event => info!("{:?}",event),
                    }
                }
                _ = delay => {
                    // Likely listening on all interfaces now, thus continuing by breaking the loop.
                    break;
                }
            }
        }
    });
    //futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse().await;
    // Connect to the bootstrap(relay) server. Not for the reservation or relayed connection, but to (a) learn
    // our local public address and (b) enable a freshly started relay to learn its public address.
    if let Some(bootstrap) = opts.bootstrap.clone() {
        swarm.dial(bootstrap.clone()).unwrap();
   

        println!(
            "Enter messages via STDIN and they will be sent to connected peers using Gossipsub"
        );
    }
    swarm
        .behaviour_mut()
        .kad
        .set_mode(Some(libp2p::kad::Mode::Server));
    info!("{:?}", swarm.network_info());
    // Kick it off
    loop {
        select! {
            line = stdin.select_next_some() => {
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(topic.clone(), line.expect("Stdin not to close").as_bytes()) {
                        info!("Publish error: {e:?}");
                }
            },
            event = swarm.select_next_some() => match event {
                // SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                //     for (peer_id, _multiaddr) in list {
                //         info!("mDNS discovered a new peer: {peer_id}");
                //         swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                //     }
                // },
                // SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                //     for (peer_id, _multiaddr) in list {
                //         info!("mDNS discover peer has expired: {peer_id}");
                //         swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                //     }
                // },

                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => info!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    ),
                SwarmEvent::Behaviour(MyBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => {
                    assert!(opts.mode == Mode::Listen);
                    info!("Relay accepted our reservation request.");
                },

                SwarmEvent::Behaviour(MyBehaviourEvent::Relay(event)) => {
                    info!("{:?}", event)
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Dcutr(event)) => {
                    info!("{:?}", event)
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Sent {
                    ..
                })) => {
                    println!("Told relay its public address.");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Identify(
                    identify::Event::Received {
                        info: identify::Info { observed_addr, .. },
                        ..
                    },
                )) => {
                    println!("Relay told us our public address: {:?}", observed_addr);
                    swarm.add_external_address(observed_addr);
                    if let Mode::Listen=opts.mode{
                        swarm.listen_on(opts.bootstrap.clone().unwrap().with(Protocol::P2pCircuit))
                              .unwrap();
                    };
                    if  let Mode::Dial=opts.mode{
                        swarm.dial(opts.bootstrap.clone().unwrap().with(Protocol::P2pCircuit).with(Protocol::P2p(opts.remote_peer_id.unwrap()))).unwrap();
                    };

                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Local node is listening on {address}");
                },
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    info!("Established connection to {:?} via {:?}", peer_id, endpoint);
                },
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    info!("Outgoing connection error to {:?}: {:?}", peer_id, error);
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Kad(event))=>{
                    info!("{:?}",event);

                }

                _ => {}
            }
        }
        info!("{:?}", swarm.network_info());
    }
}

#[derive(Debug, Parser)]
#[clap(name = "libp2p DCUtR client")]
struct Opts {
    /// The mode (client-listen, client-dial).
    #[clap(long)]
    mode: Mode,

    /// Fixed value to generate deterministic peer id.
    #[clap(long)]
    secret_key_seed: u8,

    /// The listening address
    #[clap(long)]
    relay_address: Option<Multiaddr>,

    /// Peer ID of the remote peer to hole punch to.
    #[clap(long)]
    remote_peer_id: Option<PeerId>,

    /// bootstrap Multiaddr
    #[clap(long)]
    bootstrap: Option<Multiaddr>,

    /// the listening port
    #[clap(long)]
    port: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Parser)]
enum Mode {
    Dial,
    Listen,
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            "dial" => Ok(Mode::Dial),
            "listen" => Ok(Mode::Listen),
            _ => Err("Expected either 'dial' or 'listen'".to_string()),
        }
    }
}
fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;

    identity::Keypair::ed25519_from_bytes(bytes).expect("only errors on wrong length")
}
