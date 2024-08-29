use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{stream::SplitSink, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};

use netgauze_flow_pkt::{codec::FlowInfoCodec, ipfix::*, *};

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

// Draft for Hackathon - Store option data and enrich flow records with it
// - only supporting sampling option for now
fn option_enrichment(pkt: FlowInfo) -> FlowInfo {
    // Steps TODO:
    // - v9/v10 discriminate
    // - detect if we have a template or a data record
    // - if data record: detect if we have an option data record or a flow record
    // - if option: store data in hashmap
    // - if flow: enrich based on option data from hashmap
    // (for now only limit on sampling option, recognize based on fields...)¨

    // For now only consider IPFIX v10
    match pkt {
        FlowInfo::NetFlowV9(ref _netflow_pkt) => pkt,
        FlowInfo::IPFIX(ref ipfix_pkt) => {
            for set in ipfix_pkt.sets() {
                match set {
                    Set::Data { id: _, records: _ } => {
                        if set.contains_option_data_records() {
                            //option_data_cache_handler(&set);
                        } else {
                            //let pkt = flow_records_enrich(pkt);
                        }
                    }
                    _ => {}
                }
            }
            pkt
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    let listen_addr = ":::9992";
    let socket = UdpSocket::bind(&listen_addr).await?;
    println!("Listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let clients = Arc::new(DashMap::new());
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                // If we haven't seen the client before, create a new FlowInfoCodec for it.
                // FlowInfoCodec handles the decoding/encoding of packets and caches
                // the templates learned from the client
                let result = clients
                    .entry(addr)
                    .or_insert(FlowInfoCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(pkt)) => {
                        let pkt = option_enrichment(pkt);
                        tracing::info!("{}", serde_json::to_string(&pkt).unwrap())
                    }
                    Ok(None) => {
                        println!("Stream closed, exiting");
                        return Ok(());
                    }
                    Err(err) => tracing::error!("Error decoding packet: {:?}", err),
                }
            }
            Err(err) => {
                tracing::error!("Error getting next packet: {:?}, exiting", err);
                return Ok(());
            }
        }
    }
    Ok(())
}
