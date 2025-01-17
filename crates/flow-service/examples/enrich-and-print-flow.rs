use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{stream::SplitSink, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};

use std::env;
use std::net::IpAddr;
use chrono::Utc;
use netgauze_flow_pkt::{ie, ie::*, ipfix::*, codec::FlowInfoCodec, FlowInfo, FieldSpecifier};

use reqwest::Client;
use serde_json::{json, Value};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

// For parallel processing
use tokio::task;
use tokio::sync::mpsc;

// deps for vrf binding
use std::ffi::OsString;
use nix::sys::socket::{setsockopt, sockopt::BindToDevice};

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // .with_max_level(tracing::Level::TRACE)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}




// Draft for Hackathon - Store option data and enrich flow records with it
// - only supporting sampling option for now
// fn option_enrichment(pkt: FlowInfo) -> FlowInfo {
//     // Steps TODO:
//     // - v9/v10 discriminate
//     // - detect if we have a template or a data record
//     // - if data record: detect if we have an option data record or a flow record
//     // - if option: store data in hashmap
//     // - if flow: enrich based on option data from hashmap
//     // (for now only limit on sampling option, recognize based on fields...)¨

//     // For now only consider IPFIX v10
//     match pkt {
//         FlowInfo::NetFlowV9(ref _netflow_pkt) => pkt,
//         FlowInfo::IPFIX(ref ipfix_pkt) => {
//             for set in ipfix_pkt.sets() {
//                 match set {
//                     Set::Data { id: _, records: _ } => {
//                         if set.contains_option_data_records() {
//                             //option_data_cache_handler(&set);
//                         } else {
//                             //let pkt = flow_records_enrich(pkt);
//                         }
//                     }
//                     _ => {}
//                 }
//             }
//             pkt
//         }
//     }
// }

fn feldera_enrichment(json_pkt: &str, socket_ip: IpAddr) -> String {
  // Parse the input JSON string
  let parsed_pkt: Value = serde_json::from_str(json_pkt).unwrap();

  let ts = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
  // Create the new JSON structure
  let wrapped_pkt = json!({
      "insert": {
          "ts": ts,
          "peer_src": socket_ip.to_string(),
          "writer_id": "NetGauze@taarole8-rocky8.bblab.ch",
          "payload": parsed_pkt
      }
  });

  // Serialize the new JSON object back to a string
  serde_json::to_string(&wrapped_pkt).unwrap()
}


// fn append_netgauze_internals(pkt: FlowInfo, socket_ip: IpAddr) -> FlowInfo {
//         let (socket_ip_spec, socket_ip_field) = match socket_ip {
//                 IpAddr::V4(ipv4) => (
//                         FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::peerIPv4Address), 4).unwrap(),
//                         ie::Field::NetGauze(netgauze::Field::peerIPv4Address(netgauze::peerIPv4Address(ipv4))),
//                 ),
//                 IpAddr::V6(ipv6) => (
//                         FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::peerIPv6Address), 16).unwrap(),
//                         ie::Field::NetGauze(netgauze::Field::peerIPv6Address(netgauze::peerIPv6Address(ipv6))),
//                 ),
//         };

//         let hostname_spec = FieldSpecifier::new(
//                 ie::IE::NetGauze(netgauze::IE::collectorHostname),
//                 65535,
//         ).unwrap();
//         let hostname = env::var("HOSTNAME").unwrap_or_else(|_| String::from("unknown"));
//         let hostname_field = ie::Field::NetGauze(
//                 netgauze::Field::collectorHostname(netgauze::collectorHostname(hostname)),
//         );

//         let timestamp_spec = FieldSpecifier::new(
//                 ie::IE::NetGauze(netgauze::IE::timestampArrival),
//                 4,
//         ).unwrap();
//         let timestamp_field = ie::Field::NetGauze(
//                 netgauze::Field::timestampArrival(netgauze::timestampArrival(Utc::now())),
//         );

//         pkt.append_ie(&socket_ip_spec, &socket_ip_field)
//            .append_ie(&hostname_spec, &hostname_field)
//            .append_ie(&timestamp_spec, &timestamp_field)
// }

async fn send_post_request(json_pkt: &str) -> Result<(), reqwest::Error> {
  let client = Client::new();
  // let res = client.post("http://localhost:8080/ingress/flows?format=json")
  // let res = client.post("http://localhost:8080/v0/pipelines/test/ingress/flows?format=json")
  let res = client.post("http://localhost:8080/v0/pipelines/vmware/ingress/flows?format=json")
      .header("Content-Type", "application/json")
      .body(json_pkt.to_string())
      .send()
      .await?;

  tracing::trace!("Response: {:?}", res);
  Ok(())
}

async fn write_json_to_file(json_pkt: &str) {
  let mut file = OpenOptions::new()
      .create(true)
      .append(true)
      .open("ng-output.json")
      .await
      .expect("Unable to open file");

  let json_with_newline = format!("{}\n", json_pkt);

  if let Err(e) = file.write_all(json_with_newline.as_bytes()).await {
        tracing::error!("Error writing to file: {:?}", e);
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {

    // Initialize/truncate the output json file at the start
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("ng-output.json")
        .await
        .expect("Unable to initialize file");

    init_tracing();

    let listen_addr = ":::9991";
    let socket = UdpSocket::bind(&listen_addr).await?;

    // VMWare VRF binding
    // Set the SO_BINDTODEVICE option to bind the socket to a specific VRF
    let vrf = OsString::from("vrf-dev");
    setsockopt(&socket, BindToDevice, &vrf).expect("Failed to bind to VRF");

    println!("Listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let clients = Arc::new(DashMap::new());

    let mut json_batch = Vec::new();
    let json_batch_size = 500; // 200-500 for high speed

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
                        // let pkt = append_netgauze_internals(pkt, addr.ip());
                        // let pkt = option_enrichment(pkt);

                        let json_pkt = serde_json::to_string(&pkt).unwrap();
                        let json_pkt = feldera_enrichment(&json_pkt, addr.ip());

                        // Add JSON message to batch
                        json_batch.push(json_pkt);

                        // If batch size is reached, send POST request
                        if json_batch.len() >= json_batch_size {
                            let json_batch_string = json_batch.join("\n");
                            if let Err(e) = send_post_request(&json_batch_string).await {
                                tracing::error!("Error sending POST request: {:?}", e);
                            }
                            json_batch.clear();
                        }

                        // Write JSON message to file
                        // write_json_to_file(&json_pkt).await;

                        //Log the json message
                        // tracing::info!("{}", json_pkt)
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


// // MULTI-THREADING VERSION (draft)
// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//   // Initialize/truncate the output json file at the start
//   OpenOptions::new()
//       .create(true)
//       .write(true)
//       .truncate(true)
//       .open("ng-output.json")
//       .await
//       .expect("Unable to initialize file");

//   init_tracing();

//   let listen_addr = ":::9992";
//   let socket = UdpSocket::bind(&listen_addr).await?;

//   println!("Listening on addr: {}", listen_addr);

//   let framed = UdpFramed::new(socket, BytesCodec::default());
//   let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
//   let clients = Arc::new(DashMap::new());

//   let (tx, mut rx) = mpsc::channel(100);

//   // Spawn a task to handle incoming packets
//   task::spawn(async move {
//       while let Some(next) = stream.next().await {
//           match next {
//               Ok((buf, addr)) => {
//                   let tx = tx.clone();
//                   task::spawn(async move {
//                       tx.send((buf, addr)).await.unwrap();
//                   });
//               }
//               Err(err) => {
//                   tracing::error!("Error getting next packet: {:?}, exiting", err);
//                   break;
//               }
//           }
//       }
//   });

//   // Process packets concurrently
//   while let Some((mut buf, addr)) = rx.recv().await {
//       let clients = clients.clone();
//       task::spawn(async move {
//           let result = clients
//               .entry(addr)
//               .or_insert(FlowInfoCodec::default())
//               .decode(&mut buf);
//           match result {
//               Ok(Some(pkt)) => {
//                   let json_pkt = serde_json::to_string(&pkt).unwrap();
//                   let json_pkt = feldera_enrichment(&json_pkt, addr.ip());

//                   if let Err(e) = send_post_request(&json_pkt).await {
//                       tracing::error!("Error sending POST request: {:?}", e);
//                   }
//               }
//               Ok(None) => {
//                   println!("Stream closed, exiting");
//               }
//               Err(err) => tracing::error!("Error decoding packet: {:?}", err),
//           }
//       });
//   }

//   Ok(())
// }