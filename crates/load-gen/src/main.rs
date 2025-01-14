use anyhow::Context;
use std::{
    fs::read_to_string,
    ops::Add,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{task::JoinHandle, time};

use clap::Parser;
use tokio_util::sync::CancellationToken;

use netgauze_flow_pkt::FlowInfo;
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    broker: String,

    #[arg(short, long)]
    topic: String,

    #[arg(short, long)]
    frequency: u64,

    #[arg(short, long)]
    client_count: u64,

    #[arg(short, long)]
    limit: u64,

    #[arg(short, long)]
    input: String,
}


pub fn serialize_dt<S>(dt: &chrono::DateTime<chrono::Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    dt.format("%Y-%m-%d %H:%M:%S")
        .to_string()
        .serialize(serializer)
}

#[derive(Debug, serde::Serialize)]
struct KafkaFlowMessage {
    #[serde(serialize_with = "serialize_dt")]
    ts: chrono::DateTime<chrono::Utc>,
    peer_src: String,
    payload: FlowInfo,
    writer_id: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn start_sender(
    broker: String,
    topic: String,
    peer_src: String,
    frequency: u64,
    buffers: &[FlowInfo],
    counter: Arc<AtomicU64>,
    total_counter: Arc<AtomicU64>,
    limit: u64,
    client_cancel: CancellationToken,
) -> anyhow::Result<()> {
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", broker)
        .set("message.timeout.ms", "5000")
        .set("compression.type", "gzip")
        .create()
        .expect("Producer creation error");

    let mut interval = time::interval(Duration::from_millis(1000 / frequency));
    let mut index = 0;
    // let mut ts = chrono::Utc::now() - chrono::Duration::days(30);
    while !client_cancel.is_cancelled() {
        interval.tick().await;
        if total_counter.load(Ordering::Relaxed) >= limit {
            break;
        }
        let buf = &buffers[index];
        let msg = KafkaFlowMessage {
            ts: chrono::Utc::now(),
            peer_src: peer_src.clone(),
            payload: buf.clone(),
            writer_id: "load-gen".to_string(),
        };
        let payload = serde_json::to_string(&msg)?;
        let produce_future = producer.send(
            FutureRecord::to(&topic)
                .key(&msg.peer_src)
                .payload(&payload),
            Duration::from_secs(0),
        );
        match produce_future.await {
            // Ok(delivery) => println!("Sent: {:?}", delivery),
            Ok(delivery) => {},
            Err((e, _)) => println!("Error: {:?}", e),
        }
        counter.fetch_add(1, Ordering::Relaxed);
        total_counter.fetch_add(1, Ordering::Relaxed);
        index += 1;
        if index >= buffers.len() {
            index = 0;
            // ts = ts.add(Duration::from_secs(60));
        }
    }
    //tracing::info!("Client shutdown");
    Ok(())
}

fn read_input(file_path: String) -> anyhow::Result<Vec<FlowInfo>> {
    let mut ret = vec![];
    for line in read_to_string(file_path.as_str())?.lines() {
        let pkt: FlowInfo = serde_json::from_str(line)
            .with_context(|| format!("Cannot parse flow info from {file_path}"))?;
        ret.push(pkt);
    }
    Ok(ret)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to setup tracing subscriber")?;

    let broker = args.broker.clone();
    let topic = args.topic.clone();
    eprintln!("Broker {broker} and topic: topic");

    let limit = args.limit;
    let cancel = CancellationToken::new();
    let buffers = read_input(args.input)?;

    tracing::info!(
        "Starting client count: {}, connecting to {} and topic {}, sending with frequency:{} and input size: {}",
        args.client_count,
        broker,
        topic,
        args.frequency,
        buffers.len(),
    );

    let client_count = args.client_count;
    let sent_counter = Arc::new(AtomicU64::new(0));
    let total_sent_counter = Arc::new(AtomicU64::new(0));

    let joins = (0..client_count)
        .map(|i| {
            let buffers = buffers.clone();
            let client_cancel = cancel.clone();
            let counter_clone = sent_counter.clone();
            let total_sent_counter_clone = total_sent_counter.clone();
            let broker = broker.clone();
            let topic = topic.clone();
            let peer_src = format!("10.0.0.{i}:{i}").to_string();
            tokio::spawn(async move {
                start_sender(
                    broker,
                    topic,
                    peer_src,
                    args.frequency,
                    &buffers,
                    counter_clone,
                    total_sent_counter_clone,
                    limit,
                    client_cancel,
                )
                    .await
            })
        })
        .collect::<Vec<JoinHandle<anyhow::Result<()>>>>();

    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let sent_count = sent_counter.swap(0, Ordering::Relaxed);
                let total = total_sent_counter.load(Ordering::Relaxed);
                tracing::info!("sent {}, total sent: {}", sent_count, total);
                if total >= limit {
                    tracing::info!("Limit reached sleeping for one second before shutting down");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    cancel.cancel();
                    break;
                }
            }

            _ = cancel.cancelled() => {
                break;
            }
        }
    }

    for join in joins {
        join.await??;
    }

    let sent_count = sent_counter.swap(0, Ordering::Relaxed);
    //let total = total_sent_counter.fetch_add(sent_count, Ordering::Relaxed);
    let total = total_sent_counter.load(Ordering::Relaxed);
    let diff = total as i64 - limit as i64;
    tracing::info!(
        "Final tally: sent {}, total sent: {} with (total sent - limit) = {}",
        sent_count,
        total,
        diff
    );

    Ok(())
}
