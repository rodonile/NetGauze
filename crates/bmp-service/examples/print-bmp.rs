// Copyright (C) 2022-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use netgauze_bmp_service::handle::BmpServerHandle;
use netgauze_bmp_service::server::{BmpRequest, BmpServer, BmpServerResponse};
use shadow_rs::shadow;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tower::buffer::Buffer;
use tower::{ServiceBuilder, service_fn};
use tracing::info;

shadow!(build);

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn log_info() {
    info!(
        r#"

  __/\\\\\_____/\\\__________________________________/\\\\\\\\\\\\___________________________________________________________
  _\/\\\\\\___\/\\\________________________________/\\\//////////____________________________________________________________
   _\/\\\/\\\__\/\\\____________________/\\\_______/\\\_______________________________________________________________________
    _\/\\\//\\\_\/\\\_____/\\\\\\\\___/\\\\\\\\\\\_\/\\\____/\\\\\\\__/\\\\\\\\\_____/\\\____/\\\__/\\\\\\\\\\\_____/\\\\\\\\__
     _\/\\\\//\\\\/\\\___/\\\/////\\\_\////\\\////__\/\\\___\/////\\\_\////////\\\___\/\\\___\/\\\_\///////\\\/____/\\\/////\\\_
      _\/\\\_\//\\\/\\\__/\\\\\\\\\\\_____\/\\\______\/\\\_______\/\\\___/\\\\\\\\\\__\/\\\___\/\\\______/\\\/_____/\\\\\\\\\\\__
       _\/\\\__\//\\\\\\_\//\\///////______\/\\\_/\\__\/\\\_______\/\\\__/\\\/////\\\__\/\\\___\/\\\____/\\\/______\//\\///////___
        _\/\\\___\//\\\\\__\//\\\\\\\\\\____\//\\\\\___\//\\\\\\\\\\\\/__\//\\\\\\\\/\\_\//\\\\\\\\\___/\\\\\\\\\\\__\//\\\\\\\\\\_
         _\///_____\/////____\//////////______\/////_____\////////////_____\////////\//___\/////////___\///////////____\//////////__

  "#
    );
    info!("==================== Git/Source Control Information ====================");
    info!("         Package Version:    {}", build::PKG_VERSION);
    info!("         Commit Hash:        {}", build::COMMIT_HASH);
    info!("         Commit Date:        {}", build::COMMIT_DATE);
    info!("         Branch:             {}", build::BRANCH);
    info!("         Tag:                {}", build::TAG);

    info!("");
    info!("======================== Build Information =============================");
    info!("         Build Time:         {}", build::BUILD_TIME);
    info!("         Rust Build Channel: {}", build::BUILD_RUST_CHANNEL);
    info!("         Operating System:   {}", build::BUILD_OS);
    info!("         Rust Channel:       {}", build::RUST_CHANNEL);
    info!("         Rust Version:       {}", build::RUST_VERSION);
    info!("         Cargo Version:      {}", build::CARGO_VERSION);
    info!("========================================================================");
    info!("");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    log_info();
    let local_socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 1791);
    let print_svc = ServiceBuilder::new().service(service_fn(|x: BmpRequest| async move {
        println!("Received: {}", serde_json::to_string(&x).unwrap());
        Ok::<Option<BmpServerResponse>, Infallible>(None)
    }));
    let pipeline = ServiceBuilder::new()
        //.rate_limit(1, Duration::from_secs(30))
        .service(print_svc);
    let buffer_svc = Buffer::new(pipeline, 100);

    let handle = BmpServerHandle::default();
    let handle_clone = handle.clone();
    let server_handle = tokio::spawn(async move {
        let server = BmpServer::new(local_socket, handle_clone);
        server.serve(buffer_svc).await.unwrap();
    });
    //tokio::time::sleep(Duration::from_secs(3)).await;
    //handle.shutdown();
    let (_server_ret,) = tokio::join!(server_handle);

    Ok(())
}
