// Copyright (C) 2023-present The NetGauze Authors.
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

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use netgauze_flow_pkt::FlowInfo;


// Maybe better to already Flatten this (and not simply include FlowInfo struct inside??)
// also needs to be configurable (all fields of flow_record, i.e. some we want in the aggregaate, some not...)
pub struct FlowRecordAggr {
  peer_ip_source: IpAddr,
  timestamp_arrival: DateTime<Utc>,
  flow_record: FlowInfo,
  //external_map_enrichments: //--> platform_id, node_id stuff, even sampling for platform that do not support it...
  //option_data_enrichments: OptionDataInfo, // --> vec, create it in new lib file... contains types of option data from an Enum (e.g. samplingOption, RdOption)
}
