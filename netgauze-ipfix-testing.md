# 1 - FLOW (IPFIX/NFv9) PCAP VERIFICATION WITH NETGAUZE

## Install Rust
Following to the [official instructions](https://forge.rust-lang.org/infra/other-installation-methods.html), for linux systems we run:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Clone NetGauze
```bash
git clone https://github.com/NetGauze/NetGauze.git
```

## Install necessary build dependencies
```bash
# Debian based
sudo apt install build-essential cmake perl perl-modules

# RPM based
sudo dnf install gcc gcc-c++ make cmake perl perl-IPC-Cmd
```

## Create a folder in /assets/pcaps/flow and add the pcap there, such as:
```bash
NetGauze/assets/pcaps/flow/huawei/huawei-ipfix-packets.pcap
```

## Run the NetGauze tests to generate the json file
Run tests with the OVERWRITE flag set to create the json file from the provided pcap:
```bash
cd NetGauze
OVERWRITE=true cargo test
```

### Hints:
- this will also compile NetGauze, and will take long the first time as all dependencies need to be pulled

- if this is failing, look at the logs to check if there are any missing dependencies to be installed

- if successful, then a new json file containing the parsed packets should be generated, e.g.:
  ```bash
  NetGauze/assets/pcaps/flow/huawei/huawei-ipfix-packets-flow.json
  ```

- currently we are using the destination port to perform protocol detection and **we expect IPFIX packets to have dst port 9991, 9992, or 10088** to be picked up by the tests (can be extended in the future). If you want to quickly add a new protocol locally you can edit the [pcap_tests.rs](https://github.com/NetGauze/NetGauze/blob/main/crates/flow-pkt/src/wire/tests/pcap_tests.rs#L82) file to add an additional port before running the tests.


# 2 - PMACCT ISSUE
Traffic type detection for VLAN/L2 in [nfacctd.c](https://github.com/pmacct/pmacct/blob/master/src/nfacctd.c#L3500-L3503) needs to be extended to support scenarios where not only either IE58 or IE59 are present but also scenarios where only e.g. only IE243 (dot1qvlanid), like in the Huawei pcap. The result is that such flow records end up having no category and thus are ignored by nfacct.

### What needs to be done?
The NF_evaluate_flow_type() function needs to be extended for correctly detecting all L2 scenarios.
