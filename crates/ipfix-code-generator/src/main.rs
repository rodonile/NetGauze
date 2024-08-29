use std::ffi::OsString;

use netgauze_ipfix_code_generator::{
    generate, Config, ExternalSubRegistrySource, RegistrySource, RegistryType, SourceConfig,
    SubRegistryType,
};

const IPFIX_URL: &str = "https://www.iana.org/assignments/ipfix/ipfix.xml";
const PROTOCOL_NUMBERS_URL: &str =
    "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml";

fn main() {
    let out_dir = OsString::from(
        "/home/taarole8/netgauze-dev/NetGauze/crates/ipfix-code-generator/temp-out-dir",
    );
    let registry_dir =
        OsString::from("/home/taarole8/netgauze-dev/NetGauze/crates/flow-pkt/registry");
    let registry_path = std::path::Path::new(&registry_dir);
    let subregistry_path = registry_path.join("subregistry");

    // FlowDirection SubRegistry Path
    let flow_direction_path = subregistry_path
        .join("iana_flow_direction.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load flowDirection registry file");

    // Add custom registry, the xml file must follow the IANA schema
    let nokia_path = registry_path
        .join("nokia.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load nokia registry file");
    let nokia_source = SourceConfig::new(
        RegistrySource::File(nokia_path),
        RegistryType::IanaXML,
        637,
        "nokia".to_string(),
        "Nokia".to_string(),
        None,
    );

    let netgauze_path = registry_path
        .join("netgauze.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load NetGauze registry file");
    let netgauze_source = SourceConfig::new(
        RegistrySource::File(netgauze_path),
        RegistryType::IanaXML,
        3746,
        "netgauze".to_string(),
        "NetGauze".to_string(),
        None,
    );

    let cisco_path = registry_path
        .join("cisco.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load Cisco registry file");
    let cisco_source = SourceConfig::new(
        RegistrySource::File(cisco_path),
        RegistryType::IanaXML,
        9,
        "cisco".to_string(),
        "Cisco".to_string(),
        None, /* TODO: also here we could make it better by taking
               * Option<Vec<ExternalSubRegistrySource>> as parameter, so we can pass None */
    );

    // Add any external sub-registries for VMWare
    let external_subregs = vec![
        ExternalSubRegistrySource::new(
            RegistrySource::Http(PROTOCOL_NUMBERS_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            880,
        ),
        ExternalSubRegistrySource::new(
            RegistrySource::File(flow_direction_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("ipfix-flow-direction"),
            954,
        ),
    ];
    let vmware_path = registry_path
        .join("vmware.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load VMWare registry file");
    let vmware_source = SourceConfig::new(
        RegistrySource::File(vmware_path),
        RegistryType::IanaXML,
        6876,
        "vmware".to_string(),
        "VMWare".to_string(),
        Some(external_subregs),
    );

    // Add any external sub-registries for IANA
    let external_subregs = vec![
        ExternalSubRegistrySource::new(
            RegistrySource::Http(PROTOCOL_NUMBERS_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            4,
        ),
        ExternalSubRegistrySource::new(
            RegistrySource::File(flow_direction_path),
            SubRegistryType::ValueNameDescRegistry,
            String::from("ipfix-flow-direction"),
            61,
        ),
    ];
    let iana_source = SourceConfig::new(
        RegistrySource::Http(IPFIX_URL.to_string()),
        RegistryType::IanaXML,
        0,
        "iana".to_string(),
        "IANA".to_string(),
        Some(external_subregs),
    );
    let configs = Config::new(
        iana_source,
        vec![nokia_source, netgauze_source, cisco_source, vmware_source],
    );
    generate(&out_dir, &configs).unwrap();
}
