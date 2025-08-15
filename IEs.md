# IEs

## Timestamps:

- 152: flowStartMilliseconds
- 153: flowEndMilliseconds
- 258: collectionTimeMilliseconds
- 260: maxExportSeconds
- 264: minExportSeconds
- 269: maxFlowEndMilliseconds (to be used for stats only...)
- 272: minFlowStartMilliseconds (to be used for stats only...)

missing:

- windowStart
- windowEnd

## Collector Info:

- 211: collectorIPv4Address
- 212: collectorIPv6Address
- 216: collectorTransportPort
- 375: originalFlowsPresent
- 403: originalExporterIPv4Address
- 404: originalExporterIPv6Address
- 405: originalObservationDomainId

missing:

- originalExporterTransportPort

## Statistics

- 375: originalFlowsPresent
- 149: observationDomainId: (It is RECOMMENDED that this identifier is also unique per IPFIX Device)
- 405: originalObservationDomainId
- 145: templateId
- 406: intermediateProcessId
- 407: ignoredDataRecordTotalCount (resource costrained drops)
- 42: exportedFlowRecordTotalCount
- 41: exportedMessageTotalCount
- 40: exportedOctetTotalCount - not needed

missing:

- originalTemplateId

- https://datatracker.ietf.org/doc/html/rfc5655#section-8.1.3
