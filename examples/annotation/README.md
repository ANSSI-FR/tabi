# Advanced example

This example demonstrates how to use the `tabi` module in order to detect
all possible BGP hijacks seen from a BGP collector.

## Requirements

*WARNING*: Before trying this example make sure you have at least 2GB
of free memory on your computer

The installation procedure is described in the main
[README](https://github.com/ANSSI-FR/tabi).

### MRT parser

This example is compatible with [mabo](https://github.com/ANSSI-FR/mabo) and
[bgpreader](https://bgpstream.caida.org/docs/tools/bgpreader).

## Detect the hijacks

```shell
python detect_hijacks.py -c rrc01 -i mabo \
    --rpki-roa-file roa.csv \
    --irr-ro-file routes.csv \
    --irr-mnt-file maintainers.csv \
    --irr-org-file organisations.csv \
    ../../{bview,updates}.*.gz
```

This example script prints the abnormal events that were detected by the
`tabi` module. Additionnaly it tries to filter out the conflicts that are most
probably legitimate using the following methods:

1. the conflicting announce is covered by a ROA
2. the conflicting announce is covered by a route object
3. there is an administrative relation between the two conflicting AS
4. the `AS_PATH` of the hijacker contains the ASN of the hijacked

These heuristics are documented in the `tabi.annotate` module.

## Interpreting the results

### Update example

In this example, the announce updating the route of `2403:8600:ea89::/48`
originating from AS55441 leads to the probable redirection of the traffic that

was initially directed towards AS131317. This is suspicious because there are
valid route object and ROA for the original route but not for the latest
route update.

```json
{
   "timestamp" : 1451609472,
   "collector" : "rrc01",
   "peer_ip" : "2001:7f8:4::7992:1",
   "peer_as" : 31122,
   "announce" : {
      "prefix" : "2403:8600:ea89::/48",
      "asn" : 55441,
      "as_path" : "31122 6939 6453 4755 45820 55441",
      "type" : "U"
   },
   "conflict_with" : {
      "prefix" : "2403:8600:ea89::/48",
      "asn" : 131317,
      "valid" : [
         "apnic",
         "roa"
      ]
   },
   "type" : "ABNORMAL"
}
```

 * **timestamp**: when the announce was received (UTC timestamp)
 * **collector**: which BGP collector received the announce
 * **peer_ip** & **peer_as**: which BGP peer received the announce
 * **announce**: information about the announce
   * **type**: either `U` if the announce was received from a BGP update or `F` if it was from a BGP full view
 * **conflict_with**: information about the RIB entry conflicting with the announce
   * **valid**: route objects or ROA on the couple `prefix` & `asn`

### Withdraw example

In this example the announce withdrawing the route `23.192.176.0/20` from
AS5570 leads to the probable redirection of the traffic towards AS35889 which
is announcing a route to the less specific prefix `23.192.0.0/11`.

```json
{
   "timestamp" : 1451609643,
   "collector" : "rrc01",
   "peer_ip" : "195.66.224.138",
   "peer_as" : 2914,
   "withdraw" : {
      "asn" : 55740,
      "prefix" : "23.192.176.0/20",
      "type" : "W"
   },
   "conflict_with" : {
      "prefix" : "23.192.0.0/11",
      "asn" : 35994
   },
   "type" : "ABNORMAL"
}
```

 * **timestamp**: when the announce was received (UTC timestamp)
 * **collector**: which BGP collector received the announce
 * **peer_ip** & **peer_as**: which BGP peer received the announce
 * **withdraw**: information about the withdraw
 * **conflict_with**: information about the RIB entry conflicting with the announce
