# sing-rules-filtered

Filtered copies of the SagerNet CN rule sets, rebuilt daily
by GitHub Actions from the upstream sources.

## Why

The upstream CN data claims Google: `geosite-cn` carries
Google host entries (`dl.google.com`, `googleapis.com`,
gvt/gstatic hosts), so traffic to Google services can be
matched by the CN set and sent down the wrong path — most
visibly, Play Store downloads stalling near completion.
This project republishes both CN sets with every Google
entry removed:

- **geosite-cn**: domain entries mentioning Google host
  tokens (google, gstatic, gvt, ggpht, youtube,
  doubleclick) are dropped.
- **geoip-cn**: Google's published IP ranges
  ([goog.json](https://www.gstatic.com/ipranges/goog.json))
  are subtracted from every CIDR entry.

## Files

- `rule-set/geosite-cn.srs`
- `rule-set/geoip-cn.srs`

Raw URLs:

- https://raw.githubusercontent.com/onlyno999/sing-rules-filtered/main/rule-set/geosite-cn.srs
- https://raw.githubusercontent.com/onlyno999/sing-rules-filtered/main/rule-set/geoip-cn.srs

## Sources

- https://github.com/SagerNet/sing-geosite
- https://github.com/SagerNet/sing-geoip
- https://www.gstatic.com/ipranges/goog.json

## Build the filter locally

```sh
go build -o filter./cmd/filter
./filter geosite geosite-cn.srs out.srs
./filter geoip geoip-cn.srs goog.json out.srs
```
