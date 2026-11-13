#!/bin/bash
set -e
export GOPATH=$HOME/workspace/gopath_probe
export GOCACHE=$HOME/workspace/gocache_probe
export GOTMPDIR=$HOME/workspace/gotmp
export GOFLAGS=-mod=mod
export GOPROXY=https://proxy.golang.org,direct
GO=$HOME/workspace/tools/go/bin/go
cd $HOME/workspace/sing-rules-filtered
if [ ! -f go.mod ]; then
  $GO mod init sing-rules-filtered
fi
$GO get github.com/sagernet/sing-box@latest
$GO mod tidy
$GO build -o work_filter sing-rules-filtered/cmd/filter
mkdir -p work
cp $HOME/workspace/gotmp/rs/geosite-cn.srs work/geosite-cn.srs
cp $HOME/workspace/gotmp/rs/geoip-cn.srs work/geoip-cn.srs
cp $HOME/workspace/gotmp/rs/goog.json work/goog.json
./work_filter geosite work/geosite-cn.srs rule-set/geosite-cn.srs
./work_filter geoip work/geoip-cn.srs work/goog.json rule-set/geoip-cn.srs
ls -la rule-set/
grep '^module\|sagernet/sing-box' go.mod
