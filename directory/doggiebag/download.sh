#!/bin/sh

host="18.85.22.239:80"

zlibd() (python2 -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))")

echo -e "package doggiebag\nimport \"time\"\nvar Time = time.Unix($(date +%s), 0)" > time.go
curl -# "http://$host/tor/keys/all.z" | zlibd > keys
curl -# "http://$host/tor/status-vote/current/consensus-microdesc.z" | zlibd > consensus-microdesc

(
	grep '^m' consensus-microdesc |
		cut -d' ' -f2 |
		xargs -n92 echo |
		tr ' ' '-' |
		while read batch; do
			curl -# "http://$host/tor/micro/d/$batch.z" | zlibd
		done
) > microdescriptors

go-bindata -ignore=".*.go .*.sh Makefile" -nomemcopy -nocompress -o assets.go -pkg doggiebag .
