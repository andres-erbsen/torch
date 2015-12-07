#!/bin/sh

host="18.181.5.37:9032"

echo -e "package doggiebag\nimport \"time\"\nvar Time = time.Unix($(date +%s), 0)" > time.go
curl -# "http://$host/tor/keys/all.z" | openssl zlib -d > keys
curl -# "http://$host/tor/status-vote/current/consensus-microdesc.z" | openssl zlib -d > consensus-microdesc

(
	grep '^m' consensus-microdesc |
		cut -d' ' -f2 |
		xargs -n92 echo |
		tr ' ' '-' |
		while read batch; do
			curl -# "http://$host/tor/micro/d/$batch.z" | openssl zlib -d
		done
) > microdescriptors

go-bindata -ignore=".*.go .*.sh Makefile" -nomemcopy -nocompress -o assets.go -pkg doggiebag .
