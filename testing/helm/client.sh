#!/bin/sh
# Runs in a curl pod inside the cluster during the chart test (e2e.sh).
# It starts SLOW streaming requests, then sends one short request every
# 200 ms for DURATION seconds, all through the Service. Each request prints
# one line:
#   <kind> <http status> <curl exit> <saw [DONE]> <end time, epoch s>
# e2e.sh reads the lines from the pod log and fails on anything but
# "200 0 yes".
set -u
url="http://${SERVICE}:${PORT}/v1/chat/completions"

request() {
  kind="$1"; model="$2"; out="/tmp/$kind.$$.$3"
  code="$(curl -sS -N --max-time 120 -o "$out" -w '%{http_code}' "$url" \
    -H 'content-type: application/json' \
    -d "{\"model\":\"$model\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" 2>/tmp/err.$$.$3)"
  rc=$?
  done=no
  grep -q '\[DONE\]' "$out" 2>/dev/null && done=yes
  echo "$kind $code $rc $done $(date +%s)"
  [ "$rc" -eq 0 ] || sed 's/^/  curl: /' "/tmp/err.$$.$3"
}

echo "start $(date +%s)"
i=0
while [ "$i" -lt "${SLOW}" ]; do
  request slow mock-slow "s$i" &
  i=$((i + 1))
done
end=$(( $(date +%s) + DURATION ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do
  request fast mock-fast "f$n" &
  n=$((n + 1))
  sleep 0.2
done
wait
echo "finished $(date +%s)"
