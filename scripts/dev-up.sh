#!/usr/bin/env bash
# Local development stack: anvil fork of Ethereum Sepolia (keeps the real CRE
# MockKeystoneForwarder and Chainlink feeds), fresh deployment, CRE config, rails sandbox.
set -euo pipefail
export PATH="$PATH:$HOME/.foundry/bin:$HOME/.cre/bin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/.run"
mkdir -p "$RUN"
KEYS="$ROOT/.secrets/keys.json"
key() { python3 -c "import json;print(json.load(open('$KEYS'))['$1'])"; }
addr() { python3 -c "import json;print(json.load(open('$ROOT/services/rails/addresses.json'))['$1'])"; }
RPC=http://127.0.0.1:8545
FORWARDER=0x15fC6ae953E024d975e77382eEeC56A9101f9F88

pkill -f "anvil --fork-url" 2>/dev/null || true
kill $(lsof -ti tcp:8787 -sTCP:LISTEN) 2>/dev/null || true # the local app (the listener only, never its clients)
# Wait until the old anvil and app have let go of their ports, so the probes below never reach a
# process that is shutting down.
for i in $(seq 1 30); do
  lsof -ti tcp:8545 -sTCP:LISTEN >/dev/null 2>&1 || lsof -ti tcp:8787 -sTCP:LISTEN >/dev/null 2>&1 || break
  sleep 0.5
done
sleep 1
# A load-balanced public RPC sometimes cannot serve the block it just announced, and anvil then exits
# while creating the fork ("block not found"). Start it again a few times before giving up.
for attempt in 1 2 3; do
  # The fork runs a pinned hardfork, so forge's gas estimates match what the local chain charges even
  # when Sepolia schedules a newer one.
  nohup anvil --fork-url "${SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}" --chain-id 11155111 --port 8545 --block-time 2 \
    --hardfork "${ANVIL_HARDFORK:-osaka}" >"$RUN/anvil.log" 2>&1 &
  ANVIL_PID=$!
  for i in $(seq 1 30); do
    cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break
    kill -0 $ANVIL_PID 2>/dev/null || break # anvil exited: no point waiting
    sleep 1
  done
  cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break
  echo "anvil did not start (attempt $attempt): $(tail -1 "$RUN/anvil.log")" >&2
  kill $ANVIL_PID 2>/dev/null || true
  sleep 3
done

for r in platform creSigner; do
  cast rpc anvil_setBalance "$(addr $r)" 0x56BC75E2D63100000 --rpc-url $RPC >/dev/null # 100 ETH
done

(cd "$ROOT/contracts" && FORWARDER=$FORWARDER SETTLEMENT_ACCOUNT="$(addr settlement)" ONRAMP_OPERATOR="$(addr platform)" \
  SECONDS_PER_DAY="${SECONDS_PER_DAY:-60}" DEPLOY_NAME=local \
  forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key "$(key platform)" >"$RUN/deploy.log" 2>&1)
cat "$ROOT/contracts/deployments/local.json"

# CRE config for the local target. The CLI's secrets (simulation signer, rails API key) are not
# written here: the app writes its own env file per deployment, services/rails/data/cre.local.env,
# with an API key generated at each start, and runs the workflows with it.
python3 - "$ROOT" <<'EOF'
import json, sys
root = sys.argv[1]
dep = json.load(open(f"{root}/contracts/deployments/local.json"))
signer = json.load(open(f"{root}/services/rails/addresses.json"))["creSigner"]
for w in ["listing", "lender", "settlement", "monitor"]:
    p = f"{root}/cre/{w}/config.local.json"
    c = json.load(open(p))
    c.update(market=dep["market"], stablecoin=dep["stablecoin"])
    c.pop("notes", None)  # loan notes are per-loan ERC-3643 tokens, found through market.loanToken(id)
    if "secretOwner" in c:
        c["secretOwner"] = signer
    json.dump(c, open(p, "w"), indent=2)
EOF

rm -f "$ROOT/services/rails/data/state.local.json" "$ROOT/services/rails/data/custody.local.json"
(cd "$ROOT/services/rails" && exec nohup bun run server.ts >"$RUN/rails.log" 2>&1 </dev/null & echo $! >"$RUN/rails-local.pid")
sleep 4
tail -2 "$RUN/rails.log"
