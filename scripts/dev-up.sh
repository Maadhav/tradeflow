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
pkill -f "bun run server.ts" 2>/dev/null || true
sleep 1
nohup anvil --fork-url "${SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}" --chain-id 11155111 --port 8545 --block-time 2 >"$RUN/anvil.log" 2>&1 &
for i in $(seq 1 30); do cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break; sleep 1; done

for r in platform creSigner ben; do
  cast rpc anvil_setBalance "$(addr $r)" 0x56BC75E2D63100000 --rpc-url $RPC >/dev/null # 100 ETH
done

(cd "$ROOT/contracts" && FORWARDER=$FORWARDER SETTLEMENT_ACCOUNT="$(addr settlement)" ONRAMP_OPERATOR="$(addr platform)" \
  SECONDS_PER_DAY="${SECONDS_PER_DAY:-60}" DEPLOY_NAME=local \
  forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key "$(key platform)" >"$RUN/deploy.log" 2>&1)
cat "$ROOT/contracts/deployments/local.json"

# CRE: simulation signer + rails API key for the local target
printf 'CRE_ETH_PRIVATE_KEY=%s\nRAILS_API_KEY_VAR=sandbox-key-local\n' "$(key creSigner)" >"$ROOT/cre/.env"
python3 - "$ROOT" <<'EOF'
import json, sys
root = sys.argv[1]
dep = json.load(open(f"{root}/contracts/deployments/local.json"))
signer = json.load(open(f"{root}/services/rails/addresses.json"))["creSigner"]
for w in ["listing", "lender", "settlement", "monitor"]:
    p = f"{root}/cre/{w}/config.local.json"
    c = json.load(open(p))
    c.update(market=dep["market"], stablecoin=dep["stablecoin"], notes=dep["notes"])
    if "secretOwner" in c:
        c["secretOwner"] = signer
    json.dump(c, open(p, "w"), indent=2)
EOF

rm -f "$ROOT/services/rails/data/state.local.json"
(cd "$ROOT/services/rails" && nohup bun run server.ts >"$RUN/rails.log" 2>&1 &)
sleep 4
tail -2 "$RUN/rails.log"
