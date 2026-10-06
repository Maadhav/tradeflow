#!/usr/bin/env bash
# Ethereum Sepolia deployment: fund the CRE signer and demo lender from the platform wallet,
# deploy the contracts, write the CRE sepolia configs and start a second app instance on :8788
# that runs the workflows against Sepolia (cre --target sepolia --broadcast).
set -euo pipefail
export PATH="$PATH:$HOME/.foundry/bin:$HOME/.cre/bin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/.run"
mkdir -p "$RUN"
KEYS="$ROOT/.secrets/keys.json"
key() { python3 -c "import json;print(json.load(open('$KEYS'))['$1'])"; }
addr() { python3 -c "import json;print(json.load(open('$ROOT/services/rails/addresses.json'))['$1'])"; }
RPC="${SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}"
FORWARDER=0x15fC6ae953E024d975e77382eEeC56A9101f9F88 # Sepolia MockKeystoneForwarder (CRE simulation)

echo "platform balance: $(cast balance "$(addr platform)" --rpc-url "$RPC" --ether) ETH"

topup() { # address, target ether
  local bal; bal=$(cast balance "$1" --rpc-url "$RPC")
  local want; want=$(cast to-wei "$2")
  if python3 -c "import sys;sys.exit(0 if int('$bal')<int('$want') else 1)"; then
    cast send "$1" --value "$(python3 -c "print(int('$want')-int('$bal'))")" --private-key "$(key platform)" --rpc-url "$RPC" >/dev/null
    echo "topped up $1 to $2 ETH"
  fi
}
topup "$(addr creSigner)" "${CRE_SIGNER_ETH:-0.08}"
topup "$(addr ben)" "${BEN_ETH:-0.02}"

if [ ! -f "$ROOT/contracts/deployments/sepolia.json" ] || [ "${REDEPLOY:-0}" = "1" ]; then
  rm -f "$ROOT/services/rails/data/state.sepolia.json"
  (cd "$ROOT/contracts" && FORWARDER=$FORWARDER SETTLEMENT_ACCOUNT="$(addr settlement)" ONRAMP_OPERATOR="$(addr platform)" \
    SECONDS_PER_DAY="${SECONDS_PER_DAY:-60}" DEPLOY_NAME=sepolia \
    forge script script/Deploy.s.sol --rpc-url "$RPC" --broadcast --private-key "$(key platform)" --slow \
    --gas-estimate-multiplier "${GAS_MULT:-760}" --with-gas-price "${GAS_PRICE:-1.6gwei}" --priority-gas-price 0.05gwei >"$RUN/deploy-sepolia.log" 2>&1)
fi
cat "$ROOT/contracts/deployments/sepolia.json"

python3 - "$ROOT" <<'EOF'
import json, sys
root = sys.argv[1]
dep = json.load(open(f"{root}/contracts/deployments/sepolia.json"))
signer = json.load(open(f"{root}/services/rails/addresses.json"))["creSigner"]
for w in ["listing", "lender", "settlement", "monitor"]:
    c = json.load(open(f"{root}/cre/{w}/config.local.json"))
    c.update(market=dep["market"], stablecoin=dep["stablecoin"], notes=dep["notes"], railsUrl="http://localhost:8788")
    if "secretOwner" in c:
        c["secretOwner"] = signer
    if "logConfidence" in c:
        c["logConfidence"] = "LATEST"
    json.dump(c, open(f"{root}/cre/{w}/config.sepolia.json", "w"), indent=2)
EOF

kill $(lsof -ti :8788) 2>/dev/null || true # the Sepolia app
sleep 1
(cd "$ROOT/services/rails" && PORT=8788 DEPLOYMENT=sepolia RPC_URL="$RPC" CRE_TARGET=sepolia EXPLORER=https://sepolia.etherscan.io \
  exec nohup bun run server.ts >"$RUN/rails-sepolia.log" 2>&1 </dev/null & echo $! >"$RUN/rails-sepolia.pid")
sleep 5
tail -2 "$RUN/rails-sepolia.log"
