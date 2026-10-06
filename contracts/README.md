# Tradeflow contracts

- `TradeflowMarket.sol`: credit marketplace and Chainlink CRE report receiver (via the official `ReceiverTemplate`).
- `LoanNotes.sol`: ERC-1155 loan notes, transferable only between KYC-verified holders.
- `TestStablecoin.sol`: 6-decimal testnet stablecoin minted by the on-ramp operator.

```bash
forge test
FORWARDER=0x15fC6ae953E024d975e77382eEeC56A9101f9F88 SETTLEMENT_ACCOUNT=... ONRAMP_OPERATOR=... \
  forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```
