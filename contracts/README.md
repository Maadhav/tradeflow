# Tradeflow contracts

- `TradeflowMarket.sol`: credit marketplace and Chainlink CRE report receiver (via the official `ReceiverTemplate`).
  Each listed loan gets its own ERC-3643 (T-REX) security token as its loan notes: a T-REX `TokenProxy`
  ("Tradeflow Loan Note <id>", symbol `TFN<id>`, 6 decimals) bound to its own `ModularCompliance` proxy and
  the shared identity registry. The market is the token's owner and agent: it mints on funding, burns on
  claim and fiat redemption, pauses the token while the loan is Late or Defaulted and unpauses it on repayment.
- `CreClaimIssuer.sol`: the trusted claim issuer of the identity registry (ONCHAINID `IClaimIssuer`). A KYC
  claim (topic 1) is valid only while the market has recorded it after a CRE KYC report and not revoked it.
- `TestStablecoin.sol`: 6-decimal testnet stablecoin minted by the on-ramp operator.

KYC flow: the `lender` workflow sends `VerifyLender (address lender, bool verified, bytes32 kycRef, uint16 country)`.
On the first verification the market deploys an ONCHAINID `IdentityProxy` for the lender (management key: the
market), records the claim in `CreClaimIssuer`, adds it to the identity and registers wallet, identity and
country (ISO 3166 numeric) in the shared T-REX `IdentityRegistry`. `verified = false` revokes the claim, so
`identityRegistry.isVerified(wallet)` turns false and every loan token refuses to mint or transfer to it.

`script/Deploy.s.sol` deploys the T-REX v4.1.6 implementations behind one `TREXImplementationAuthority`, the
shared identity registry (storage, claim topics registry requiring topic 1, trusted issuers registry trusting
`CreClaimIssuer`), the ONCHAINID identity implementation and authority, the stablecoin and the market, and
writes `deployments/<DEPLOY_NAME>.json` with `chainId`, `forwarder`, `market`, `stablecoin`,
`identityRegistry` and `claimIssuer`.

```bash
forge test
FORWARDER=0x15fC6ae953E024d975e77382eEeC56A9101f9F88 SETTLEMENT_ACCOUNT=... ONRAMP_OPERATOR=... \
  forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

T-REX and ONCHAINID are vendored in `lib/` (GPL-3.0); see [`lib/README.md`](lib/README.md).
