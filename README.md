# Self-Sovereign Identity PoC

A minimal proof-of-concept of how to leverage Verifiable Credentials (VC) and Decentralized Identifiers (DID) to implement identity and trust in a data space.

> [!NOTE]  
> Built on top of [walt.id](https://docs.oss.walt.id/), which provides comprehensive APIs for deployment of _Wallets_, _Issuers_, and _Verifiers_.

```mermaid
sequenceDiagram
    participant VER as Verifier
    participant ISS as Issuer
    participant WPR as Provider Wallet
    participant WCN as Consumer Wallet
    participant WAN as Anchor Wallet
    WAN->>WAN: Creates trust anchor key
    WAN->>ISS: Uses trust anchor key to issue a VC
    ISS->>WCN: Returns credential offer URL
    WCN->>ISS: Accepts credential offer
    ISS->>WCN: Stores newly issued VC
    WPR->>VER: Creates presentation request where allowed issuer is Anchor Wallet
    VER->>WCN: Returns presentation request URL
    WCN->>WCN: Finds credentials that match presentation request URL
    WCN->>VER: Shares credentials to fulfil presentation request
    WPR->>VER: Requests verification status
    VER->>WPR: Returns verification status
    WPR->>WPR: Validates that presentation request has been fulfilled
```
