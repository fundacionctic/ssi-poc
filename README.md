# Self-Sovereign Identity PoC

A minimal proof-of-concept of how to leverage Verifiable Credentials (VC) and Decentralized Identifiers (DID) to implement identity and trust in a data space.

> [!NOTE]
> [walt.id](https://docs.oss.walt.id/) is the key building block used to implement the services and the orchestration script. walt.id provides off-the-shelf services to deploy Wallets, Issuers, and Verifiers, and exposes all operations via well-documented HTTP APIs.

The Compose stack in `docker-compose.yml` is configured with three different instances of wallets, an issuer, and a verifier. The wallets represent two participants—consumer and provider—and a trust anchor that acts as one of the authorities of the data space. The issuer and verifier are centralised services that have key roles in the implementation of OpenID4VP and OpenID4VC flows.

The script in this repository illustrates the interactions between the wallets, issuer, and verifier to issue a VC, request the presentation of the VC, and fulfil that presentation request. Moreover, only VCs issued with the key of the trust anchor are accepted as valid credentials.

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
    ISS->>WCN: Returns VC
    WCN->>WCN: Stores newly issued VC in wallet
    WPR->>VER: Creates presentation request where allowed issuer is Anchor Wallet
    VER->>WCN: Returns presentation request URL
    WCN->>WCN: Finds credentials that match presentation request URL
    WCN->>VER: Shares credentials to fulfil presentation request
    WPR->>VER: Requests verification status
    VER->>WPR: Returns verification status
    WPR->>WPR: Validates that presentation request has been fulfilled
```
