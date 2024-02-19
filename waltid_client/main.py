import json
import logging
import pprint
from dataclasses import dataclass
from typing import Dict, List, Tuple, Union
from urllib.parse import parse_qs, unquote, urlparse

import environ
import requests
from rich.logging import RichHandler

logging.basicConfig(
    level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

logger = logging.getLogger("rich")


@environ.config(prefix="")
class AppConfig:
    issuer_api_base_url = environ.var()
    verifier_api_base_url = environ.var()
    signing_key_algorithm = environ.var(default="RSA")
    vc_path = environ.var()

    wallet_anchor_api_base_url = environ.var()
    wallet_anchor_user_name = environ.var()
    wallet_anchor_user_password = environ.var()
    wallet_anchor_user_email = environ.var()

    wallet_provider_api_base_url = environ.var()
    wallet_provider_user_name = environ.var()
    wallet_provider_user_password = environ.var()
    wallet_provider_user_email = environ.var()

    wallet_consumer_api_base_url = environ.var()
    wallet_consumer_user_name = environ.var()
    wallet_consumer_user_password = environ.var()
    wallet_consumer_user_email = environ.var()


def auth_login_wallet(wallet_api_base_url: str, email: str, password: str) -> str:
    url = wallet_api_base_url + "/wallet-api/auth/login"
    data = {"type": "email", "email": email, "password": password}
    response = requests.post(url, json=data)
    response.raise_for_status()
    res_json = response.json()
    logger.info(res_json)
    return res_json["token"]


def get_first_wallet_id(wallet_api_base_url: str, wallet_token: str) -> str:
    headers = {"Authorization": "Bearer " + wallet_token}
    url_accounts = wallet_api_base_url + "/wallet-api/wallet/accounts/wallets"
    res_accounts = requests.get(url_accounts, headers=headers)
    res_accounts.raise_for_status()
    res_accounts_json = res_accounts.json()
    logger.info(res_accounts_json)
    return res_accounts_json["wallets"][0]["id"]


def get_jwk_key(
    wallet_api_base_url: str, wallet_id: str, key_id: str, wallet_token: str
) -> dict:
    headers = {"Authorization": "Bearer " + wallet_token}

    url_export_key = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/export/{key_id}"
    )

    res_export_key_jwk = requests.get(
        url_export_key,
        headers=headers,
        params={"format": "JWK", "loadPrivateKey": True},
    )

    res_export_key_jwk.raise_for_status()
    key_jwk = res_export_key_jwk.json()
    logger.info(pprint.pformat(key_jwk))

    return key_jwk


def get_openid4vc_credential_offer_url(
    jwk: dict, vc: dict, issuer_api_base_url: str, issuer_did: str
) -> str:
    issuance_key = {"type": "local", "jwk": json.dumps(jwk)}

    mapping = {
        "id": "<uuid>",
        "issuer": {"id": "<issuerDid>"},
        "credentialSubject": {"id": "<subjectDid>"},
        "issuanceDate": "<timestamp>",
        "expirationDate": "<timestamp-in:365d>",
    }

    data = {
        "issuanceKey": issuance_key,
        "vc": vc,
        "mapping": mapping,
        "issuerDid": issuer_did,
    }

    logger.info(pprint.pformat(data))

    url_issue = issuer_api_base_url + "/openid4vc/jwt/issue"
    res_issue = requests.post(url_issue, headers={"Accept": "text/plain"}, json=data)
    res_issue.raise_for_status()
    credential_offer_url = res_issue.text
    logger.info(credential_offer_url)

    parsed_credential_offer = json.loads(
        unquote(credential_offer_url.split("credential_offer=")[1])
    )

    logger.info(pprint.pformat(parsed_credential_offer))

    return credential_offer_url


def get_openid4vp_presentation_request_url(
    verifier_api_base_url: str,
    request_credentials: list,
    allowed_issuer_dids: Union[str, List[str]] = None,
    vp_policies: List[str] = None,
    vc_policies: List[str] = None,
) -> str:
    url_verify = verifier_api_base_url + "/openid4vc/verify"

    headers = {
        "Accept": "*/*",
        "authorizeBaseUrl": "openid4vp://authorize",
        "responseMode": "direct_post",
    }

    vp_policies = vp_policies or ["signature", "expired"]
    vc_policies = vc_policies or ["signature", "expired"]

    if allowed_issuer_dids:
        vc_policies.append(
            {
                "policy": "allowed-issuer",
                "args": (
                    allowed_issuer_dids
                    if isinstance(allowed_issuer_dids, list)
                    else [allowed_issuer_dids]
                ),
            }
        )

    data = {
        "request_credentials": request_credentials,
        "vp_policies": vp_policies,
        "vc_policies": vc_policies,
    }

    logger.info(
        "Requesting credentials (%s):\n%s",
        url_verify,
        pprint.pformat(data),
    )

    res_verify = requests.post(url_verify, headers=headers, json=data)

    try:
        res_verify.raise_for_status()
    except:
        logger.error(res_verify.text)
        raise

    openid4vp_authorize_url = res_verify.text
    logger.info(openid4vp_authorize_url)

    return openid4vp_authorize_url


def parse_presentation_definition(presentation_url: str) -> dict:
    parsed_url = urlparse(presentation_url)
    query_params = parse_qs(parsed_url.query)
    presentation_definition = query_params.get("presentation_definition", [None])[0]
    return json.loads(presentation_definition)


def find_matching_credentials(
    presentation_url: str,
    wallet_api_base_url: str,
    wallet_token: str,
    wallet_id: str,
    latest_only: bool = True,
) -> Union[List, Dict, None]:
    pres_def = parse_presentation_definition(presentation_url)
    logger.info("Parsed presentation definition:\n%s", pprint.pformat(pres_def))

    url_match = (
        wallet_api_base_url
        + f"/wallet-api/wallet/{wallet_id}/exchange/matchCredentialsForPresentationDefinition"
    )

    headers = {"Authorization": "Bearer " + wallet_token}
    res_match = requests.post(url_match, headers=headers, json=pres_def)

    try:
        res_match.raise_for_status()
    except:
        logger.error(res_match.text)
        raise

    matching_credentials = res_match.json()

    if not matching_credentials:
        return None

    if len(matching_credentials) > 0 and latest_only:
        matching_credentials.sort(key=lambda x: x["addedOn"], reverse=True)
        return matching_credentials[0]

    return matching_credentials


def share_credentials(
    signing_did_key: str,
    presentation_url: str,
    shared_credential_ids: List[str],
    wallet_api_base_url: str,
    wallet_token: str,
    wallet_id: str,
):
    data = {
        "did": signing_did_key,
        "presentationRequest": presentation_url,
        "selectedCredentials": shared_credential_ids,
    }

    logger.debug(pprint.pformat(data))

    url_exchange = (
        wallet_api_base_url
        + f"/wallet-api/wallet/{wallet_id}/exchange/usePresentationRequest"
    )

    headers = {"Authorization": "Bearer " + wallet_token}
    res_exchange = requests.post(url_exchange, headers=headers, json=data)

    try:
        res_exchange.raise_for_status()
    except:
        logger.error(res_exchange.text)
        raise

    exchange_resp = res_exchange.json()
    logger.debug(pprint.pformat(exchange_resp))

    return exchange_resp


def use_offer_request(
    wallet_api_base_url: str,
    wallet_id: str,
    user_did_key: str,
    wallet_token: str,
    credential_offer_url: str,
) -> dict:
    url_use_offer_request = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest"
    )

    headers = {"Authorization": "Bearer " + wallet_token}

    res_use_offer_request = requests.post(
        url_use_offer_request,
        headers={**headers, **{"Accept": "*/*", "Content-Type": "text/plain"}},
        params={"did": user_did_key},
        data=credential_offer_url,
    )

    res_use_offer_request.raise_for_status()
    res_use_offer_request_json = res_use_offer_request.json()
    logger.info(pprint.pformat(res_use_offer_request_json))

    return res_use_offer_request_json


def get_verification_status(verifier_api_base_url: str, presentation_url: str) -> dict:
    parsed_url = urlparse(presentation_url)
    query_params = parse_qs(parsed_url.query)
    session_id = query_params["state"][0]
    logger.info("Checking OpenID4VC session status (session=%s)", session_id)
    url_state = verifier_api_base_url + f"/openid4vc/session/{session_id}"
    headers = {"Accept": "*/*"}
    res_state = requests.get(url_state, headers=headers)

    try:
        res_state.raise_for_status()
    except:
        logger.error(res_state.text)
        raise

    verification_status = res_state.json()
    logger.debug(pprint.pformat(verification_status))

    return verification_status


def create_wallet_user(wallet_api_base_url: str, name: str, email: str, password: str):
    url = wallet_api_base_url + "/wallet-api/auth/create"

    data = {
        "name": name,
        "email": email,
        "password": password,
        "type": "email",
    }

    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        logger.info(response.text)
    except requests.exceptions.HTTPError as e:
        logger.warning("Request failed, this is expected if the user already exists.")


def generate_key(
    wallet_api_base_url: str,
    wallet_token: str,
    algorithm: str = "RSA",
    wallet_id: str = None,
    alias: str = None,
) -> Tuple[str, str, str]:
    wallet_id = wallet_id or get_first_wallet_id(wallet_api_base_url, wallet_token)

    url_create_key = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/generate"
    )

    headers = {"Authorization": "Bearer " + wallet_token}

    res_create_key = requests.post(
        url_create_key, headers=headers, params={"algorithm": algorithm}
    )

    res_create_key.raise_for_status()
    key_id = res_create_key.text
    logger.info(key_id)

    logger.info("Creating DID for key %s (wallet=%s)", key_id, wallet_id)

    url_create_did = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/dids/create/key"
    )

    params = {"keyId": key_id}

    if alias:
        params["alias"] = alias

    res_create_did = requests.post(url_create_did, headers=headers, params=params)

    try:
        res_create_did.raise_for_status()
    except:
        logger.error(res_create_did.text)
        raise

    did_key = res_create_did.text

    return (wallet_id, key_id, did_key)


def import_key(wallet_api_base_url: str, wallet_token: str, wallet_id: str, jwk: dict):
    headers = {"Authorization": "Bearer " + wallet_token}

    url_list = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys"
    res_list = requests.get(url_list, headers=headers)
    res_list.raise_for_status()

    exists = next(
        (item for item in res_list.json() if item["keyId"]["id"] == jwk["kid"]), None
    )

    if exists:
        logger.info("Key '%s' already exists in wallet '%s'", jwk["kid"], wallet_id)
        return

    url_import = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/import"
    res_import = requests.post(url_import, headers=headers, json=jwk)

    try:
        res_import.raise_for_status()
    except:
        logger.error(res_import.text)
        raise

    logger.debug(res_import.text)


def list_credentials(
    wallet_api_base_url: str, wallet_token: str, wallet_id: str
) -> list:
    headers = {"Authorization": "Bearer " + wallet_token}

    url_list_credentials = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/credentials"
    )

    res_list_credentials = requests.get(url_list_credentials, headers=headers)
    res_list_credentials.raise_for_status()
    list_creds = res_list_credentials.json()
    logger.info(pprint.pformat(list_creds))

    return list_creds


def debug_wallet(wallet_api_base_url: str, wallet_token: str):
    logger.debug("Debugging wallet: %s", wallet_api_base_url)
    headers = {"Authorization": "Bearer " + wallet_token}

    logger.debug("Listing wallet accounts")
    url_accounts = wallet_api_base_url + "/wallet-api/wallet/accounts/wallets"
    res_accounts = requests.get(url_accounts, headers=headers)
    res_accounts.raise_for_status()
    accounts = res_accounts.json()
    logger.debug(pprint.pformat(accounts))

    wallet_ids = [item["id"] for item in accounts["wallets"]]

    for wallet_id in wallet_ids:
        logger.debug("Listing Keys for wallet %s", wallet_id)
        url_keys = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys"
        res_keys = requests.get(url_keys, headers=headers)
        res_keys.raise_for_status()
        keys = res_keys.json()
        logger.debug(pprint.pformat(keys))

        logger.debug("Listing DIDs for wallet %s", wallet_id)
        url_dids = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/dids"
        res_dids = requests.get(url_dids, headers=headers)
        res_dids.raise_for_status()
        dids = res_dids.json()
        logger.debug(pprint.pformat(dids))

        logger.debug("Listing Credentials for wallet %s", wallet_id)
        url_creds = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/credentials"
        res_creds = requests.get(url_creds, headers=headers)
        res_creds.raise_for_status()
        creds = res_creds.json()
        logger.debug(pprint.pformat(creds))


@dataclass
class WalletUser:
    wallet_api_base_url: str
    token: str
    wallet_id: str
    key_id: str
    did: str

    def get_key_as_jwk(self) -> dict:
        return get_jwk_key(
            wallet_api_base_url=self.wallet_api_base_url,
            wallet_id=self.wallet_id,
            key_id=self.key_id,
            wallet_token=self.token,
        )


def build_wallet_user(
    wallet_api_base_url: str, email: str, password: str, key_alias: str = "ssi-poc"
) -> WalletUser:
    token = auth_login_wallet(
        wallet_api_base_url=wallet_api_base_url, email=email, password=password
    )

    wallet_id = get_first_wallet_id(wallet_api_base_url, token)

    url_dids = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/dids"
    headers = {"Authorization": "Bearer " + token}
    res_dids = requests.get(url_dids, headers=headers)
    res_dids.raise_for_status()
    dids = res_dids.json()
    did_dict = next((item for item in dids if item["alias"] == key_alias), None)

    if did_dict:
        logger.info(
            "Found existing DID for alias '%s' (url=%s)", key_alias, wallet_api_base_url
        )

        key_id = did_dict["keyId"]
        did = did_dict["did"]
    else:
        logger.info(
            "Generating new key for alias '%s' (url=%s)", key_alias, wallet_api_base_url
        )

        wid, key_id, did = generate_key(
            wallet_api_base_url=wallet_api_base_url,
            wallet_token=token,
            wallet_id=wallet_id,
            alias=key_alias,
        )

        assert wid == wallet_id

    wallet_user = WalletUser(
        wallet_api_base_url=wallet_api_base_url,
        token=token,
        wallet_id=wallet_id,
        key_id=key_id,
        did=did,
    )

    logger.debug("Wallet user (%s): %s", wallet_api_base_url, wallet_user)

    return wallet_user


def main():
    cfg = environ.to_config(AppConfig)
    logger.info(cfg)

    for item in [
        (
            cfg.wallet_anchor_api_base_url,
            cfg.wallet_anchor_user_name,
            cfg.wallet_anchor_user_email,
            cfg.wallet_anchor_user_password,
        ),
        (
            cfg.wallet_provider_api_base_url,
            cfg.wallet_provider_user_name,
            cfg.wallet_provider_user_email,
            cfg.wallet_provider_user_password,
        ),
        (
            cfg.wallet_consumer_api_base_url,
            cfg.wallet_consumer_user_name,
            cfg.wallet_consumer_user_email,
            cfg.wallet_consumer_user_password,
        ),
    ]:
        logger.info("Creating wallet user: %s", item[2])
        create_wallet_user(*item)

    logger.info("Logging in wallet user: %s", cfg.wallet_anchor_user_email)

    anchor_wallet_user = build_wallet_user(
        wallet_api_base_url=cfg.wallet_anchor_api_base_url,
        email=cfg.wallet_anchor_user_email,
        password=cfg.wallet_anchor_user_password,
    )

    logger.info("Logging in wallet user: %s", cfg.wallet_provider_user_email)

    provider_wallet_user = build_wallet_user(
        wallet_api_base_url=cfg.wallet_provider_api_base_url,
        email=cfg.wallet_provider_user_email,
        password=cfg.wallet_provider_user_password,
    )

    logger.info("Logging in wallet user: %s", cfg.wallet_consumer_user_email)

    consumer_wallet_user = build_wallet_user(
        wallet_api_base_url=cfg.wallet_consumer_api_base_url,
        email=cfg.wallet_consumer_user_email,
        password=cfg.wallet_consumer_user_password,
    )

    logger.info("Signing key wallet ID: %s", anchor_wallet_user.wallet_id)
    logger.info("Signing key ID: %s", anchor_wallet_user.key_id)
    logger.info("Signing key DID: %s", anchor_wallet_user.did)

    issuer_signing_jwk = anchor_wallet_user.get_key_as_jwk()

    logger.info("Signing key in JWK format:\n%s", pprint.pformat(issuer_signing_jwk))
    logger.info("Loading VC from disk: %s", cfg.vc_path)

    vc = json.load(open(cfg.vc_path))

    logger.info("Creating credential offer URL")

    credential_offer_url = get_openid4vc_credential_offer_url(
        jwk=issuer_signing_jwk,
        vc=vc,
        issuer_api_base_url=cfg.issuer_api_base_url,
        issuer_did=anchor_wallet_user.did,
    )

    logger.info("Importing signing key to consumer and provider wallets")

    import_key(
        wallet_api_base_url=consumer_wallet_user.wallet_api_base_url,
        wallet_token=consumer_wallet_user.token,
        wallet_id=consumer_wallet_user.wallet_id,
        jwk=issuer_signing_jwk,
    )

    import_key(
        wallet_api_base_url=provider_wallet_user.wallet_api_base_url,
        wallet_token=provider_wallet_user.token,
        wallet_id=provider_wallet_user.wallet_id,
        jwk=issuer_signing_jwk,
    )

    logger.info("Using offer request with recipient user: %s", provider_wallet_user.did)

    use_offer_request(
        wallet_api_base_url=provider_wallet_user.wallet_api_base_url,
        wallet_id=provider_wallet_user.wallet_id,
        user_did_key=provider_wallet_user.did,
        wallet_token=provider_wallet_user.token,
        credential_offer_url=credential_offer_url,
    )

    logger.info(
        "Listing credentials for wallet %s (wallet_id=%s)",
        cfg.wallet_provider_api_base_url,
        provider_wallet_user.wallet_id,
    )

    list_credentials(
        wallet_api_base_url=provider_wallet_user.wallet_api_base_url,
        wallet_token=provider_wallet_user.token,
        wallet_id=provider_wallet_user.wallet_id,
    )

    request_credentials = ["UniversityDegreeCredential"]

    logger.info(
        "Creating verification request (%s):\n%s",
        cfg.verifier_api_base_url,
        pprint.pformat(request_credentials),
    )

    openid4vp_authorize_url = get_openid4vp_presentation_request_url(
        verifier_api_base_url=cfg.verifier_api_base_url,
        request_credentials=request_credentials,
        allowed_issuer_dids=anchor_wallet_user.did,
    )

    logger.info("Got OpenID4VP presentation request URL: %s", openid4vp_authorize_url)

    logger.info(
        "Looking for matching credentials in %s",
        provider_wallet_user.wallet_api_base_url,
    )

    matching_creds = find_matching_credentials(
        presentation_url=openid4vp_authorize_url,
        wallet_api_base_url=provider_wallet_user.wallet_api_base_url,
        wallet_token=provider_wallet_user.token,
        wallet_id=provider_wallet_user.wallet_id,
        latest_only=True,
    )

    logger.info("Found matching credentials:\n%s", pprint.pformat(matching_creds))
    logger.info("Sharing credentials from %s", provider_wallet_user.wallet_api_base_url)

    status_before = get_verification_status(
        verifier_api_base_url=cfg.verifier_api_base_url,
        presentation_url=openid4vp_authorize_url,
    )

    assert not status_before.get("policyResults")
    assert not status_before.get("verificationResult")

    share_credentials(
        signing_did_key=anchor_wallet_user.did,
        presentation_url=openid4vp_authorize_url,
        shared_credential_ids=[matching_creds["id"]],
        wallet_api_base_url=provider_wallet_user.wallet_api_base_url,
        wallet_token=provider_wallet_user.token,
        wallet_id=provider_wallet_user.wallet_id,
    )

    status_after = get_verification_status(
        verifier_api_base_url=cfg.verifier_api_base_url,
        presentation_url=openid4vp_authorize_url,
    )

    assert status_after.get("verificationResult")


if __name__ == "__main__":
    main()
