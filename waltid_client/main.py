import base64
import json
import logging
import pprint
from typing import Tuple
from urllib.parse import unquote

import base58
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


def jwk_to_did_key(jwk: dict) -> str:
    public_key = jwk["x"]
    public_key_bytes = base64.urlsafe_b64decode(public_key + "==")
    public_key_multicodec = b"\xed" + public_key_bytes
    public_key_base58 = base58.b58encode(public_key_multicodec)
    did_key = "z" + public_key_base58.decode()
    return f"did:key:{did_key}"


def get_first_wallet_id(wallet_api_base_url: str, wallet_token: str) -> str:
    headers = {"Authorization": "Bearer " + wallet_token}
    url_accounts = wallet_api_base_url + "/wallet-api/wallet/accounts/wallets"
    res_accounts = requests.get(url_accounts, headers=headers)
    res_accounts.raise_for_status()
    res_accounts_json = res_accounts.json()
    logger.info(res_accounts_json)
    return res_accounts_json["wallets"][0]["id"]


def get_first_did(wallet_api_base_url: str, wallet_token: str, wallet_id: str) -> str:
    headers = {"Authorization": "Bearer " + wallet_token}
    url_dids = wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/dids"
    res_dids = requests.get(url_dids, headers=headers)
    res_dids.raise_for_status()
    res_dids_json = res_dids.json()
    logger.info(pprint.pformat(res_dids_json))
    return res_dids_json[0]["did"]


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
    jwk: dict, vc: dict, issuer_api_base_url: str
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
        "issuerDid": jwk_to_did_key(jwk),
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
    wallet_api_base_url: str, wallet_token: str, algo: str = "RSA"
) -> Tuple[str, str]:
    wallet_id = get_first_wallet_id(wallet_api_base_url, wallet_token)

    url_create_key = (
        wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/generate"
    )

    headers = {"Authorization": "Bearer " + wallet_token}

    res_create_key = requests.post(
        url_create_key, headers=headers, params={"algorithm": algo}
    )

    res_create_key.raise_for_status()
    key_id = res_create_key.text
    logger.info(key_id)

    return (wallet_id, key_id)


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

    anchor_wallet_token = auth_login_wallet(
        cfg.wallet_anchor_api_base_url,
        cfg.wallet_anchor_user_email,
        cfg.wallet_anchor_user_password,
    )

    logger.info("Logging in wallet user: %s", cfg.wallet_provider_user_email)

    provider_wallet_token = auth_login_wallet(
        cfg.wallet_provider_api_base_url,
        cfg.wallet_provider_user_email,
        cfg.wallet_provider_user_password,
    )

    logger.info("Logging in wallet user: %s", cfg.wallet_consumer_user_email)

    consumer_wallet_token = auth_login_wallet(
        cfg.wallet_consumer_api_base_url,
        cfg.wallet_consumer_user_email,
        cfg.wallet_consumer_user_password,
    )

    logger.info("Generating signing key")

    anchor_wallet_id, signing_key_id = generate_key(
        wallet_api_base_url=cfg.wallet_anchor_api_base_url,
        wallet_token=anchor_wallet_token,
        algo=cfg.signing_key_algorithm,
    )

    logger.info("Anchor wallet ID: %s", anchor_wallet_id)
    logger.info("Signing key ID: %s", signing_key_id)
    logger.info("Exporting signing key to JWK")

    issuer_signing_jwk = get_jwk_key(
        wallet_api_base_url=cfg.wallet_anchor_api_base_url,
        wallet_id=anchor_wallet_id,
        key_id=signing_key_id,
        wallet_token=anchor_wallet_token,
    )

    logger.info("Loading VC from disk: %s", cfg.vc_path)

    vc = json.load(open(cfg.vc_path))

    logger.info("Creating credential offer URL")

    credential_offer_url = get_openid4vc_credential_offer_url(
        jwk=issuer_signing_jwk, vc=vc, issuer_api_base_url=cfg.issuer_api_base_url
    )

    provider_wallet_id = get_first_wallet_id(
        cfg.wallet_provider_api_base_url, provider_wallet_token
    )

    provider_user_did_key = get_first_did(
        cfg.wallet_provider_api_base_url, provider_wallet_token, provider_wallet_id
    )

    logger.info("Using offer request with recipient user: %s", provider_user_did_key)

    use_offer_request(
        wallet_api_base_url=cfg.wallet_provider_api_base_url,
        wallet_id=provider_wallet_id,
        user_did_key=provider_user_did_key,
        wallet_token=provider_wallet_token,
        credential_offer_url=credential_offer_url,
    )

    logger.info(
        "Listing credentials for wallet %s (wallet_id=%s)",
        cfg.wallet_provider_api_base_url,
        provider_wallet_id,
    )

    list_credentials(
        wallet_api_base_url=cfg.wallet_provider_api_base_url,
        wallet_token=provider_wallet_token,
        wallet_id=provider_wallet_id,
    )


if __name__ == "__main__":
    main()
