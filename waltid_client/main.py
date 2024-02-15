import base64
import json
import logging
import os
import pprint
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
    wallet_api_base_url = environ.var()
    issuer_api_base_url = environ.var()
    wallet_user_name = environ.var()
    wallet_user_password = environ.var()
    wallet_user_email = environ.var()
    signing_key_algorithm = environ.var(default="RSA")
    signing_key_path = environ.var()
    signing_key_path = environ.var()
    vc_path = environ.var()


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


def get_first_wallet_id(cfg: AppConfig, token: str) -> str:
    headers = {"Authorization": "Bearer " + token}
    url_accounts = cfg.wallet_api_base_url + "/wallet-api/wallet/accounts/wallets"
    res_accounts = requests.get(url_accounts, headers=headers)
    res_accounts.raise_for_status()
    res_accounts_json = res_accounts.json()
    logger.info(res_accounts_json)
    return res_accounts_json["wallets"][0]["id"]


def get_first_did(cfg: AppConfig, token: str, wallet_id: str) -> str:
    headers = {"Authorization": "Bearer " + token}
    url_dids = cfg.wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/dids"
    res_dids = requests.get(url_dids, headers=headers)
    res_dids.raise_for_status()
    res_dids_json = res_dids.json()
    logger.info(pprint.pformat(res_dids_json))
    return res_dids_json[0]["did"]


def create_wallet_user(cfg: AppConfig):
    url = cfg.wallet_api_base_url + "/wallet-api/auth/create"

    data = {
        "name": cfg.wallet_user_name,
        "email": cfg.wallet_user_email,
        "password": cfg.wallet_user_password,
        "type": "email",
    }

    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        logger.info(response.text)
    except requests.exceptions.HTTPError as e:
        logger.warning("Request failed, this is expected if the user already exists.")


def create_signing_key(cfg: AppConfig):
    if os.path.exists(cfg.signing_key_path):
        logger.info("Signing key already exists, skipping creation.")
        return

    token = auth_login_wallet(
        cfg.wallet_api_base_url, cfg.wallet_user_email, cfg.wallet_user_password
    )

    headers = {"Authorization": "Bearer " + token}

    wallet_id = get_first_wallet_id(cfg, token)

    url_create_key = (
        cfg.wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/generate"
    )

    res_create_key = requests.post(
        url_create_key, headers=headers, params={"algorithm": cfg.signing_key_algorithm}
    )

    res_create_key.raise_for_status()
    key_id = res_create_key.text
    logger.info(key_id)

    url_export_key = (
        cfg.wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/keys/export/{key_id}"
    )

    res_export_key_jwk = requests.get(
        url_export_key,
        headers=headers,
        params={"format": "JWK", "loadPrivateKey": True},
    )

    res_export_key_jwk.raise_for_status()
    key_jwk = res_export_key_jwk.json()
    logger.info(key_jwk)

    with open(cfg.signing_key_path, "w") as f:
        f.write(json.dumps(key_jwk))


def issue_credential(cfg: AppConfig) -> str:
    jwk = json.load(open(cfg.signing_key_path))
    issuance_key = {"type": "local", "jwk": json.dumps(jwk)}

    vc = json.load(open(cfg.vc_path))

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

    url_issue = cfg.issuer_api_base_url + "/openid4vc/jwt/issue"
    res_issue = requests.post(url_issue, headers={"Accept": "text/plain"}, json=data)
    res_issue.raise_for_status()
    credential_offer_url = res_issue.text
    logger.info(credential_offer_url)

    parsed_credential_offer = json.loads(
        unquote(credential_offer_url.split("credential_offer=")[1])
    )

    logger.info(pprint.pformat(parsed_credential_offer))

    return credential_offer_url


def accept_credential_offer(cfg: AppConfig, credential_offer_url: str):
    token = auth_login_wallet(
        cfg.wallet_api_base_url, cfg.wallet_user_email, cfg.wallet_user_password
    )

    headers = {"Authorization": "Bearer " + token}

    wallet_id = get_first_wallet_id(cfg, token)
    user_did_key = get_first_did(cfg, token, wallet_id)

    url_use_offer_request = (
        cfg.wallet_api_base_url
        + f"/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest"
    )

    res_use_offer_request = requests.post(
        url_use_offer_request,
        headers={**headers, **{"Accept": "*/*", "Content-Type": "text/plain"}},
        params={"did": user_did_key},
        data=credential_offer_url,
    )

    res_use_offer_request.raise_for_status()
    res_use_offer_request_json = res_use_offer_request.json()
    logger.info(pprint.pformat(res_use_offer_request_json))

    url_list_credentials = (
        cfg.wallet_api_base_url + f"/wallet-api/wallet/{wallet_id}/credentials"
    )

    res_list_credentials = requests.get(url_list_credentials, headers=headers)
    res_list_credentials.raise_for_status()
    logger.info(pprint.pformat(res_list_credentials.json()))


def main():
    cfg = environ.to_config(AppConfig)
    logger.info(cfg)
    create_wallet_user(cfg)
    create_signing_key(cfg)
    credential_offer_url = issue_credential(cfg)
    accept_credential_offer(cfg, credential_offer_url)


if __name__ == "__main__":
    main()
