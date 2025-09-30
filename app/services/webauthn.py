from __future__ import annotations

import base64
import pickle
import base64
import pickle
import uuid
from typing import Any, Optional

from fido2.server import Fido2Server
from fido2.webauthn import (
    AuthenticatorAssertionResponse,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db import models
from app.services.challenges import create_challenge, delete_challenge, get_challenge

_RP = PublicKeyCredentialRpEntity(id=settings.webauthn_rp_id, name=settings.webauthn_rp_name)
_server = Fido2Server(_RP)
def _b64decode(value: str) -> bytes:
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


async def start_registration(db: AsyncSession, user: models.User) -> dict[str, Any]:
    user_entity = PublicKeyCredentialUserEntity(
        id=user.id.bytes,
        name=user.email,
        display_name=user.email,
    )

    credentials = await db.execute(
        select(models.WebAuthnCredential).where(models.WebAuthnCredential.user_id == user.id)
    )
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=cred.id) for cred in credentials.scalars().all()
    ]

    options, state = _server.register_begin(
        user=user_entity,
        credentials=exclude_credentials,
        user_verification="preferred",
        authenticator_selection=None,
        attestation="direct",
        pub_key_cred_params=[
            PublicKeyCredentialParameters(type="public-key", alg=-7),
            PublicKeyCredentialParameters(type="public-key", alg=-257),
        ],
    )

    challenge_id = await create_challenge({
        "type": "webauthn_register",
        "user_id": str(user.id),
        "state": base64.b64encode(pickle.dumps(state)).decode("utf-8"),
    })

    return {
        "challenge_id": challenge_id,
        "publicKey": options.to_json(),
    }


async def finish_registration(
    db: AsyncSession,
    *,
    challenge_id: str,
    client_data_json: str,
    attestation_object: str,
    transports: Optional[list[str]],
) -> models.WebAuthnCredential:
    challenge = await get_challenge(challenge_id)
    if not challenge or challenge.get("type") != "webauthn_register":
        raise ValueError("Invalid challenge")

    state = pickle.loads(base64.b64decode(challenge["state"]))
    att_obj = _b64decode(attestation_object)
    client_data = _b64decode(client_data_json)

    auth_data = _server.register_complete(
        state,
        client_data,
        att_obj,
    )

    credential = models.WebAuthnCredential(
        id=auth_data.credential_id,
        user_id=uuid.UUID(challenge["user_id"]),
        public_key=auth_data.credential_public_key,
        sign_count=auth_data.counter,
        transports=",".join(transports or []),
    )
    db.add(credential)
    await db.flush()
    await delete_challenge(challenge_id)
    return credential


async def start_login(db: AsyncSession, user: models.User) -> dict[str, Any]:
    credentials = await db.execute(
        select(models.WebAuthnCredential).where(models.WebAuthnCredential.user_id == user.id)
    )
    creds = credentials.scalars().all()
    if not creds:
        raise ValueError("No credentials available")

    descriptors = [PublicKeyCredentialDescriptor(id=cred.id) for cred in creds]
    options, state = _server.authenticate_begin(descriptors, user_verification="preferred")
    challenge_id = await create_challenge({
        "type": "webauthn_login",
        "user_id": str(user.id),
        "state": base64.b64encode(pickle.dumps(state)).decode("utf-8"),
    })
    return {
        "challenge_id": challenge_id,
        "publicKey": options.to_json(),
    }


async def finish_login(
    db: AsyncSession,
    *,
    challenge_id: str,
    credential_id: str,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
    user_handle: Optional[str],
) -> models.WebAuthnCredential:
    challenge = await get_challenge(challenge_id)
    if not challenge or challenge.get("type") != "webauthn_login":
        raise ValueError("Invalid challenge")

    credential = await db.get(models.WebAuthnCredential, _b64decode(credential_id))
    if not credential:
        raise ValueError("Unknown credential")

    state = pickle.loads(base64.b64decode(challenge["state"]))

    assertion_response = AuthenticatorAssertionResponse(
        client_data=_b64decode(client_data_json),
        authenticator_data=_b64decode(authenticator_data),
        signature=_b64decode(signature),
        user_handle=_b64decode(user_handle) if user_handle else None,
    )

    _server.authenticate_complete(
        state,
        [PublicKeyCredentialDescriptor(id=credential.id)],
        credential.id,
        assertion_response,
    )

    credential.sign_count = assertion_response.authenticator_data.counter
    await db.flush()
    await delete_challenge(challenge_id)
    return credential

