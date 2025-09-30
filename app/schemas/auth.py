from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)
    name: Optional[str] = None


class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr


class VerifyEmailRequest(BaseModel):
    token: str


class VerifyEmailResponse(BaseModel):
    ok: bool = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    mfa_required: bool = False
    methods: list[str] = []
    challenge_id: Optional[str] = None
    webauthn: Optional['WebAuthnStartResponse'] = None


class SessionInfo(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_used_at: datetime
    ip: Optional[str]
    user_agent: Optional[str]
    current: bool = False


class SessionsResponse(BaseModel):
    sessions: list[SessionInfo]


class UserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    email_verified: bool
    role: str
    totp_enabled: bool


class TOTPSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TOTPVerifyRequest(BaseModel):
    code: str
    email: Optional[EmailStr] = None
    challenge_id: Optional[str] = None


class MFACompletionResponse(BaseModel):
    success: bool


class WebAuthnStartResponse(BaseModel):
    challenge_id: str
    publicKey: dict[str, Any]


class WebAuthnLoginStartRequest(BaseModel):
    email: EmailStr


class WebAuthnRegisterFinishRequest(BaseModel):
    challenge_id: str
    client_data_json: str
    attestation_object: str
    transports: Optional[list[str]] = None


class WebAuthnLoginFinishRequest(BaseModel):
    challenge_id: str
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str
    user_handle: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=10)


class SimpleResponse(BaseModel):
    ok: bool = True


class CSRFTokenResponse(BaseModel):
    csrf_token: str


class StepUpCheckResponse(BaseModel):
    requires_mfa: bool
    methods: list[str] = []

