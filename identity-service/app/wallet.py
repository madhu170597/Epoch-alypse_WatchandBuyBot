"""Wallet: dummy payment cards + shipping addresses per user.

DEMO ONLY. No real card data is accepted or stored: the PAN is validated for
shape (Luhn) and then discarded — only the brand, last 4 digits, expiry and a
generated opaque instrument id (`dmtok_…`) are kept. Use test PANs such as
4242 4242 4242 4242. This keeps the demo realistic without ever holding a real
card number.
"""

import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app import store
from app.auth import require_user

router = APIRouter(prefix="/wallet", tags=["wallet"])


class CardBody(BaseModel):
    number: str = Field(..., description="Test PAN; stored only as last4 + brand")
    exp_month: int = Field(..., ge=1, le=12)
    exp_year: int = Field(..., ge=2024, le=2099)
    holder: str = ""


class AddressBody(BaseModel):
    name: str
    line1: str
    line2: str = ""
    city: str
    region: str = ""
    postal: str = ""
    country: str = "US"


def _luhn_ok(pan: str) -> bool:
    digits = [int(c) for c in pan if c.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _brand(pan: str) -> str:
    if pan.startswith("4"):
        return "Visa"
    if pan[:2] in {"34", "37"}:
        return "Amex"
    if pan[:2] in {"51", "52", "53", "54", "55"} or pan[:4].isdigit() and 2221 <= int(pan[:4]) <= 2720:
        return "Mastercard"
    if pan.startswith("6"):
        return "Discover"
    return "Card"


@router.post("/cards")
def add_card(body: CardBody, user: dict = Depends(require_user)) -> dict:
    pan = "".join(c for c in body.number if c.isdigit())
    if not _luhn_ok(pan):
        raise HTTPException(status_code=400, detail="invalid card number")
    card = {
        "brand": _brand(pan),
        "last4": pan[-4:],
        "exp_month": body.exp_month,
        "exp_year": body.exp_year,
        "holder": body.holder,
        "instrument_id": "dmtok_" + secrets.token_hex(8),
    }
    store.add_card(user["uid"], card)  # pan is never stored
    return {"id": card["instrument_id"], **card}


@router.get("/cards")
def list_cards(user: dict = Depends(require_user)) -> dict:
    return {"cards": store.list_cards(user["uid"])}


@router.delete("/cards/{card_id}")
def delete_card(card_id: str, user: dict = Depends(require_user)) -> dict:
    store.delete_card(user["uid"], card_id)
    return {"ok": True}


@router.post("/addresses")
def add_address(body: AddressBody, user: dict = Depends(require_user)) -> dict:
    addr_id = store.add_address(user["uid"], body.model_dump())
    return {"id": addr_id, **body.model_dump()}


@router.get("/addresses")
def list_addresses(user: dict = Depends(require_user)) -> dict:
    return {"addresses": store.list_addresses(user["uid"])}


@router.delete("/addresses/{addr_id}")
def delete_address(addr_id: str, user: dict = Depends(require_user)) -> dict:
    store.delete_address(user["uid"], addr_id)
    return {"ok": True}
