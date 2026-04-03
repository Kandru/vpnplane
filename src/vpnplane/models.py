"""Pydantic v2 models for tunnel and route configuration."""

from __future__ import annotations

import base64
import ipaddress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_cidr(v: str) -> str:
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError(f"Invalid CIDR: {v!r}")
    return v


def _validate_cidr_list(v: list[str]) -> list[str]:
    return [_validate_cidr(x) for x in v]


def _validate_wg_key(v: str) -> str:
    try:
        decoded = base64.b64decode(v, validate=True)
        if len(decoded) != 32:
            raise ValueError("WireGuard key must decode to exactly 32 bytes")
    except Exception as exc:
        raise ValueError(f"Invalid WireGuard key: {exc}") from exc
    return v


# ---------------------------------------------------------------------------
# WireGuard models
# ---------------------------------------------------------------------------

class WireGuardPeer(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    public_key: str
    # "auto"  → tool generates + stores a PSK
    # Path    → read PSK from this file
    # None    → no PSK
    preshared_key: Literal["auto"] | Path | None = "auto"
    endpoint: str | None = None
    allowed_ips: list[str]
    persistent_keepalive: int = Field(default=0, ge=0, le=65535)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        return _validate_wg_key(v)

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, v: list[str]) -> list[str]:
        return _validate_cidr_list(v)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if ":" not in v:
            raise ValueError("endpoint must be in host:port format")
        host, port_str = v.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"endpoint port is not a number: {port_str!r}")
        if not (1 <= port <= 65535):
            raise ValueError(f"endpoint port out of range: {port}")
        return v

    @field_validator("preshared_key", mode="before")
    @classmethod
    def coerce_preshared_key(cls, v: object) -> object:
        if v is None or v == "auto":
            return v
        # Convert string paths to Path objects
        if isinstance(v, str):
            return Path(v)
        return v


class WireGuardTunnel(BaseModel):
    type: Literal["wireguard"] = "wireguard"
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,15}$")
    description: str = ""
    address: str
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    private_key: Path
    dns: list[str] = []
    mtu: int = Field(default=1420, ge=576, le=9000)
    table: str = "auto"
    fritzbox: bool = False
    post_up: list[str] = []
    post_down: list[str] = []
    peer: WireGuardPeer | None = None

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        return _validate_cidr(v)

    @field_validator("dns")
    @classmethod
    def validate_dns(cls, v: list[str]) -> list[str]:
        for entry in v:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                raise ValueError(f"Invalid DNS IP: {entry!r}")
        return v

    @model_validator(mode="after")
    def validate_fritzbox_address(self) -> WireGuardTunnel:
        if not self.fritzbox:
            return self

        iface = ipaddress.ip_interface(self.address)
        if iface.version != 4:
            raise ValueError("fritzbox=true currently supports IPv4 tunnel addresses only")
        if iface.network.prefixlen >= 32:
            raise ValueError("fritzbox=true requires a subnet address like 192.168.178.1/24, not /32")

        first_host = next(iface.network.hosts(), None)
        if first_host is None or iface.ip != first_host:
            raise ValueError(
                "fritzbox=true requires Address to use the FritzBox tunnel gateway IP "
                "(first usable host), e.g. 192.168.178.1/24"
            )

        return self

    @model_validator(mode="after")
    def private_key_must_exist(self) -> WireGuardTunnel:
        if not self.private_key.exists():
            raise ValueError(f"Private key file not found: {self.private_key}")
        return self


# ---------------------------------------------------------------------------
# IPSec models
# ---------------------------------------------------------------------------

class IPSecAuth(BaseModel):
    method: Literal["psk", "cert"]
    secret: Path | None = None   # path to PSK file when method=psk
    cert: Path | None = None     # path to certificate when method=cert
    key: Path | None = None      # path to private key when method=cert

    @model_validator(mode="after")
    def validate_auth_fields(self) -> IPSecAuth:
        if self.method == "psk" and self.secret is None:
            raise ValueError("auth.secret is required when method is 'psk'")
        if self.method == "cert" and (self.cert is None or self.key is None):
            raise ValueError("auth.cert and auth.key are required when method is 'cert'")
        return self


class IPSecSide(BaseModel):
    address: str
    subnets: list[str]
    auth: IPSecAuth

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @field_validator("subnets")
    @classmethod
    def validate_subnets(cls, v: list[str]) -> list[str]:
        return _validate_cidr_list(v)


class IKEConfig(BaseModel):
    version: Literal[2] = 2
    encryption: str = "aes256"
    integrity: str = "sha256"
    dh_group: str = "modp2048"
    lifetime: int = Field(default=86400, ge=60)


class ESPConfig(BaseModel):
    encryption: str = "aes256"
    integrity: str = "sha256"
    lifetime: int = Field(default=3600, ge=60)
    dpd_action: Literal["restart", "clear", "none"] = "restart"
    dpd_delay: int = Field(default=30, ge=0)


class IPSecTunnel(BaseModel):
    type: Literal["ipsec"] = "ipsec"
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    description: str = ""
    local: IPSecSide
    remote: IPSecSide
    ike: IKEConfig = Field(default_factory=IKEConfig)
    esp: ESPConfig = Field(default_factory=ESPConfig)
    auto_start: bool = True


# ---------------------------------------------------------------------------
# Route models
# ---------------------------------------------------------------------------

class RouteEndpoint(BaseModel):
    interface: str
    subnets: list[str] = []

    @field_validator("subnets")
    @classmethod
    def validate_subnets(cls, v: list[str]) -> list[str]:
        return _validate_cidr_list(v)


class RouteRule(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    from_: RouteEndpoint = Field(alias="from")
    to: RouteEndpoint
    protocol: Literal["tcp", "udp", "icmp", "any"] = "any"
    ports: list[int] = []
    bidirectional: bool = True
    action: Literal["allow", "deny"] = "allow"
    comment: str = ""

    model_config = {"populate_by_name": True}

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_nat_keys(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data

        removed = [
            key for key in ("nat", "nat_mode", "snat", "snat_peer_ip", "snat_fallback_ip")
            if key in data
        ]
        if removed:
            raise ValueError(
                "Removed route keys are no longer supported: "
                + ", ".join(removed)
                + ". Remove them from route YAML."
            )
        return data

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of range")
        return v

    @model_validator(mode="after")
    def ports_require_protocol(self) -> RouteRule:
        if self.ports and self.protocol == "icmp":
            raise ValueError("ports cannot be specified with protocol 'icmp'")
        if self.ports and self.protocol == "any":
            raise ValueError("ports require protocol 'tcp' or 'udp'")
        return self


# ---------------------------------------------------------------------------
# Top-level config containers
# ---------------------------------------------------------------------------

AnyTunnel = Annotated[WireGuardTunnel | IPSecTunnel, Field(discriminator="type")]


def load_tunnel(data: dict) -> WireGuardTunnel | IPSecTunnel:
    """Deserialize a tunnel config dict using the 'type' discriminator."""
    tunnel_type = data.get("type", "wireguard")
    if tunnel_type == "wireguard":
        return WireGuardTunnel.model_validate(data)
    elif tunnel_type == "ipsec":
        return IPSecTunnel.model_validate(data)
    else:
        raise ValueError(f"Unknown tunnel type: {tunnel_type!r}")


def load_route(data: dict) -> RouteRule:
    """Deserialize a route rule config dict."""
    return RouteRule.model_validate(data)
