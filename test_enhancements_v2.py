"""Tests for enhancements: device sync (reactions & groups), WebSocket bridging,
group unread isolation, and accessibility improvements."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

import chat
from chat import (
    ChatHTTPHandler,
    QuantumNode,
    canonical_json,
)


def make_node(tmp_path: Path, name: str) -> QuantumNode:
    db_file = tmp_path / f"{name}.db"
    node = QuantumNode(str(db_file), "ws://127.0.0.1:65535", direct_url=None, enable_direct=False)
    node.allow_remote_ui = False
    return node


def test_device_sync_reaction_handling(tmp_path: Path) -> None:
    """Verify that _handle_device_sync adds and removes reactions correctly."""
    node = make_node(tmp_path, "node_sync_react")
    broadcasted: list[dict[str, Any]] = []

    async def mock_broadcast_ui(msg: dict[str, Any]) -> None:
        broadcasted.append(msg)

    node.broadcast_ui = mock_broadcast_ui

    # First save a message to react to
    msg_id = "msg-sync-react-1"
    peer = "11" * 32
    node.db.save_message(msg_id, peer, "Hello!", "in", delivered=True, status="delivered")

    key = node.crypto.derive_device_sync_key(node.secret_key)

    # Sync an added reaction
    sync_add_body = canonical_json({
        "event": "reaction",
        "data": {
            "msg_id": msg_id,
            "peer": peer,
            "emoji": "🔥",
            "action": "add",
        },
    })
    packet_add = node.crypto.encrypt(key, sync_add_body)
    envelope_add = node.signed_payload("device_sync", {"packet": packet_add})

    asyncio.run(node._handle_device_sync(node.public_key, envelope_add))

    reactions = node.db.get_reactions([msg_id]).get(msg_id, [])
    assert len(reactions) == 1
    assert reactions[0]["emoji"] == "🔥"
    assert reactions[0]["peer_pubkey"] == peer
    assert len(broadcasted) == 1
    assert broadcasted[0]["type"] == "reaction"
    assert broadcasted[0]["action"] == "add"

    # Sync removing the reaction
    sync_rm_body = canonical_json({
        "event": "reaction",
        "data": {
            "msg_id": msg_id,
            "peer": peer,
            "emoji": "🔥",
            "action": "remove",
        },
    })
    packet_rm = node.crypto.encrypt(key, sync_rm_body)
    envelope_rm = node.signed_payload("device_sync", {"packet": packet_rm})

    asyncio.run(node._handle_device_sync(node.public_key, envelope_rm))

    reactions_after = node.db.get_reactions([msg_id]).get(msg_id, [])
    assert len(reactions_after) == 0
    assert len(broadcasted) == 2
    assert broadcasted[1]["action"] == "remove"


def test_device_sync_group_chat_no_friend_unread_bump(tmp_path: Path) -> None:
    """Group chat messages synced from another device should NOT increment 1:1 unread badge."""
    node = make_node(tmp_path, "node_sync_group")
    broadcasted: list[dict[str, Any]] = []

    async def mock_broadcast_ui(msg: dict[str, Any]) -> None:
        broadcasted.append(msg)

    node.broadcast_ui = mock_broadcast_ui

    sender = "22" * 32
    node.db.add_friend(sender, nickname="Sender")
    friend = [f for f in node.db.get_friends() if f["pubkey"] == sender][0]
    assert friend["unread"] == 0

    key = node.crypto.derive_device_sync_key(node.secret_key)
    group_msg_body = canonical_json({
        "event": "chat_in",
        "data": {
            "msg_id": "group-msg-123",
            "sender_pubkey": sender,
            "recipient_pubkey": node.public_key,
            "group_id": "grp-abc-999",
            "body": "Team meeting at 3pm",
            "delivered": True,
            "status": "delivered",
        },
    })
    packet_group = node.crypto.encrypt(key, group_msg_body)
    envelope_group = node.signed_payload("device_sync", {"packet": packet_group})

    asyncio.run(node._handle_device_sync(node.public_key, envelope_group))

    # Sender's private 1:1 unread count must remain 0!
    friend = [f for f in node.db.get_friends() if f["pubkey"] == sender][0]
    assert friend["unread"] == 0
    assert len(broadcasted) == 1
    assert broadcasted[0]["message"]["group_id"] == "grp-abc-999"

    # Regular 1:1 message sync DOES increment unread
    dm_msg_body = canonical_json({
        "event": "chat_in",
        "data": {
            "msg_id": "dm-msg-456",
            "sender_pubkey": sender,
            "recipient_pubkey": node.public_key,
            "group_id": None,
            "body": "Hey privately",
            "delivered": True,
            "status": "delivered",
        },
    })
    packet_dm = node.crypto.encrypt(key, dm_msg_body)
    envelope_dm = node.signed_payload("device_sync", {"packet": packet_dm})

    asyncio.run(node._handle_device_sync(node.public_key, envelope_dm))
    friend = [f for f in node.db.get_friends() if f["pubkey"] == sender][0]
    assert friend["unread"] == 1


def _relative_luminance(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4))

    def linearize(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)


def _contrast_ratio(fg: str, bg: str) -> float:
    l1, l2 = sorted((_relative_luminance(fg), _relative_luminance(bg)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


def test_ui_contrast_variables() -> None:
    """Verify UI text contrast variables adhere to WCAG AA.

    The v4 glass theme computes ratios against the solid fallback surfaces
    (what the page degrades to without backdrop-filter) rather than asserting
    exact hex literals, so the palette can evolve while the guarantee holds.
    """
    import re

    def css_var(name: str) -> str:
        match = re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})", chat.HTML)
        assert match, f"--{name} must be defined as a 6-digit hex color"
        return match.group(1)

    # Darkest backgrounds text can sit on: the page background and the
    # solid-fallback glass surface (no-support branch).
    surfaces = ["#070b13", "#0f1521", "#1a2437"]
    for name in ("text1", "text2", "text3"):
        fg = css_var(name)
        for bg in surfaces:
            ratio = _contrast_ratio(fg, bg)
            assert ratio >= 4.5, (
                f"--{name} ({fg}) on {bg} is {ratio:.2f}:1 — below WCAG AA (4.5:1)"
            )


def test_websocket_bridge_in_http_handler() -> None:
    """Test ChatHTTPHandler WebSocket upgrade detection and handling."""
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/?token=secret123"
    handler.headers = {"Host": "127.0.0.1:8080", "Upgrade": "websocket"}
    handler.require_http_auth = False
    handler._host_allowed = lambda: True

    bridge_called = []
    handler._bridge_websocket = lambda: bridge_called.append(True)
    handler.send_error = lambda code, msg="": pytest.fail(f"Unexpected send_error {code}: {msg}")

    ChatHTTPHandler.do_GET(handler)
    assert bridge_called == [True]


def test_websocket_bridge_requires_auth_when_configured() -> None:
    """When require_http_auth is True, unauthenticated WebSocket upgrades are rejected."""
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/?token=wrong"
    handler.headers = {"Host": "remote-host.com", "Upgrade": "websocket"}
    handler.require_http_auth = True
    handler._host_allowed = lambda: True
    handler._http_authenticated = lambda parsed: False

    errors = []
    handler.send_error = lambda code, msg="": errors.append((code, msg))
    handler._bridge_websocket = lambda: pytest.fail("Bridge should not be called when unauthenticated")

    ChatHTTPHandler.do_GET(handler)
    assert len(errors) == 1
    assert errors[0][0] == 401
