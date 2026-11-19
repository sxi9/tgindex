"""Parse t.me/s/<channel> preview HTML into structured records."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional
from urllib.parse import unquote, urlparse

from lxml import html as LH

M = "//div[contains(concat(' ',normalize-space(@class),' '),' tgme_widget_message ') and @data-post]"
_COUNT_RE = re.compile(r"^([\d.,]+)\s*([KMB]?)$", re.I)
_MULT = {"": 1, "K": 1_000, "M": 1_000_000, "B": 1_000_000_000}
_POST_RE = re.compile(r"^/?([A-Za-z0-9_]{3,32})/(\d+)")
_BLOCKS = {"br", "p", "div", "blockquote", "pre", "li", "tr"}


def parse_count(raw: Optional[str]) -> Optional[int]:
    """'4.45M' -> 4450000. Telegram abbreviates; we store an integer."""
    if not raw:
        return None
    m = _COUNT_RE.match(raw.strip().replace(" ", "").replace(" ", ""))
    if not m:
        return None
    num, suffix = m.group(1).replace(",", ""), m.group(2).upper()
    try:
        return int(float(num) * _MULT[suffix])
    except (ValueError, KeyError):
        return None


def _text_with_breaks(el) -> str:
    """text_content() loses <br>, which destroys line structure in posts."""
    out: list[str] = []

    def walk(node):
        if node.tag == "br":
            out.append("\n")
        if node.text:
            out.append(node.text)
        for child in node:
            walk(child)
            if isinstance(child.tag, str) and child.tag in _BLOCKS:
                out.append("\n")
            if child.tail:
                out.append(child.tail)

    walk(el)
    text = "".join(out)
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _split_post(href_or_post: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    if not href_or_post:
        return None, None
    path = urlparse(href_or_post).path if "//" in href_or_post else href_or_post
    m = _POST_RE.match(unquote(path).lstrip("/"))
    if not m:
        return None, None
    return m.group(1).lower(), int(m.group(2))


@dataclass
class Message:
    channel: str
    msg_id: int
    uid: str
    date: Optional[str] = None
    text: str = ""
    views: Optional[int] = None
    author: Optional[str] = None
    fwd_channel: Optional[str] = None
    fwd_msg_id: Optional[int] = None
    fwd_name: Optional[str] = None
    reply_channel: Optional[str] = None
    reply_msg_id: Optional[int] = None
    media: list[str] = field(default_factory=list)
    preview_url: Optional[str] = None
    preview_title: Optional[str] = None
    preview_site: Optional[str] = None
    preview_desc: Optional[str] = None
    outlinks: list[str] = field(default_factory=list)
    content_hash: str = ""

    @property
    def canonical_uid(self) -> str:
        """Forward origin if known, else self. Collapses viral reposts."""
        if self.fwd_channel and self.fwd_msg_id:
            return f"{self.fwd_channel}/{self.fwd_msg_id}"
        return self.uid

    @property
    def url(self) -> str:
        return f"https://t.me/{self.channel}/{self.msg_id}"


@dataclass
class ChannelInfo:
    username: str
    title: Optional[str] = None
    description: Optional[str] = None
    subscribers: Optional[int] = None
    photo: Optional[str] = None


def _first(el, xp: str) -> Optional[str]:
    r = el.xpath(xp)
    if not r:
        return None
    v = r[0]
    return v.strip() if isinstance(v, str) else _text_with_breaks(v)


def _channel_username(doc) -> str:
    """og:url is absent on these pages; the header anchor is the reliable source."""
    href = _first(doc, "//div[contains(@class,'tgme_channel_info_header_username')]//a/@href")
    if href:
        name = urlparse(href).path.strip("/").split("/")[0]
        if re.fullmatch(r"[A-Za-z0-9_]{3,32}", name or ""):
            return name.lower()
    canon = _first(doc, "//link[@rel='canonical']/@href") or ""
    m = re.search(r"/s/([A-Za-z0-9_]{3,32})", canon)
    if m:
        return m.group(1).lower()
    post = _first(doc, M + "/@data-post")
    return (_split_post(post)[0] or "")


def parse_channel(doc) -> ChannelInfo:
    info = ChannelInfo(username=_channel_username(doc))
    info.title = _first(doc, "//div[contains(@class,'tgme_channel_info_header_title')]//span/text()") or _first(
        doc, "//meta[@property='og:title']/@content"
    )
    info.description = _first(doc, "//div[contains(@class,'tgme_channel_info_description')]")
    info.photo = _first(doc, "//meta[@property='og:image']/@content")
    for counter in doc.xpath("//div[contains(@class,'tgme_channel_info_counter')]"):
        ctype = (_first(counter, ".//span[contains(@class,'counter_type')]/text()") or "").lower()
        if ctype.startswith("subscriber") or ctype.startswith("member"):
            info.subscribers = parse_count(
                _first(counter, ".//span[contains(@class,'counter_value')]/text()")
            )
    return info


def _media_types(el) -> list[str]:
    checks = {
        "photo": ".//a[contains(@class,'tgme_widget_message_photo_wrap')]",
        "video": ".//*[contains(@class,'tgme_widget_message_video')]",
        "voice": ".//*[contains(@class,'tgme_widget_message_voice')]",
        "document": ".//*[contains(@class,'tgme_widget_message_document')]",
        "sticker": ".//*[contains(@class,'tgme_widget_message_sticker')]",
        "poll": ".//*[contains(@class,'tgme_widget_message_poll')]",
        "location": ".//*[contains(@class,'tgme_widget_message_location')]",
    }
    return sorted(k for k, xp in checks.items() if el.xpath(xp))


def parse_messages(doc) -> Iterator[Message]:
    for el in doc.xpath(M):
        channel, msg_id = _split_post(el.get("data-post"))
        if not channel or msg_id is None:
            continue
        m = Message(channel=channel, msg_id=msg_id, uid=f"{channel}/{msg_id}")

        m.date = _first(el, ".//time/@datetime")
        body = el.xpath(".//div[contains(@class,'tgme_widget_message_text') and contains(@class,'js-message_text')]")
        if body:
            m.text = _text_with_breaks(body[0])

        m.views = parse_count(_first(el, ".//span[contains(@class,'tgme_widget_message_views')]/text()"))
        m.author = _first(el, ".//span[contains(@class,'tgme_widget_message_from_author')]/text()")

        fwd = el.xpath(".//a[contains(@class,'tgme_widget_message_forwarded_from_name')]")
        if fwd:
            m.fwd_channel, m.fwd_msg_id = _split_post(fwd[0].get("href"))
            m.fwd_name = _text_with_breaks(fwd[0]) or None
        else:
            name = _first(el, ".//span[contains(@class,'tgme_widget_message_forwarded_from_name')]")
            if name:
                m.fwd_name = name

        reply = el.xpath(".//a[contains(@class,'tgme_widget_message_reply')]")
        if reply:
            m.reply_channel, m.reply_msg_id = _split_post(reply[0].get("href"))

        m.media = _media_types(el)

        lp = el.xpath(".//a[contains(@class,'tgme_widget_message_link_preview')]")
        if lp:
            m.preview_url = lp[0].get("href")
            m.preview_title = _first(lp[0], ".//div[contains(@class,'link_preview_title')]")
            m.preview_site = _first(lp[0], ".//div[contains(@class,'link_preview_site_name')]")
            m.preview_desc = _first(lp[0], ".//div[contains(@class,'link_preview_description')]")

        seen = set()
        for href in el.xpath(".//div[contains(@class,'tgme_widget_message_text')]//a/@href"):
            if href.startswith(("http://", "https://")) and href not in seen:
                seen.add(href)
                m.outlinks.append(href)

        basis = (m.text or "") + "|" + "|".join(m.media) + "|" + (m.preview_url or "")
        m.content_hash = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:32]
        yield m


def next_before(doc) -> Optional[int]:
    """Cursor for the next page back, or None at the start of history."""
    for attr in doc.xpath("//a[contains(@class,'tme_messages_more')]/@data-before"):
        try:
            return int(attr)
        except ValueError:
            continue
    return None


def parse_page(text: str):
    doc = LH.fromstring(text)
    return parse_channel(doc), list(parse_messages(doc)), next_before(doc)


def to_epoch(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        return int(datetime.fromisoformat(iso).astimezone(timezone.utc).timestamp())
    except ValueError:
        return None
