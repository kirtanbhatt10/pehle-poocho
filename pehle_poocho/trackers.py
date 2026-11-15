"""Known third-party tracking services and a small registrable-domain helper."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class Tracker:
    domain: str
    vendor: str
    category: str


CATEGORY_SEVERITY = {
    "advertising": "high",
    "session-replay": "high",
    "attribution": "high",
    "analytics": "medium",
    "marketing": "medium",
    "tag-manager": "low",
    "monitoring": "low",
}

_CATALOGUE = {
    "advertising": {
        "doubleclick.net": "Google Ads (DoubleClick)",
        "googlesyndication.com": "Google AdSense",
        "googleadservices.com": "Google Ads",
        "facebook.net": "Meta Pixel",
        "facebook.com": "Meta Pixel",
        "ads.linkedin.com": "LinkedIn Insight Tag",
        "snap.licdn.com": "LinkedIn Insight Tag",
        "ads-twitter.com": "X Ads",
        "analytics.tiktok.com": "TikTok Pixel",
        "bat.bing.com": "Microsoft Advertising",
        "ct.pinterest.com": "Pinterest Tag",
        "tr.snapchat.com": "Snap Pixel",
        "sc-static.net": "Snap Pixel",
        "criteo.com": "Criteo",
        "criteo.net": "Criteo",
        "taboola.com": "Taboola",
        "outbrain.com": "Outbrain",
        "adnxs.com": "Xandr",
        "amazon-adsystem.com": "Amazon Ads",
        "crwdcntrl.net": "Lotame",
        "quantserve.com": "Quantcast",
    },
    "analytics": {
        "google-analytics.com": "Google Analytics",
        "analytics.google.com": "Google Analytics",
        "mixpanel.com": "Mixpanel",
        "segment.io": "Segment",
        "segment.com": "Segment",
        "amplitude.com": "Amplitude",
        "heapanalytics.com": "Heap",
        "posthog.com": "PostHog",
        "mc.yandex.ru": "Yandex Metrica",
        "scorecardresearch.com": "Comscore",
        "hs-analytics.net": "HubSpot Analytics",
    },
    "session-replay": {
        "clarity.ms": "Microsoft Clarity",
        "hotjar.com": "Hotjar",
        "hotjar.io": "Hotjar",
        "fullstory.com": "FullStory",
        "mouseflow.com": "Mouseflow",
        "smartlook.com": "Smartlook",
        "lr-ingest.io": "LogRocket",
        "contentsquare.net": "Contentsquare",
    },
    "attribution": {
        "branch.io": "Branch",
        "app.link": "Branch",
        "appsflyer.com": "AppsFlyer",
        "adjust.com": "Adjust",
        "singular.net": "Singular",
    },
    "marketing": {
        "moengage.com": "MoEngage",
        "clevertap.com": "CleverTap",
        "clevertap-prod.com": "CleverTap",
        "webengage.com": "WebEngage",
        "netcoresmartech.com": "Netcore",
        "onesignal.com": "OneSignal",
        "hs-scripts.com": "HubSpot",
        "klaviyo.com": "Klaviyo",
    },
    "tag-manager": {
        "googletagmanager.com": "Google Tag Manager",
    },
    "monitoring": {
        "nr-data.net": "New Relic",
        "sentry.io": "Sentry",
    },
}

TRACKERS = {
    domain: Tracker(domain, vendor, category)
    for category, entries in _CATALOGUE.items()
    for domain, vendor in entries.items()
}

_MULTI_PART_SUFFIXES = frozenset(
    """
    co.in net.in org.in gov.in ac.in edu.in res.in firm.in gen.in ind.in nic.in mil.in
    co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp com.sg com.my co.za
    com.br com.cn
    """.split()
)


def _clean(host: str) -> str:
    return host.strip().lower().rstrip(".")


def match_tracker(host: str) -> Tracker | None:
    parts = _clean(host).split(".")
    for i in range(len(parts)):
        found = TRACKERS.get(".".join(parts[i:]))
        if found:
            return found
    return None


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) without the Public Suffix List."""
    host = _clean(host)
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
