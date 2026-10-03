# Impossible reviewed adware definitions

Signed public detection data for the Impossible Android app. No app inventory, personal data, APK samples or private signing key are stored here.

## Coverage

Version2 contains27 exact APK SHA256 indicators:26 from Zimperium zLabs’ July2025 Konfety campaign and one historical Unit42 indicator. This is narrow documented campaign coverage. Advertising SDK presence and an app’s installer are not malware verdicts. An exact match does not prove that an observed popup came from that app.

## Authenticity and updates

The Android app validates the ECDSA signature with its pinned public key, expiry, schema, size and monotonic version before accepting data. HTTPS hosting alone is not the trust decision. No download-supplied key is accepted. Definition renewal requires reviewed source facts and a newly signed higher version; it never automatically approves new indicators.

## Sources and terms

Zimperium campaign: https://zimperium.com/blog/konfety-returns-classic-mobile-threat-with-new-evasion-techniques

Pinned factual APK indicators: https://github.com/Zimperium/IOC/blob/17c1b2ff70e65eb8d3de44ccc1c0106822523aa5/2025-07-Konfety/apks.csv

Zimperium’s published terms invite downloading and integrating indicators for detection and mobile threat hunting, provided as-is for defensive use: https://github.com/Zimperium/IOC/blob/17c1b2ff70e65eb8d3de44ccc1c0106822523aa5/README.md

The legitimate mimicked package list is excluded. No vendor report prose, illustrations, malware samples or proprietary tools are included. No vendor endorsement is implied.

Unit42 historical indicator: https://unit42.paloaltonetworks.com/patient-zero-web-threats/ ; original MIT IoC notice accompanies this feed.

## Separate SDK inspection data

The app’s neutral Exodus advertising-library database, original input, transformation and attribution are available under [sdk/](sdk/). These signatures are separate from the signed malware-identity feed.
