# Impossible Adware Remover — reviewed definitions

Signed public detection data for the Impossible Adware Remover Android app. No app inventory, personal data, APK samples or private signing key are stored here.

## Coverage

Version 4 contains 61 exact APK SHA256 indicators: 26 from Zimperium zLabs’ July2025 Konfety campaign, one historical Unit42 indicator, 25 Symantec-reported historical artifacts, five additional historical artifacts measured from unchanged APK bytes linked to primary MD5 reports, and four Jamf-reported MobiDash APKs from May2026. This is narrow documented campaign coverage. Advertising SDK presence and an app’s installer are not malware verdicts. An exact match does not prove that an observed popup came from that app.

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

## Historical campaign additions in version 3

Exact historical artifact identifiers are attributed to these primary reports:

- https://www.security.com/threat-intelligence/hidden-adware-google-play (2019-09-23; 25 APK SHA256s)
- https://securelist.com/in-app-advertising-in-android/97065/ (2020-05-25)
- https://www.sonicwall.com/blog/android-adware-that-delays-its-advertisements (2020-01-30)
- https://www.bitdefender.com/en-au/blog/labs/seventeen-android-nasties-spotted-in-google-play-total-over-550k-downloads (2020-01-14)

The latter three reports publish MD5 identifiers. Five distinct additional SHA256s were measured over the same unchanged complete original APK bytes that match those reported MD5s and package context. No MD5 string was converted mathematically to SHA256; 96 unique unresolved MD5 indicators remain excluded. One measured artifact is covered by two reports.

Only attributed factual artifact identifiers and source URLs are distributed here. No report prose, images, original malware APKs, proprietary software, source report files or database compilation is supplied. No vendor licence or endorsement is claimed for these factual historical indicators. Exact affected builds cannot implicate clean updates, legitimate same-label apps or all versions of a package.

The earlier five locally tested original APKs are included as disclosed regression fixtures. Their previous misses remain failures of the earlier one-indicator set. Inclusion here is not fresh independent detection accuracy evidence or proof that archived ad infrastructure is active.

## MobiDash additions in version 4

Four exact whole-APK SHA256 facts are attributed to Jamf Threat Labs’ May13,2026 report:
https://www.jamf.com/blog/mobidash-android-ad-fraud-click-injection-analysis/

Only factual artifact identifiers and the source URL are included. No report prose, images, software or original APKs are distributed; no vendor licence or endorsement is claimed. These four additions have not been tested against acquired original samples. They do not match an entire package, signer, advertising SDK or unreported variant. Source-reported adware classification does not prove ownership of a current popup. The previous57 exact rule objects are unchanged.
