# Exodus Privacy / ETIP attribution and corresponding data

Contains information from Exodus Privacy / ETIP: https://etip.exodus-privacy.eu.org/trackers/export . Snapshot retrieved2October2026. Original notices: https://github.com/Exodus-Privacy/etip/blob/master/README.md .

The adapted advertising-library database (`exodus-sdk.json`) is available under the Open Database License1.0: https://opendatacommons.org/licenses/odbl/1-0/ . Individual contents are under the Database Contents License1.0: https://opendatacommons.org/licenses/dbcl/1-0/ . These terms apply to this SDK data separately from the app and the reviewed adware indicator feed.

`source-trackers.json` is the unmodified input. `prepare_sdk_definitions.py` is the full deterministic transformation, selecting accepted Advertisement entries and supported literal signatures. Unsupported regex signatures are retained as excluded/unsupported data and never executed. Reproduce with:

    python3 prepare_sdk_definitions.py --source source-trackers.json --output reproduced.json

119 advertising SDK signatures are included. Finding one means code or a packaged reference is present. It does not establish execution, a network connection, popup ownership or malware. These are not119 adware verdict rules.
