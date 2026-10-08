# Third-Party Notices

DN Scout is licensed under the MIT License. The project depends on or may package the following third-party software. This file is provided for attribution and release transparency; the authoritative license terms are the licenses distributed by each upstream project.

| Component | Purpose | License | Upstream |
|---|---|---|---|
| Python | Runtime for source execution / packaged application | Python Software Foundation License | https://www.python.org/psf/license/ |
| Requests | HTTPS/HTTP client | Apache License 2.0 | https://requests.readthedocs.io/ |
| urllib3 | HTTP transport dependency used by Requests | MIT License | https://urllib3.readthedocs.io/ |
| certifi | CA certificate bundle dependency used by Requests | Mozilla Public License 2.0 | https://github.com/certifi/python-certifi |
| charset-normalizer | Character encoding dependency used by Requests | MIT License | https://github.com/jawah/charset_normalizer |
| idna | Internationalized domain name dependency used by Requests | BSD 3-Clause License | https://github.com/kjd/idna |
| sv-ttk | Optional light/dark Tk theme | MIT License | https://github.com/rdbende/Sun-Valley-ttk-theme |
| PyInstaller | Windows executable build tooling/bootloader | GPL-2.0-or-later with PyInstaller bootloader exception | https://pyinstaller.org/ |

PyInstaller is a build dependency rather than an application API dependency, but official Windows artifacts use its bootloader/runtime packaging and therefore it is included in these notices.

Before redistributing a modified binary, confirm the licenses/notices for the exact dependency versions included in that build.
