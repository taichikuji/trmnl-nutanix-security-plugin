# Nutanix Security for TRMNL

## Setup

From the repository root, build the private plugin ZIP:

```sh
python3 scripts/package-import.py
```

On the [Private Plugins page](https://trmnl.com/plugin_settings?keyname=private_plugin), select **Import new** and upload `dist/trmnl-nutanix-sec-plugin.zip`. Choose **Table to display** in the plugin settings. **Product (NXVD)** applies to the vulnerabilities table.

For manual setup, create a private plugin with Polling, an empty polling URL, Node Serverless and a 360-minute refresh interval. Copy the form fields from [settings.yml](src/settings.yml), paste [transform.js](src/transform.js) into Serverless, and copy the five Liquid files to their matching markup tabs.

## Icon

The listing icon is available at [media/icon.svg](media/icon.svg). Upload it separately from the private plugin ZIP.

## Previews

Recorded on November 20, 2026 using public Nutanix data.

| Security Advisories | Full | Half horizontal | Half vertical | Quadrant |
| --- | --- | --- | --- | --- |
| OG | ![Full](media/preview_full.webp) | ![Half horizontal](media/preview_half_horizontal.webp) | ![Half vertical](media/preview_half_vertical.webp) | ![Quadrant](media/preview_quadrant.webp) |
| X | ![Full](media/preview_trmnl_x.webp) | ![Half horizontal](media/preview_trmnl_x_half_horizontal.webp) | ![Half vertical](media/preview_trmnl_x_half_vertical.webp) | ![Quadrant](media/preview_trmnl_x_quadrant.webp) |

| NXVD | Full | Half horizontal | Half vertical | Quadrant |
| --- | --- | --- | --- | --- |
| OG | ![Full](media/preview_nxvd_full.webp) | ![Half horizontal](media/preview_nxvd_half_horizontal.webp) | ![Half vertical](media/preview_nxvd_half_vertical.webp) | ![Quadrant](media/preview_nxvd_quadrant.webp) |
| X | ![Full](media/preview_nxvd_trmnl_x.webp) | ![Half horizontal](media/preview_nxvd_trmnl_x_half_horizontal.webp) | ![Half vertical](media/preview_nxvd_trmnl_x_half_vertical.webp) | ![Quadrant](media/preview_nxvd_trmnl_x_quadrant.webp) |

## Templates

[Shared Liquid](src/shared.liquid) renders both briefs. Advisories leads with the latest publication. NXVD leads with the first released fix on the CVSS-ranked page and shows its product, package and fixed release when available.

The full OG view stacks the lead and table. The full landscape X view uses a separate lead panel beside a wider table with dedicated publication dates or product and fixed-release columns. Portrait views stack the content. The OG quadrant shows one featured item, and the X quadrant also fits a short table. [TRMNL X layout guide](https://trmnl.com/framework/docs/3.4/trmnl_x_guide)

The native table fits rows to the space available. These landscape previews use the same public data for both devices. Counts include the featured item and vary with the feed, title lengths, and display scale. [TRMNL table overflow](https://trmnl.com/framework/docs/3.4/table_overflow)

| Layout | OG Advisories | X Advisories | OG NXVD | X NXVD |
| --- | ---: | ---: | ---: | ---: |
| Full | 9 | 22 | 8 | 15 |
| Half horizontal | 6 | 9 | 6 | 8 |
| Half vertical | 9 | 16 | 8 | 15 |
| Quadrant | 1 | 6 | 1 | 5 |

The sample NXVD page supplied 15 fixes. The full landscape X regression shows all 20 fixes on a filled page.

## Data behavior

Each refresh makes one request to the selected Nutanix feed. Advisories uses a GET and displays publication dates. NXVD uses a POST for the first page in descending CVSS order, with a product filter when selected. Nutanix can return fewer than the requested 20 rows, and the counts on screen cover only released fixes in that page. Check deployed versions separately to determine which fixes a cluster has.

The public NXVD response has no publication date field. In testing, `DATE`, `PUBLICATION_DATE` and `RELEASE_DATE` returned the same rows in the same order as an unknown sort column.

The portal endpoints are undocumented and may change. Empty responses and source errors have separate messages. To diagnose a refresh failure, enable **Debug Logs** in the private plugin settings.

## Checks

With Node.js 22, Python 3 and Docker installed, run from the repository root:

```sh
node --test TRMNL/tests/transform.test.cjs
./scripts/preview
docker run --rm --volume "$PWD/TRMNL:/plugin" trmnl/trmnlp:v0.32.3 lint
python3 scripts/package-import.py
```

The preview tests run the real transform against mocked Nutanix responses. They cover both briefs, empty data and an HTTP error in all four layouts on OG and X in landscape and portrait. Screenshots are written to `TRMNL/_build/previews/` and the HTML report is at `TRMNL/_build/report/index.html`.

## Publish

[Check plugin](../.github/workflows/check.yml) runs the tests, renders layouts, lints templates and builds the import ZIP. [Publish to TRMNL](../.github/workflows/publish.yml) runs these checks before publishing changes to `TRMNL/src/` on `main`. It can also be triggered manually.

Set the `TRMNL_API_KEY` and `TRMNL_PLUGIN_SETTING_ID` repository secrets to enable publishing. The setting ID is the integer in the private plugin's edit URL (`/plugin_settings/<ID>/edit`).
