"""Build the flat ZIP accepted by TRMNL's private plugin importer."""

import pathlib
import sys
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'TRMNL/src'
names = (
    'settings.yml', 'shared.liquid', 'full.liquid', 'half_horizontal.liquid',
    'half_vertical.liquid', 'quadrant.liquid', 'transform.js',
)
files = {name: (src / name).read_text(encoding='utf-8') for name in names}
# The listing icon is uploaded separately from the seven plugin files.
files['settings.yml'] = ''.join(
    line for line in files['settings.yml'].splitlines(keepends=True)
    if not line.startswith('icon:')
)

output = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'dist/trmnl-nutanix-sec-plugin.zip'
output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name, content in files.items():
        archive.writestr(name, content)

print(f'Created {output} with {len(files)} plugin files.')
