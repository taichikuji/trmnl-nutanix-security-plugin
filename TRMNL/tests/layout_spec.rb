require 'fileutils'
require 'json'
require 'yaml'

RSpec.describe 'Nutanix Security layouts' do
  advisories_url = 'https://portal.nutanix.com/api/v1/pages/securityAdvisories'
  nxvd_url = 'https://portal.nutanix.com/api/v1/vulnerabilities'

  advisories = (1..20).map do |n|
    {
      advisoryNumber: format('%04d', n), criticality: (4..19).cover?(n) ? 'Critical' : 'High',
      date: "Nov #{n}, 2026",
      affectedVersions: 'Nutanix AOS, Prism Central, and AHV on the affected software releases',
      summary: "Investigation and BreakFix Guidance for CVE-2099-#{1000 + n} in a component with a very long name affecting several product versions",
      href: "https://download.nutanix.com/alerts/Security_Advisory_#{format('%04d', n)}.pdf"
    }
  end

  released = (1..20).map do |n|
    {
      productName: 'AOS', status: 'Released', severity: n < 3 ? 'Critical' : 'High',
      cvss: n < 3 ? 9.8 : 8.8, cveList: ["CVE-2099-#{1000 + n}", "CVE-2099-#{2000 + n}"],
      package: 'package-with-a-long-name', fixedReleases: ['aos.7.6', 'aos.7.5.0.2', 'aos.7.3.1.8']
    }
  end

  advisory_mocks = { "GET #{advisories_url}" => { json: { content: { body: advisories.rotate(2) } } } }
  cases = {
    'advisories' => ['advisories', advisory_mocks, 'CVE-2099-1020', 20],
    'advisories-empty' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: [] } } } }, 'No advisories returned', 0],
    'nxvd' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released, totalCount: 200 } } }, 'CVE-2099-1001', 20],
    'nxvd-single' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released.take(1) } } }, 'CVE-2099-1001', 1],
    'nxvd-empty' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: [] } } }, 'No released fixes on this page', 0],
    'nxvd-error' => ['nxvd', { "POST #{nxvd_url}" => { status: 503 } }, 'HTTP 503', 0],
    'advisories-criticality' => ['advisories', advisory_mocks, 'CVE-2099-1019', 20, 'criticality']
  }
  devices = {
    'og' => { model: 'og_png', width: 800, height: 480, bit_depth: 1, screen_classes: 'screen screen--og_png screen--md screen--1bit' },
    'x' => { model: 'v2', width: 1872, height: 1404, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit' },
    'og-portrait' => { model: 'og_plus', width: 480, height: 800, bit_depth: 2, screen_classes: 'screen screen--ogv2 screen--md screen--2bit screen--portrait' },
    'x-portrait' => { model: 'v2', width: 1404, height: 1872, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit screen--portrait' }
  }
  views = %w[full half_horizontal half_vertical quadrant]
  row_limits = {
    'og' => [4, 3, 4, 0],
    'og-portrait' => [8, 3, 8, 0],
    'x' => [10, 5, 9, 2],
    'x-portrait' => [10, 5, 9, 2]
  }

  cases.each do |scenario, (mode, mocks, label, count, advisory_sort)|
    devices.each do |device_name, device|
      views.each_with_index do |view, view_index|
        it "renders #{scenario} on #{device_name} #{view}" do
          fields = { table_type: mode, nxvd_product: 'aos' }
          fields[:advisory_sort] = advisory_sort if advisory_sort
          screen = trmnl.render(view: view, device: device, custom_fields: fields, mocks: mocks)
          expect(screen).to have_no_transform_error
          expect(screen).to have_text(label)
          expect(screen).to have_no_text('ALL CLEAR')
          expect(screen.all('[data-ns-lead]').size).to eq(count.positive? ? 1 : 0)
          expect(screen).to have_no_css('.title_bar')
          expect(screen).to have_no_css('.layout a')
          expect(screen).to have_no_css('.layout [data-table-limit], .layout [data-clamp]')
          expect(screen.result.requests.size).to eq(1)
          expect(screen).to have_css('[data-ns-lead] [data-ns-subject]', text: label) if count.positive?

          if count.positive? && mode == 'nxvd'
            expect(screen.find('[data-ns-score]').text).to eq('9.8')
            expect(screen).to have_text('Fixed in')
          elsif count.positive?
            day = advisory_sort == 'criticality' ? 19 : 20
            expect(screen).to have_text("SA #00#{day}")
            expect(screen).to have_text("Nov #{day}, 2026")
            expect(screen.find('[data-ns-order]').text).to eq(advisory_sort == 'criticality' ? 'By criticality' : 'Latest advisory')
            expect(screen).to have_no_text('Investigation and BreakFix Guidance for')
          end

          request = screen.result.requests.first
          expect(request).to include(mocked: true, via: :transform)
          if mode == 'nxvd'
            expect(JSON.parse(request[:body])).to eq(
              'page' => 1, 'pageSize' => 20, 'sort' => 'DESC', 'sortColumn' => 'CVSS', 'product' => ['AOS']
            )
          end

          box = screen.box('.view')
          geometry = screen.evaluate(<<~JS)
            (() => {
              const frame = document.querySelector('.layout').getBoundingClientRect();
              const mast = document.querySelector('[data-ns-mast]');
              const lead = document.querySelector('[data-ns-lead]')?.getBoundingClientRect();
              const leadRule = document.querySelector('[data-ns-order]')?.parentElement.getBoundingClientRect();
              const table = document.querySelector('table');
              const tableBox = table?.getBoundingClientRect();
              const beside = Boolean(tableBox && lead && tableBox.left >= lead.right - 1);
              const rows = [...document.querySelectorAll('[data-ns-row]')].filter(row => row.getClientRects().length);
              const boxes = [...rows, ...document.querySelectorAll('thead, [data-ns-lead]')]
                .filter(element => element.getClientRects().length)
                .map(element => element.getBoundingClientRect());
              const cellOverflow = rows.some(row => [...row.querySelectorAll('.nutanix-line')].some(element => {
                if (!element.getClientRects().length) return false;
                return element.getBoundingClientRect().right > element.closest('td').getBoundingClientRect().right + 1;
              }));
              return {
                rows: rows.length,
                renderedRows: document.querySelectorAll('[data-ns-row]').length,
                cellOverflow,
                widthOverflow: mast.scrollWidth - mast.clientWidth,
                clipped: boxes.some(box => box.top < frame.top - 1 || box.bottom > frame.bottom + 1 ||
                                          box.left < frame.left - 1 || box.right > frame.right + 1),
                beside,
                gutterDifference: rows.length && !beside ? Math.max(
                  Math.abs(table.querySelector('th .title').getBoundingClientRect().left - leadRule.left),
                  Math.abs(tableBox.right - leadRule.right)
                ) : 0,
                columns: table ? [...table.querySelectorAll('th')].filter(cell => cell.getClientRects().length).length : 0
              };
            })()
          JS
          expect(geometry['widthOverflow']).to be <= 1
          expect(geometry['clipped']).to be(false)
          expect(geometry['cellOverflow']).to be(false)
          expect(geometry['gutterDifference']).to be <= 1
          remaining = [count - 1, 0].max
          expect(geometry['rows']).to eq([remaining, row_limits.fetch(device_name)[view_index]].min)
          expect(geometry['renderedRows']).to eq([remaining, row_limits.fetch('x')[view_index]].min)
          if count > 1 && view == 'full' && %w[og x].include?(device_name)
            expect(geometry['beside']).to eq(device_name == 'x')
            columns = device_name == 'x' ? (mode == 'nxvd' ? 4 : 3) : 2
            expect(geometry['columns']).to eq(columns)
          end

          FileUtils.mkdir_p('_build/previews')
          image = MiniMagick::Image.read(screen.png_bytes)
          image.crop("#{box.width.round}x#{box.height.round}+#{box.left.round}+#{box.top.round}")
          image.write("_build/previews/#{scenario}-#{device_name}-#{view}.png")
        end
      end
    end
  end

  %w[og x].each do |device_name|
    it "keeps the full #{device_name} layout steady while framework JavaScript loads" do
      version = YAML.safe_load_file(File.expand_path('../src/settings.yml', __dir__)).fetch('framework_version')
      overrides = {
        "https://trmnl.com/js/#{version}/plugins.js" => {
          body: 'window.TRMNL_PLUGINS_READY = true; window.nutanixCssOnly = true;',
          content_type: 'application/javascript'
        }
      }
      args = { view: 'full', device: devices.fetch(device_name),
               custom_fields: { table_type: 'advisories' }, mocks: advisory_mocks }
      geometry = <<~JS
        Array.from(document.querySelectorAll('[data-ns-mast], [data-ns-lead], [data-ns-subject], table, [data-ns-row]'))
          .filter(element => element.getClientRects().length)
          .map(element => {
            const { x, y, width, height } = element.getBoundingClientRect();
            return [x, y, width, height].map(Math.round);
          })
      JS
      initial = trmnl.render(**args, asset_overrides: overrides)
      expect(initial.evaluate('Boolean(window.nutanixCssOnly)')).to eq(true)
      before = initial.evaluate(geometry)
      settled = trmnl.render(**args)
      expect(settled.evaluate('Boolean(window.TRMNL_PLUGINS_READY && !window.nutanixCssOnly)')).to eq(true)
      expect(settled.evaluate(geometry)).to eq(before)
    end
  end

  [
    ['nxvd', 'og', 'full', { delay: 4.7, status: 503 }, 'TIMEOUT'],
    ['nxvd', 'x', 'quadrant', { status: 503 }, 'HTTP 503'],
    ['advisories-criticality', 'og-portrait', 'half_vertical', { status: 503 }, 'HTTP 503']
  ].each do |scenario, device_name, view, failure, reason|
    it "shows dated saved #{scenario} on #{device_name} #{view} after #{reason}" do
      mode, mocks, label, _, advisory_sort = cases.fetch(scenario)
      fields = { table_type: mode, nxvd_product: 'aos', advisory_sort: advisory_sort }
      live = trmnl.transform(custom_fields: fields, mocks: mocks, now: '2026-11-20T15:30:00Z')
      expect(live.error).to be_nil
      expect(live.state.fetch('saved_at')).to start_with('2026-11-20T15:30:')

      screen = trmnl.render(view: view, device: devices.fetch(device_name), custom_fields: fields,
                            mocks: { mocks.keys.first => failure }, state: live.state)
      expect(screen).to have_no_transform_error
      expect(screen).to have_text('Saved 2026-11-20')
      expect(screen).to have_css('[data-ns-lead] [data-ns-subject]', text: label)
      expect(screen.result.data.fetch('source_error')).to eq(reason)
      expect(screen.result.state).to eq(live.state)
      expect(screen.result.requests.size).to eq(1)
      expect(screen.evaluate(<<~JS)).to eq(true)
        [...document.querySelectorAll('[data-ns-lead], [data-ns-row]')].every(element =>
          element.getBoundingClientRect().bottom <= document.querySelector('.layout').getBoundingClientRect().bottom + 1)
      JS

      FileUtils.mkdir_p('_build/previews')
      File.binwrite("_build/previews/saved-#{scenario}-#{device_name}-#{view}.png", screen.png_bytes)
    end
  end
end
