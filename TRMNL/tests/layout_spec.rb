require 'fileutils'
require 'json'

RSpec.describe 'Nutanix Security layouts' do
  advisories_url = 'https://portal.nutanix.com/api/v1/pages/securityAdvisories'
  nxvd_url = 'https://portal.nutanix.com/api/v1/vulnerabilities'

  advisories = (1..34).map do |n|
    {
      advisoryNumber: format('%04d', n), criticality: (4..19).cover?(n) ? 'Critical' : 'High',
      date: n <= 20 ? "Nov #{n}, 2026" : "Oct #{n - 20}, 2026",
      affectedVersions: 'Nutanix AOS, Prism Central, and AHV on the affected software releases',
      summary: "Investigation and BreakFix Guidance for CVE-2099-#{1000 + n} in a component with a very long name affecting several product versions",
      href: "https://download.nutanix.com/alerts/Security_Advisory_#{format('%04d', n)}.pdf"
    }
  end

  released = (1..28).map do |n|
    {
      productName: 'AOS', status: 'Released',
      severity: n == 4 ? 'Informational' : (n < 3 ? 'Critical' : 'High'),
      cvss: n < 3 ? 9.8 : 8.8, cveList: ["CVE-2099-#{1000 + n}", "CVE-2099-#{2000 + n}"],
      package: 'package-with-a-long-name', fixedReleases: ['aos.7.6', 'aos.7.5.0.2', 'aos.7.3.1.8']
    }
  end

  advisory_mocks = { "GET #{advisories_url}" => { json: { content: { body: advisories.rotate(2) } } } }
  cases = {
    'advisories' => ['advisories', advisory_mocks, 'CVE-2099-1020', advisories.size],
    'advisories-empty' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: [] } } } }, 'No advisories returned', 0],
    'nxvd' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released, totalCount: 200 } } }, 'CVE-2099-1001', released.size],
    'nxvd-single' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released.take(1) } } }, 'CVE-2099-1001', 1],
    'nxvd-empty' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: [] } } }, 'No released fixes on this page', 0],
    'nxvd-error' => ['nxvd', { "POST #{nxvd_url}" => { status: 503 } }, 'HTTP 503', 0],
    'advisories-criticality' => ['advisories', advisory_mocks, 'CVE-2099-1019', advisories.size, 'criticality']
  }
  devices = {
    'og' => { model: 'og_png', width: 800, height: 480, bit_depth: 1, screen_classes: 'screen screen--og_png screen--md screen--1bit' },
    'x' => { model: 'v2', width: 1872, height: 1404, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit' },
    'og-portrait' => { model: 'og_plus', width: 480, height: 800, bit_depth: 2, screen_classes: 'screen screen--ogv2 screen--md screen--2bit screen--portrait' },
    'x-portrait' => { model: 'v2', width: 1404, height: 1872, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit screen--portrait' }
  }
  views = %w[full half_horizontal half_vertical quadrant]
  cases.each do |scenario, (mode, mocks, label, count, advisory_sort)|
    devices.each do |device_name, device|
      views.each do |view|
        it "renders #{scenario} on #{device_name} #{view}" do
          fields = { table_type: mode, nxvd_product: 'aos' }
          fields[:advisory_sort] = advisory_sort if advisory_sort
          screen = trmnl.render(view: view, device: device, custom_fields: fields, mocks: mocks)
          expect(screen).to have_no_transform_error
          expect(screen).to have_text(label)
          expect(screen).to have_no_text('ALL CLEAR')
          expect(screen.all('[data-ns-lead]').size).to eq(count.positive? ? 1 : 0)
          expect(screen.find('[data-ns-heading]').text).to eq(mode == 'nxvd' ? 'VULNERABILITY FIXES' : 'SECURITY ADVISORIES')
          expect(screen).to have_no_css('.title_bar')
          expect(screen).to have_no_css('[data-ns-mast].border--h-black')
          expect(screen).to have_no_css('.layout a')
          expect(screen.has_css?('[data-ns-qr] svg.qr-code')).to eq(view == 'full')
          expect(screen).to have_no_css('[data-ns-mast] svg.qr-code')
          if view == 'full'
            expect(screen).to have_qr_code(screen.result.data.fetch('portal_url'))
            width = device_name.start_with?('x') ? 133.2 : 68
            expect(screen.box('[data-ns-qr] svg.qr-code').width).to be_within(0.1).of(width)
          end
          expect(screen.all('table[data-table-limit="true"]', visible: :all).size).to eq(count > 1 && view != 'full' ? 1 : 0)
          expect(screen.result.requests.size).to eq(1)
          expect(screen).to have_css('[data-ns-lead] [data-ns-subject]', text: label) if count.positive?

          if count.positive? && mode == 'nxvd'
            expect(screen.find('[data-ns-order]').text).to eq('By criticality')
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
              'page' => 1, 'pageSize' => 40, 'sort' => 'DESC', 'sortColumn' => 'CVSS', 'product' => ['AOS']
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
              const counter = table?.querySelector('[data-table-overflow-label]');
              const boxes = [...document.querySelectorAll('table, [data-ns-lead]')]
                .filter(element => element.getClientRects().length)
                .map(element => element.getBoundingClientRect());
              const cellOverflow = rows.some(row => [...row.querySelectorAll('.nutanix-line')].some(element => {
                if (!element.getClientRects().length) return false;
                return element.getBoundingClientRect().right > element.closest('td').getBoundingClientRect().right + 1;
              }));
              const severityClipped = rows.some(row => [...row.querySelectorAll('td:last-child .nutanix-line')].some(
                label => label.scrollWidth > label.clientWidth + 1
              ));
              const fontSizes = new Set(Array.from(table?.querySelectorAll('thead .label, [data-ns-row] .label') ?? [])
                .filter(element => element.getClientRects().length)
                .map(element => getComputedStyle(element).fontSize));
              return {
                tableFontSizes: fontSizes.size,
                stackedMetadata: Boolean(rows[0]?.querySelector('td:first-child > :nth-child(2)')?.getClientRects().length),
                rows: rows.length,
                renderedRows: document.querySelectorAll('[data-ns-row]').length,
                counter: counter?.textContent.trim(),
                unusedHeight: table ? table.parentElement.getBoundingClientRect().bottom - tableBox.bottom : 0,
                rowHeight: rows[0]?.getBoundingClientRect().height,
                cellOverflow,
                severityClipped,
                widthOverflow: mast.scrollWidth - mast.clientWidth,
                clipped: boxes.some(box => box.top < frame.top - 1 || box.bottom > frame.bottom + 1 ||
                                          box.left < frame.left - 1 || box.right > frame.right + 1),
                beside,
                rightGap: rows.length ? Math.abs(tableBox.right - table.querySelector('th:last-child').getBoundingClientRect().right) : 0,
                gutterDifference: rows.length && !beside ? Math.max(
                  Math.abs(table.querySelector('th .label').getBoundingClientRect().left - leadRule.left),
                  Math.abs(tableBox.right - leadRule.right)
                ) : 0,
                headers: Array.from(table?.querySelectorAll('th .label') ?? [])
                  .filter(cell => cell.getClientRects().length)
                  .map(cell => cell.textContent.trim())
              };
            })()
          JS
          expect(geometry['widthOverflow']).to be <= 1
          expect(geometry['clipped']).to be(false)
          expect(geometry['cellOverflow']).to be(false)
          expect(geometry['severityClipped']).to be(false)
          expect(geometry['tableFontSizes']).to be <= 1
          expect(geometry['rightGap']).to be <= 1
          expect(geometry['gutterDifference']).to be <= 1
          remaining = (count - 1).clamp(0, 30)
          if view == 'full'
            budget = { 'og' => 6, 'og-portrait' => 16, 'x' => 14, 'x-portrait' => 22 }.fetch(device_name)
            shown = [remaining, budget].min
            expect(geometry['renderedRows']).to eq(shown)
            expect(geometry['rows']).to eq(shown)
            expect(geometry['counter']).to be_nil
            if remaining > shown
              expect(screen.find('[data-ns-more]').text).to eq("+#{remaining - shown} more")
            else
              expect(screen).to have_no_css('[data-ns-more]')
            end
          else
            expect(geometry['renderedRows']).to eq(remaining)
            expect(screen).to have_no_css('[data-ns-footer]')
            if remaining.zero? || (view == 'quadrant' && device_name.start_with?('og'))
              expect(geometry['rows']).to eq(0)
              expect(geometry['counter']).to be_nil
            else
              expect(geometry['rows']).to be_between(1, remaining)
              hidden = remaining - geometry['rows']
              if hidden.positive?
                expect(geometry['counter']).to match(/\Aand #{hidden} more\z/i)
                expect(geometry['unusedHeight']).to be < geometry['rowHeight'] + 1
              else
                expect(geometry['counter']).to be_nil
              end
            end
          end
          if count > 1 && view == 'full'
            expect(geometry['stackedMetadata']).to be(false)
            expect(geometry['beside']).to be(false)
            expect(geometry['headers'].size).to eq(4)
            if mode == 'advisories'
              expect(geometry['headers']).to eq(%w[Summary Published Advisory Severity])
              expect(screen).to have_no_css('[data-ns-row] td:nth-child(2)', text: /#/)
              expect(screen).to have_css('[data-ns-row] td:nth-child(3) > span',
                                         text: advisory_sort == 'criticality' ? '#0018' : '#0019', exact_text: true)
            end
          end
          if geometry['rows'].positive?
            expect(geometry['beside']).to eq(view == 'half_horizontal' && !device_name.end_with?('-portrait'))
            expect(geometry['headers'].last).to eq('Severity')
            if mode == 'nxvd' && (view == 'full' || device_name.start_with?('x'))
              expect(geometry['headers'].last(2)).to eq(%w[CVSS Severity])
              expect(screen).to have_css('[data-ns-row] td:nth-last-child(2)', text: '9.8')
            end
          end

          FileUtils.mkdir_p('_build/previews')
          image = MiniMagick::Image.read(screen.png_bytes)
          image.crop("#{box.width.round}x#{box.height.round}+#{box.left.round}+#{box.top.round}")
          image.write("_build/previews/#{scenario}-#{device_name}-#{view}.png")
        end
      end
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
      expect(screen.has_css?('[data-ns-qr] svg.qr-code')).to eq(view == 'full')
      expect(screen).to have_no_css('[data-ns-mast] svg.qr-code')
      expect(screen).to have_css('[data-ns-lead] [data-ns-subject]', text: label)
      expect(screen.result.data.fetch('source_error')).to eq(reason)
      expect(screen.result.state).to eq(live.state)
      expect(screen.result.requests.size).to eq(1)
      expect(screen.evaluate(<<~JS)).to eq(true)
        [...document.querySelectorAll('[data-ns-lead], table')].every(element =>
          element.getBoundingClientRect().bottom <= document.querySelector('.layout').getBoundingClientRect().bottom + 1)
      JS

      FileUtils.mkdir_p('_build/previews')
      File.binwrite("_build/previews/saved-#{scenario}-#{device_name}-#{view}.png", screen.png_bytes)
    end
  end
end
