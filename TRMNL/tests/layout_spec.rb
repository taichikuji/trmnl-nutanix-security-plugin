require 'fileutils'
require 'json'

RSpec.describe 'Nutanix Security layouts' do
  advisories_url = 'https://portal.nutanix.com/api/v1/pages/securityAdvisories'
  nxvd_url = 'https://portal.nutanix.com/api/v1/vulnerabilities'

  advisories = (1..20).map do |n|
    {
      advisoryNumber: format('%04d', n), criticality: n > 3 ? 'Critical' : 'High',
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

  cases = {
    'advisories' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: advisories.rotate(2) } } } }, 'CVE-2099-1020', 20],
    'advisories-empty' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: [] } } } }, 'No advisories returned', 0],
    'nxvd' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released, totalCount: 200 } } }, 'CVE-2099-1001', 20],
    'nxvd-single' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released.take(1) } } }, 'CVE-2099-1001', 1],
    'nxvd-empty' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: [] } } }, 'No released fixes on this page', 0],
    'nxvd-error' => ['nxvd', { "POST #{nxvd_url}" => { status: 503 } }, 'HTTP 503', 0]
  }
  devices = {
    'og' => { model: 'og_png', width: 800, height: 480, bit_depth: 1, screen_classes: 'screen screen--og_png screen--md screen--1bit' },
    'x' => { model: 'v2', width: 1872, height: 1404, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit' },
    'og-portrait' => { model: 'og_plus', width: 480, height: 800, bit_depth: 2, screen_classes: 'screen screen--ogv2 screen--md screen--2bit screen--portrait' },
    'x-portrait' => { model: 'v2', width: 1404, height: 1872, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit screen--portrait' }
  }
  views = %w[full half_horizontal half_vertical quadrant]

  cases.each do |scenario, (mode, mocks, label, count)|
    devices.each do |device_name, device|
      views.each do |view|
        it "renders #{scenario} on #{device_name} #{view}" do
          fields = { table_type: mode, nxvd_product: 'aos' }
          screen = trmnl.render(view: view, device: device, custom_fields: fields, mocks: mocks)
          expect(screen).to have_no_transform_error
          expect(screen).to have_text(label)
          expect(screen).to have_no_text('ALL CLEAR')
          expect(screen.all('[data-ns-lead]').size).to eq(count.positive? ? 1 : 0)
          expect(screen).to have_no_css('.title_bar')
          expect(screen).to have_no_css('.layout a')
          expect(screen.result.requests.size).to eq(1)
          expect(screen).to have_css('[data-ns-lead] [data-ns-subject]', text: label) if count.positive?

          if count.positive? && mode == 'nxvd'
            expect(screen).to have_text("#{count} on page")
            expect(screen.find('[data-ns-score]').text).to eq('9.8')
            expect(screen).to have_text('Fixed in')
          elsif count.positive?
            expect(screen).to have_text("SA #0020")
            expect(screen).to have_text('Nov 20, 2026')
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
              const table = document.querySelector('table');
              const rows = [...document.querySelectorAll('[data-ns-row]')].filter(row => row.getClientRects().length);
              const boxes = [...rows, ...document.querySelectorAll('thead, [data-ns-lead]')]
                .filter(element => element.getClientRects().length)
                .map(element => element.getBoundingClientRect());
              const cellOverflow = rows.some(row => [...row.querySelectorAll('[data-clamp]')].some(element => {
                if (!element.getClientRects().length) return false;
                const text = document.createRange();
                text.selectNodeContents(element);
                return text.getBoundingClientRect().right > element.closest('td').getBoundingClientRect().right + 1;
              }));
              return {
                rows: rows.length,
                cellOverflow,
                widthOverflow: mast.scrollWidth - mast.clientWidth,
                clipped: boxes.some(box => box.top < frame.top - 1 || box.bottom > frame.bottom + 1 ||
                                          box.left < frame.left - 1 || box.right > frame.right + 1),
                beside: Boolean(table && lead && table.getBoundingClientRect().left >= lead.right - 1),
                columns: table ? [...table.querySelectorAll('th')].filter(cell => cell.getClientRects().length).length : 0
              };
            })()
          JS
          expect(geometry['widthOverflow']).to be <= 1
          expect(geometry['clipped']).to be(false)
          expect(geometry['cellOverflow']).to be(false)
          if count <= 1 || (view == 'quadrant' && device_name.start_with?('og'))
            expect(geometry['rows']).to eq(0)
          else
            expect(geometry['rows']).to be_between(1, count - 1)
          end
          if count > 1 && view == 'full' && %w[og x].include?(device_name)
            expect(geometry['beside']).to eq(device_name == 'x')
            columns = device_name == 'x' ? (mode == 'nxvd' ? 4 : 3) : 2
            expect(geometry['columns']).to eq(columns)
            expect(geometry['rows']).to eq(count - 1) if device_name == 'x' && mode == 'nxvd'
          end

          FileUtils.mkdir_p('_build/previews')
          image = MiniMagick::Image.read(screen.png_bytes)
          image.crop("#{box.width.round}x#{box.height.round}+#{box.left.round}+#{box.top.round}")
          image.write("_build/previews/#{scenario}-#{device_name}-#{view}.png")
        end
      end
    end
  end
end
