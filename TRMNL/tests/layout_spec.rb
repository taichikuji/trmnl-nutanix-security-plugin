require 'fileutils'
require 'json'

RSpec.describe 'Nutanix Security layouts' do
  advisories_url = 'https://portal.nutanix.com/api/v1/pages/securityAdvisories'
  nxvd_url = 'https://portal.nutanix.com/api/v1/vulnerabilities'

  advisories = (1..6).map do |n|
    {
      advisoryNumber: format('%04d', n), criticality: n > 3 ? 'Critical' : 'High',
      date: "Nov #{14 + n}, 2026",
      affectedVersions: 'Nutanix AOS, Prism Central, and AHV on the affected software releases',
      summary: "Investigation and BreakFix Guidance for CVE-2099-#{1000 + n} in a component with a long name",
      href: "https://download.nutanix.com/alerts/Security_Advisory_#{format('%04d', n)}.pdf"
    }
  end

  released = (1..6).map do |n|
    {
      productName: 'AOS', status: 'Released', severity: n < 3 ? 'Critical' : 'High',
      cvss: n < 3 ? 9.8 : 8.8, cveList: ["CVE-2099-#{1000 + n}", "CVE-2099-#{2000 + n}"],
      package: 'package-with-a-long-name', fixedReleases: ['aos.7.6', 'aos.7.5.0.2', 'aos.7.3.1.8']
    }
  end

  cases = {
    'advisories' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: advisories.rotate(2) } } } }, 'CVE-2099-1006', 6],
    'advisories-empty' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: [] } } } }, 'No advisories returned', 0],
    'nxvd' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: released, totalCount: 200 } } }, 'CVE-2099-1001', 6],
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
  row_limits = { 'full' => 4, 'half_horizontal' => 2, 'half_vertical' => 4, 'quadrant' => 0 }

  cases.each do |scenario, (mode, mocks, label, count)|
    devices.each do |device_name, device|
      row_limits.each do |view, limit|
        it "renders #{scenario} on #{device_name} #{view}" do
          fields = { table_type: mode, nxvd_product: 'aos' }
          screen = trmnl.render(view: view, device: device, custom_fields: fields, mocks: mocks)

          expect(screen).to have_no_transform_error
          expect(screen).to have_text(label)
          expect(screen).to have_no_text('ALL CLEAR')
          expect(screen.all('[data-ns-lead]').size).to eq(count.positive? ? 1 : 0)
          expect(screen.all('[data-ns-row]').size).to eq([limit, [count - 1, 0].max].min)
          expect(screen.result.requests.size).to eq(1)
          expect(screen).to have_css('[data-ns-lead] .ns-subject', text: label) if count.positive?

          if count.positive? && mode == 'nxvd'
            expect(screen).to have_text("#{count} on page")
            expect(screen.find('.ns-score').text).to eq('9.8')
            expect(screen).to have_text('Fixed in')
          elsif count.positive?
            expect(screen).to have_text("SA #0006")
            expect(screen).to have_text('Nov 20, 2026')
            expect(screen).to have_no_text('Investigation and BreakFix Guidance for')
            expect(screen).to have_text('1 published Nov 20')
          end

          request = screen.result.requests.first
          expect(request).to include(mocked: true, via: :transform)
          if mode == 'nxvd'
            expect(JSON.parse(request[:body])).to eq(
              'page' => 1, 'pageSize' => 20, 'sort' => 'DESC', 'sortColumn' => 'CVSS', 'product' => ['AOS']
            )
          end

          footer = screen.box('[data-ns-footer]')
          box = screen.box('.view')
          expect(screen.evaluate("document.querySelector('.ns-mast').scrollWidth - document.querySelector('.ns-mast').clientWidth")).to be <= 1
          bottom = footer.top + footer.height
          expect(bottom).to be <= box.top + box.height + 1
          if count.positive?
            last_selector = limit.positive? && count > 1 ? '[data-ns-row]:last-child' : '[data-ns-lead]'
            last = screen.box(last_selector)
            expect(last.top + last.height).to be <= footer.top + 1
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
