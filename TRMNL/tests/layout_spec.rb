require 'fileutils'
require 'json'

RSpec.describe 'Nutanix Security layouts' do
  advisories_url = 'https://portal.nutanix.com/api/v1/pages/securityAdvisories'
  nxvd_url = 'https://portal.nutanix.com/api/v1/vulnerabilities'

  advisory = {
    advisoryNumber: '0001', criticality: 'High', date: 'Nov 20, 2026',
    affectedVersions: 'AOS 7.5', summary: 'Security update available',
    href: 'https://download.nutanix.com/alerts/Security_Advisory_0001.pdf'
  }
  released = { productName: 'AOS', status: 'Released', severity: 'Critical', cvss: 9.8,
               cveList: ['CVE-2099-1000'], package: 'sample-package', fixedReleases: ['aos.7.6'] }

  cases = {
    'advisories' => ['advisories', { "GET #{advisories_url}" => { json: { content: { body: [advisory] } } } }, 'SA #0001'],
    'nxvd' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: [released] } } }, 'CVE-2099-1000'],
    'nxvd-empty' => ['nxvd', { "POST #{nxvd_url}" => { json: { vulnerabilities: [] } } }, 'No released fixes on this page'],
    'nxvd-error' => ['nxvd', { "POST #{nxvd_url}" => { status: 503 } }, 'HTTP 503']
  }
  devices = {
    'og' => { model: 'og_png', width: 800, height: 480, bit_depth: 1, screen_classes: 'screen screen--og_png screen--md screen--1bit' },
    'x' => { model: 'v2', width: 1872, height: 1404, bit_depth: 4, screen_classes: 'screen screen--v2 screen--lg screen--4bit' }
  }

  cases.each do |scenario, (mode, mocks, label)|
    devices.each do |device_name, device|
      %w[full half_horizontal half_vertical quadrant].each do |view|
        it "renders #{scenario} on #{device_name} #{view}" do
          fields = { table_type: mode, nxvd_product: 'aos' }
          screen = trmnl.render(view: view, device: device, custom_fields: fields, mocks: mocks)

          expect(screen).to have_no_transform_error
          expect(screen).to have_text(label)
          expect(screen).to have_no_text('ALL CLEAR')
          expect(screen.result.requests.size).to eq(1)

          if scenario == 'nxvd'
            expect(screen).to have_text('1 on page')
          end
          if mode == 'nxvd' && %w[half_vertical quadrant].include?(view)
            expect(screen.find('.title_bar .instance').text).to eq('portal.nutanix.com')
          end

          request = screen.result.requests.first
          expect(request).to include(mocked: true, via: :transform)
          if mode == 'nxvd'
            expect(JSON.parse(request[:body])).to eq(
              'page' => 1, 'pageSize' => 20, 'sort' => 'DESC', 'sortColumn' => 'CVSS', 'product' => ['AOS']
            )
          end

          FileUtils.mkdir_p('_build/previews')
          image = MiniMagick::Image.read(screen.png_bytes)
          box = screen.box('.view')
          image.crop("#{box.width.round}x#{box.height.round}+#{box.left.round}+#{box.top.round}")
          image.write("_build/previews/#{scenario}-#{device_name}-#{view}.png")
        end
      end
    end
  end
end
