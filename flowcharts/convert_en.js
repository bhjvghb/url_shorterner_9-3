const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const svgDir = 'C:/Users/txz/url_shorterner_9-3/flowcharts';
const outDir = path.join(svgDir, 'jpg_en');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const files = [
  'en_01_product_overview.svg',
  'en_02_create_link.svg',
  'en_03_click_redirect.svg',
  'en_04_manage_analytics.svg',
];

async function convert() {
  for (const f of files) {
    const svgPath = path.join(svgDir, f);
    const jpgPath = path.join(outDir, f.replace('.svg', '.jpg'));

    if (!fs.existsSync(svgPath)) {
      console.log(`SKIP: ${f}`);
      continue;
    }

    try {
      const svgBuf = fs.readFileSync(svgPath);
      await sharp(svgBuf, { density: 144 })
        .jpeg({ quality: 90 })
        .toFile(jpgPath);
      const kb = (fs.statSync(jpgPath).size / 1024).toFixed(0);
      console.log(`OK: ${f} -> ${path.basename(jpgPath)} (${kb} KB)`);
    } catch (e) {
      console.log(`FAIL: ${f} — ${e.message}`);
    }
  }
  console.log('\nDone!');
}

convert();
