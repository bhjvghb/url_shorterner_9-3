const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const svgDir = 'C:/Users/txz/url_shorterner_9-3/flowcharts';
const outDir = 'C:/Users/txz/url_shorterner_9-3/flowcharts/jpg';
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const files = [
  'func_01_product_overview.svg',
  'func_02_create_link.svg',
  'func_03_click_redirect.svg',
  'func_04_manage_analytics.svg',
];

async function convert() {
  for (const f of files) {
    const svgPath = path.join(svgDir, f);
    const jpgPath = path.join(outDir, f.replace('.svg', '.jpg'));

    if (!fs.existsSync(svgPath)) {
      console.log(`SKIP (not found): ${f}`);
      continue;
    }

    try {
      const svgBuf = fs.readFileSync(svgPath);
      await sharp(svgBuf)
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
