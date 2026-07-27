const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const svgDir = 'C:/Users/txz/url_shorterner_9-3/flowcharts';

const tasks = [
  {
    svgs: ['func_01_product_overview.svg', 'func_02_create_link.svg', 'func_03_click_redirect.svg', 'func_04_manage_analytics.svg'],
    outDir: path.join(svgDir, 'jpg'),
  },
  {
    svgs: ['en_01_product_overview.svg', 'en_02_create_link.svg', 'en_03_click_redirect.svg', 'en_04_manage_analytics.svg'],
    outDir: path.join(svgDir, 'jpg_en'),
  },
];

async function convert() {
  for (const task of tasks) {
    if (!fs.existsSync(task.outDir)) fs.mkdirSync(task.outDir, { recursive: true });
    for (const f of task.svgs) {
      const svgPath = path.join(svgDir, f);
      const jpgPath = path.join(task.outDir, f.replace('.svg', '.jpg'));
      if (!fs.existsSync(svgPath)) { console.log(`SKIP: ${f}`); continue; }
      try {
        const svgBuf = fs.readFileSync(svgPath);
        await sharp(svgBuf)
          .flatten({ background: '#ffffff' })
          .jpeg({ quality: 90 })
          .toFile(jpgPath);
        const kb = (fs.statSync(jpgPath).size / 1024).toFixed(0);
        console.log(`OK: ${f} -> ${path.basename(jpgPath)} (${kb} KB)`);
      } catch (e) {
        console.log(`FAIL: ${f} — ${e.message}`);
      }
    }
  }
  console.log('\nDone!');
}

convert();
