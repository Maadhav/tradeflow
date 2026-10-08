// Renders deck/social/posters.html to deck/social/poster-N.png (2x, 1080 x 1350).
// Usage: cd demo && bun render-posters.ts
import { chromium } from 'playwright';
import { resolve } from 'node:path';

const dir = resolve(import.meta.dir, '../deck/social');
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1080, height: 1350 }, deviceScaleFactor: 2 });
await page.goto(`file://${dir}/posters.html`);
await page.evaluate(() => document.fonts.ready);
await page.waitForTimeout(300);
const posters = page.locator('section.poster');
const n = await posters.count();
for (let i = 0; i < n; i++) await posters.nth(i).screenshot({ path: `${dir}/poster-${i + 1}.png` });
await browser.close();
console.log(`rendered ${n} posters`);
