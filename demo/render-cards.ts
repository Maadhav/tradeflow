// Renders deck/social/cards.html to deck/social/card-N.png (2x).
// Usage: cd demo && bun render-cards.ts
import { chromium } from 'playwright';
import { resolve } from 'node:path';

const dir = resolve(import.meta.dir, '../deck/social');
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 2 });
await page.goto(`file://${dir}/cards.html`);
await page.evaluate(() => document.fonts.ready);
const cards = page.locator('section.card');
const n = await cards.count();
for (let i = 0; i < n; i++) await cards.nth(i).screenshot({ path: `${dir}/card-${i + 1}.png` });
await browser.close();
console.log(`rendered ${n} cards`);
