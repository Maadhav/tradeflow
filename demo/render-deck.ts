// Renders deck/pdf/deck.html to deck/pdf/slide-N.png (2x) and deck/pdf/Tradeflow.pdf.
// Usage: cd demo && bun render-deck.ts
import { chromium } from 'playwright';
import { resolve } from 'node:path';

const dir = resolve(import.meta.dir, '../deck/pdf');
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 2 });
await page.goto(`file://${dir}/deck.html`);
await page.evaluate(() => document.fonts.ready);
const slides = page.locator('section.slide');
const n = await slides.count();
for (let i = 0; i < n; i++) await slides.nth(i).screenshot({ path: `${dir}/slide-${i + 1}.png` });
await page.pdf({ path: `${dir}/Tradeflow.pdf`, width: '1280px', height: '720px', printBackground: true });
await browser.close();
console.log(`rendered ${n} slides`);
