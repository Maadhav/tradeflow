// Sample trade documents for trying Tradeflow by hand: commercial invoices, a bill of lading and a
// purchase order for the demo's fictional businesses. Every company, address, tax number and bank
// account here is invented. Amounts and dates match what the app expects for each document.
// Usage: bun run docs/make-docs.ts [outDir]   (default: ~/Desktop/Tradeflow sample documents)

import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const OUT = process.argv[2] ?? `${process.env.HOME}/Desktop/Tradeflow sample documents`

type Party = { name: string; lines: string[] }
type Line = { item: string; detail?: string; qty: string; unit: string; amount: string }
type Doc = {
  file: string
  kind: 'COMMERCIAL INVOICE' | 'TAX INVOICE' | 'BILL OF LADING' | 'PURCHASE ORDER'
  issuer: Party & { mark: string; color: string; regLabel: string; reg: string }
  meta: [string, string][]
  parties: { label: string; party: Party }[]
  lines?: Line[]
  totals?: [string, string][]
  currency?: string
  blocks?: { title: string; rows: [string, string][] }[]
  notes: string[]
  signer: string
}

const money = (n: number) => n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })

const docs: Doc[] = [
  {
    file: 'INV-2026-0142 Sierra Verde to Kaffeehaus Berlin.pdf',
    kind: 'COMMERCIAL INVOICE',
    issuer: {
      name: 'Sierra Verde Coffee Exporters S.A.S.',
      mark: 'SV', color: '#2f6b3a', regLabel: 'NIT', reg: '900.482.115-3',
      lines: ['Carrera 5 # 21-38, Neiva, Huila, Colombia', 'exports@sierraverde-coffee.co  ·  +57 608 871 4402'],
    },
    meta: [['Invoice no.', 'INV-2026-0142'], ['Issue date', '7 October 2026'], ['Due date', '6 December 2026'], ['Terms', 'Net 60 days'], ['Incoterms', 'FOB Buenaventura'], ['Currency', 'EUR']],
    parties: [
      { label: 'Bill to', party: { name: 'Kaffeehaus Berlin GmbH', lines: ['Schönhauser Allee 112, 10437 Berlin, Germany', 'USt-IdNr. DE318552904', 'payables@kaffeehaus-berlin.de'] } },
      { label: 'Ship to', party: { name: 'Kaffeehaus Berlin GmbH, Rösterei', lines: ['Lagerstraße 9, 13355 Berlin, Germany'] } },
    ],
    lines: [
      { item: 'Specialty washed Arabica, Huila Supremo', detail: 'Screen 17/18, crop 2026, 16 jute bags of 69 kg net, lot SV-26-0418', qty: '1,104 kg', unit: '8.25', amount: money(9108) },
      { item: 'Export documentation', detail: 'Certificate of origin, phytosanitary certificate, ICO mark', qty: '1', unit: '142.00', amount: money(142) },
    ],
    totals: [['Subtotal', money(9250)], ['VAT', 'Exempt (export)'], ['Total due', `EUR ${money(9250)}`]],
    blocks: [{ title: 'Remit to', rows: [['Bank', 'Banco Andino de Comercio Exterior'], ['Account', '4471-2290-01 (EUR)'], ['SWIFT', 'BACEXCOBB'], ['Reference', 'INV-2026-0142']] }],
    notes: ['Shipped on MV Coral Meridian from Buenaventura, BL BUN-SV-26-0418.', 'Goods remain property of the seller until paid in full.'],
    signer: 'Laura Restrepo, Export Manager',
  },
  {
    file: 'INV-2026-0999 Sierra Verde to Northbrook Trading.pdf',
    kind: 'COMMERCIAL INVOICE',
    issuer: {
      name: 'Sierra Verde Coffee Exporters S.A.S.',
      mark: 'SV', color: '#2f6b3a', regLabel: 'NIT', reg: '900.482.115-3',
      lines: ['Carrera 5 # 21-38, Neiva, Huila, Colombia', 'exports@sierraverde-coffee.co  ·  +57 608 871 4402'],
    },
    meta: [['Invoice no.', 'INV-2026-0999'], ['Issue date', '7 October 2026'], ['Due date', '5 January 2027'], ['Terms', 'Net 90 days'], ['Incoterms', 'FOB Buenaventura'], ['Currency', 'EUR']],
    parties: [
      { label: 'Bill to', party: { name: 'Northbrook Trading Ltd', lines: ['41 Wharf Road, London N1 7GR, United Kingdom', 'Company no. 10928451', 'ap@northbrook-trading.co.uk'] } },
      { label: 'Ship to', party: { name: 'Northbrook Trading Ltd, Tilbury warehouse', lines: ['Unit 4, Dock Road, Tilbury RM18 7BB, United Kingdom'] } },
    ],
    lines: [
      { item: 'Washed Arabica, Huila Supremo', detail: 'Screen 17/18, crop 2026, 87 jute bags of 69 kg net, lots SV-26-0420 to 0426', qty: '6,003 kg', unit: '8.25', amount: money(49524.75) },
      { item: 'Export documentation and fumigation', detail: 'Certificates of origin, phytosanitary certificates, container fumigation', qty: '1', unit: '475.25', amount: money(475.25) },
    ],
    totals: [['Subtotal', money(50000)], ['VAT', 'Exempt (export)'], ['Total due', `EUR ${money(50000)}`]],
    blocks: [{ title: 'Remit to', rows: [['Bank', 'Banco Andino de Comercio Exterior'], ['Account', '4471-2290-01 (EUR)'], ['SWIFT', 'BACEXCOBB'], ['Reference', 'INV-2026-0999']] }],
    notes: ['Shipment scheduled on the November sailing from Buenaventura.', 'Goods remain property of the seller until paid in full.'],
    signer: 'Laura Restrepo, Export Manager',
  },
  {
    file: 'INV-2026-0388 Rapid Parts to Gulf Auto Services.pdf',
    kind: 'TAX INVOICE',
    issuer: {
      name: 'Rapid Parts Trading L.L.C.',
      mark: 'RP', color: '#a33a2a', regLabel: 'Trade licence', reg: 'CN-3307119',
      lines: ['Warehouse 12, Al Qusais Industrial Area 2, Dubai, United Arab Emirates', 'TRN 100482231700003  ·  sales@rapidparts.ae  ·  +971 4 263 0912'],
    },
    meta: [['Tax invoice no.', 'INV-2026-0388'], ['Issue date', '8 September 2026'], ['Due date', '8 October 2026'], ['Terms', 'Net 30 days'], ['Delivery', 'DAP Musaffah, Abu Dhabi'], ['Currency', 'USD']],
    parties: [
      { label: 'Bill to', party: { name: 'Gulf Auto Services LLC', lines: ['Plot 41, Musaffah M-14, Abu Dhabi, United Arab Emirates', 'TRN 100377145200003', 'accounts@gulfautoservices.ae'] } },
      { label: 'Deliver to', party: { name: 'Gulf Auto Services LLC, fleet workshop', lines: ['Plot 41, Musaffah M-14, Abu Dhabi'] } },
    ],
    lines: [
      { item: 'Front brake pad kits', detail: 'Ceramic, light commercial vans, part RP-BP-2210', qty: '40', unit: '38.50', amount: money(1540) },
      { item: 'Brake disc pairs', detail: 'Vented 300 mm, part RP-BD-3004', qty: '20', unit: '52.00', amount: money(1040) },
      { item: 'Oil filters', detail: 'Spin-on, part RP-OF-118', qty: '120', unit: '4.25', amount: money(510) },
      { item: 'Air filters', detail: 'Panel, part RP-AF-560', qty: '48', unit: '14.99', amount: money(719.52) },
    ],
    totals: [['Subtotal', money(3809.52)], ['VAT 5%', money(190.48)], ['Total due', `USD ${money(4000)}`]],
    blocks: [{ title: 'Remit to', rows: [['Bank', 'Emirates Gulf Commercial Bank'], ['Account', 'AE07 0331 2345 6789 0123 456'], ['SWIFT', 'EGCBAEAD'], ['Reference', 'INV-2026-0388']] }],
    notes: ['Delivered on 8 September 2026, delivery note DN-26-1774, received by fleet workshop.', 'Late payments may be charged 1.5% per month.'],
    signer: 'Omar Haddad, Accounts',
  },
  {
    file: 'BL-SGSIN-88231 Pacific Freight Lines to Harbor Retail.pdf',
    kind: 'BILL OF LADING',
    issuer: {
      name: 'Straits Ocean Carriers Pte. Ltd.',
      mark: 'SO', color: '#1f4f7a', regLabel: 'Carrier SCAC', reg: 'SOCU',
      lines: ['80 Robinson Road #14-02, Singapore 068898', 'Port-to-port shipment, non-negotiable copy'],
    },
    meta: [['B/L no.', 'BL-SGSIN-88231'], ['Booking no.', 'SOC-SG-552817'], ['Vessel / voyage', 'MV Coral Meridian / 042E'], ['Port of loading', 'Singapore (SGSIN)'], ['Port of discharge', 'Los Angeles (USLAX)'], ['Shipped on board', '5 October 2026']],
    parties: [
      { label: 'Shipper', party: { name: 'Pacific Freight Lines Pte. Ltd.', lines: ['10 Anson Road #22-03, Singapore 079903', 'UEN 201412345K'] } },
      { label: 'Consignee', party: { name: 'Harbor Retail Group LLC', lines: ['2200 E. Pacific Coast Hwy, Long Beach, CA 90806, USA', 'payables@harborretail.com'] } },
      { label: 'Notify party', party: { name: 'Same as consignee', lines: [] } },
    ],
    lines: [
      { item: '1 x 40\' HC container SOCU 482113-7, seal SG7741902', detail: 'Said to contain 1,240 cartons of household storage goods (HS 3924.90). Gross weight 14,860 kg, measurement 66.2 CBM', qty: '1,240 ctns', unit: '', amount: '' },
    ],
    blocks: [
      { title: 'Freight and value', rows: [['Freight', 'Prepaid'], ['Declared value', 'USD 15,000.00'], ['Commercial invoice', 'CI-PFL-26-1182, USD 15,000.00, payable 90 days from B/L date']] },
      { title: 'Issue', rows: [['Place and date', 'Singapore, 5 October 2026'], ['Originals', 'Electronic B/L (eBL), 1 original'], ['Movement', 'FCL / FCL, CY / CY']] },
    ],
    notes: ['Received in apparent good order and condition unless otherwise stated, for carriage subject to the carrier\'s terms and conditions.', 'Shipper\'s load, stow and count.'],
    signer: 'For the carrier, Straits Ocean Carriers Pte. Ltd.',
  },
  {
    file: 'EQ-2026-0077 Telares Industriales purchase order to Medina Textiles.pdf',
    kind: 'PURCHASE ORDER',
    issuer: {
      name: 'Telares Industriales S.A. de C.V.',
      mark: 'TI', color: '#6b3fa0', regLabel: 'RFC', reg: 'TIN090212AB3',
      lines: ['Av. Industrial 455, Parque Industrial Lerma, Estado de México, Mexico', 'compras@telaresindustriales.mx  ·  +52 728 285 3301'],
    },
    meta: [['PO no.', 'EQ-2026-0077'], ['PO date', '28 September 2026'], ['Delivery by', '10 October 2026'], ['Payment', '180 days after delivery and acceptance'], ['Incoterms', 'DAP Lerma'], ['Currency', 'USD']],
    parties: [
      { label: 'Supplier', party: { name: 'Medina Textiles S.A. de C.V.', lines: ['Calle Hidalgo 210, Puebla, Mexico', 'RFC MTE180503KL2'] } },
      { label: 'Deliver to', party: { name: 'Telares Industriales, Planta 2', lines: ['Av. Industrial 455, Lerma, Estado de México'] } },
    ],
    lines: [
      { item: 'Electronic jacquard looms, refurbished', detail: '2,688 hooks, 190 cm reed width, 12-month warranty', qty: '6', unit: '3,200.00', amount: money(19200) },
      { item: 'Installation and commissioning', detail: 'On site, including operator training', qty: '1', unit: '800.00', amount: money(800) },
    ],
    totals: [['Subtotal', money(20000)], ['IVA', 'Invoiced separately'], ['Order total', `USD ${money(20000)}`]],
    blocks: [{ title: 'Approval', rows: [['Requested by', 'Production, Planta 2'], ['Budget line', 'CAPEX 2026-14'], ['Supplier ref.', 'MT-Q-26-031']] }],
    notes: ['Please quote the PO number on the invoice and delivery note.', 'Acceptance after a 5-day production trial.'],
    signer: 'Ing. Alejandro Ruiz, Procurement Director',
  },
]

const css = `
  @page { size: A4; margin: 0; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 10.5pt/1.45 "Helvetica Neue", Arial, sans-serif; color: #1d232a; }
  .page { width: 210mm; min-height: 297mm; padding: 16mm 16mm 14mm; position: relative; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding-bottom: 12px; border-bottom: 2px solid var(--c); }
  .brand { display: flex; gap: 12px; align-items: center; }
  .mark { width: 46px; height: 46px; border-radius: 10px; background: var(--c); color: #fff; font-weight: 700; font-size: 17pt; display: grid; place-items: center; letter-spacing: .5px; }
  .co { font-weight: 700; font-size: 13pt; }
  .small { font-size: 8.5pt; color: #5a6470; }
  .kind { text-align: right; }
  .kind h1 { margin: 0; font-size: 17pt; letter-spacing: 1.5px; color: var(--c); }
  .meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px 18px; margin: 14px 0; }
  .meta div { border-left: 2px solid #e2e6ea; padding-left: 8px; }
  .meta b { display: block; font-size: 8pt; color: #5a6470; font-weight: 600; }
  .parties { display: grid; grid-template-columns: repeat(var(--n), 1fr); gap: 12px; margin: 6px 0 16px; }
  .box { border: 1px solid #dfe3e7; border-radius: 6px; padding: 9px 11px; }
  .box .lbl { font-size: 8pt; color: #5a6470; font-weight: 600; margin-bottom: 3px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 8.5pt; color: #5a6470; font-weight: 600; border-bottom: 1px solid #c9d0d6; padding: 6px 6px; }
  td { padding: 8px 6px; border-bottom: 1px solid #eceff2; vertical-align: top; }
  td.n, th.n { text-align: right; white-space: nowrap; }
  .det { font-size: 8.5pt; color: #5a6470; }
  .totals { margin-left: auto; width: 46%; margin-top: 10px; }
  .totals td { border: 0; padding: 4px 6px; }
  .totals tr:last-child td { font-weight: 700; font-size: 12pt; border-top: 2px solid var(--c); padding-top: 8px; }
  .blocks { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 18px; }
  .blocks table td { border: 0; padding: 2px 0; }
  .blocks table td:first-child { color: #5a6470; width: 38%; }
  .notes { margin-top: 16px; font-size: 8.5pt; color: #5a6470; }
  .notes p { margin: 0 0 4px; }
  .sign { position: absolute; left: 16mm; right: 16mm; bottom: 16mm; display: flex; justify-content: space-between; align-items: flex-end; }
  .line { border-top: 1px solid #1d232a; width: 70mm; padding-top: 4px; font-size: 8.5pt; }
  .stamp { width: 34mm; height: 34mm; border: 2px solid var(--c); border-radius: 50%; color: var(--c); display: grid; place-items: center; text-align: center; font-size: 7pt; font-weight: 700; letter-spacing: .5px; transform: rotate(-12deg); opacity: .75; padding: 6px; }
`

function html(d: Doc) {
  const parties = d.parties.map((p) => `<div class="box"><div class="lbl">${p.label}</div><div><b>${p.party.name}</b></div>${p.party.lines.map((l) => `<div class="small">${l}</div>`).join('')}</div>`).join('')
  const rows = (d.lines ?? []).map((l) => `<tr><td><div>${l.item}</div>${l.detail ? `<div class="det">${l.detail}</div>` : ''}</td><td class="n">${l.qty}</td><td class="n">${l.unit}</td><td class="n">${l.amount}</td></tr>`).join('')
  const isBL = d.kind === 'BILL OF LADING'
  const table = `<table><thead><tr><th>${isBL ? 'Marks, numbers and description of goods' : 'Description'}</th><th class="n">${isBL ? 'Packages' : 'Quantity'}</th><th class="n">${isBL ? '' : `Unit (${d.meta.find(([k]) => k === 'Currency')?.[1] ?? ''})`}</th><th class="n">${isBL ? '' : 'Amount'}</th></tr></thead><tbody>${rows}</tbody></table>`
  const totals = d.totals ? `<table class="totals">${d.totals.map(([k, v]) => `<tr><td>${k}</td><td class="n">${v}</td></tr>`).join('')}</table>` : ''
  const blocks = d.blocks ? `<div class="blocks">${d.blocks.map((b) => `<div class="box"><div class="lbl">${b.title}</div><table>${b.rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}</table></div>`).join('')}</div>` : ''
  return `<!doctype html><html><head><meta charset="utf-8"><style>${css}</style></head><body>
  <div class="page" style="--c:${d.issuer.color}">
    <div class="head">
      <div class="brand"><div class="mark">${d.issuer.mark}</div><div><div class="co">${d.issuer.name}</div>${d.issuer.lines.map((l) => `<div class="small">${l}</div>`).join('')}<div class="small">${d.issuer.regLabel} ${d.issuer.reg}</div></div></div>
      <div class="kind"><h1>${d.kind}</h1><div class="small">${d.meta[0][1]}</div></div>
    </div>
    <div class="meta">${d.meta.map(([k, v]) => `<div><b>${k}</b>${v}</div>`).join('')}</div>
    <div class="parties" style="--n:${d.parties.length}">${parties}</div>
    ${table}${totals}${blocks}
    <div class="notes">${d.notes.map((n) => `<p>${n}</p>`).join('')}</div>
    <div class="sign"><div class="line">${d.signer}</div><div class="stamp">${d.issuer.name.toUpperCase()}</div></div>
  </div></body></html>`
}

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const page = await browser.newPage()
for (const d of docs) {
  await page.setContent(html(d), { waitUntil: 'load' })
  await page.pdf({ path: `${OUT}/${d.file}`, format: 'A4', printBackground: true })
  console.log('wrote', d.file)
}
await browser.close()
