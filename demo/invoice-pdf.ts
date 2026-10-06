// A one-page commercial invoice as a hand-written PDF (base-14 Helvetica, no dependencies).
// The recorder attaches it to INV-2026-0142, with the issue and due dates it types into the form.
// Usage: bun run invoice-pdf.ts   (writes demo/assets/INV-2026-0142.pdf, issued today, due in 60 days)

import { mkdirSync, writeFileSync } from 'node:fs'

export type InvoiceDates = { issued: Date; due: Date }

const fmt = (d: Date) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
const eur = (n: number) => n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })

// Helvetica and Helvetica-Bold share these widths (1/1000 em) for the characters right-aligned below.
const WIDTH: Record<string, number> = { ',': 278, '.': 278, ' ': 278, E: 667, U: 722, R: 722, '%': 889 }
const widthOf = (s: string, size: number) => ([...s].reduce((w, c) => w + (WIDTH[c] ?? 556), 0) * size) / 1000

// PDF string literal in WinAnsiEncoding: escape the delimiters, write non-ASCII as octal.
const WIN: Record<string, number> = { '€': 0x80, 'ñ': 0xf1, 'é': 0xe9, 'á': 0xe1, 'í': 0xed, 'ó': 0xf3, 'ü': 0xfc, 'ß': 0xdf }
const lit = (s: string) =>
  '(' +
  [...s]
    .map((c) => {
      if (c === '\\' || c === '(' || c === ')') return `\\${c}`
      const code = WIN[c] ?? c.charCodeAt(0)
      return code < 128 ? c : `\\${code.toString(8).padStart(3, '0')}`
    })
    .join('') +
  ')'

export function invoicePdf({ issued, due }: InvoiceDates): Uint8Array {
  const ops: string[] = []
  const text = (x: number, y: number, s: string, size = 9, bold = false, rgb = '0.11 0.13 0.15') =>
    ops.push(`BT ${rgb} rg /${bold ? 'F2' : 'F1'} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td ${lit(s)} Tj ET`)
  const right = (x: number, y: number, s: string, size = 9, bold = false) => text(x - widthOf(s, size), y, s, size, bold)
  const rule = (x1: number, y: number, x2: number, w = 0.6, rgb = '0.80 0.82 0.84') => ops.push(`${rgb} RG ${w} w ${x1} ${y} m ${x2} ${y} l S`)
  const box = (x: number, y: number, w: number, h: number, rgb: string) => ops.push(`${rgb} rg ${x} ${y} ${w} ${h} re f`)
  const muted = '0.38 0.42 0.46'
  const green = '0.18 0.36 0.24'

  // Letterhead
  box(0, 806, 595, 36, green)
  text(48, 818, 'Sierra Verde Coffee Exporters', 15, true, '1 1 1')
  text(372, 818, 'Specialty green coffee since 2014', 9, false, '0.86 0.92 0.88')
  text(48, 784, 'Carrera 4 # 9-27, Pitalito, Huila, Colombia', 9, false, muted)
  text(48, 771, 'NIT 900482115-3   |   finance@sierraverde.co   |   +57 608 836 2140', 9, false, muted)

  text(48, 728, 'Commercial invoice', 22, true)
  const meta: [string, string][] = [
    ['Invoice number', 'INV-2026-0142'],
    ['Issue date', fmt(issued)],
    ['Due date', fmt(due)],
    ['Payment terms', 'Net 60 days'],
    ['Incoterms', 'FOB Buenaventura'],
  ]
  meta.forEach(([k, v], i) => {
    text(372, 734 - i * 15, k, 9, false, muted)
    text(460, 734 - i * 15, v, 9, true)
  })

  const shipped = new Date(issued)
  shipped.setDate(shipped.getDate() - 4)
  const eta = new Date(issued)
  eta.setDate(eta.getDate() + 28)
  text(48, 640, 'Bill to', 9, true, muted)
  ;['Kaffeehaus Berlin GmbH', 'Torstrasse 112, 10119 Berlin, Germany', 'VAT DE 314 159 265', 'payables@kaffeehaus-berlin.de'].forEach((l, i) =>
    text(48, 625 - i * 13, l, 10, i === 0),
  )
  text(300, 640, 'Shipment', 9, true, muted)
  ;['Vessel Maersk Cartagena, voyage 241E', 'Bill of lading MAEU 261404 142', 'Container MSKU 482115 3, 20 ft dry', `Shipped ${fmt(shipped)}, ETA Hamburg ${fmt(eta)}`].forEach((l, i) =>
    text(300, 625 - i * 13, l, 10),
  )

  // Line items
  const top = 540
  box(48, top - 6, 499, 22, '0.94 0.95 0.96')
  text(56, top + 1, 'Description', 9, true)
  right(372, top + 1, 'Quantity', 9, true)
  right(452, top + 1, 'Unit price', 9, true)
  right(539, top + 1, 'Amount', 9, true)
  const items: [string, string, string, number, number][] = [
    ['Huila Supremo, washed Arabica, screen 17/18', 'Lot SV-2609-H, 10 bags of 69 kg', '690 kg', 8.5, 5865],
    ['Nariño Excelso EP, washed Arabica', 'Lot SV-2609-N, 6 bags of 69 kg', '414 kg', 8.0, 3312],
    ['Export documents', 'Certificate of origin, phytosanitary certificate', '1', 73, 73],
  ]
  items.forEach(([d, sub, q, unit, amt], i) => {
    const y = top - 30 - i * 36
    text(56, y, d, 10, true)
    text(56, y - 13, sub, 8.5, false, muted)
    right(372, y, q, 10)
    right(452, y, eur(unit), 10)
    right(539, y, eur(amt), 10)
    rule(48, y - 22, 547)
  })

  const sumY = top - 30 - items.length * 36 - 10
  const totals: [string, string][] = [
    ['Subtotal', eur(9250)],
    ['VAT (export, exempt)', eur(0)],
  ]
  totals.forEach(([k, v], i) => {
    text(372, sumY - i * 16, k, 9.5, false, muted)
    right(539, sumY - i * 16, v, 9.5)
  })
  box(364, sumY - 52, 183, 24, green)
  text(372, sumY - 44, 'Total due', 11, true, '1 1 1')
  text(539 - widthOf('EUR 9,250.00', 11), sumY - 44, 'EUR 9,250.00', 11, true, '1 1 1')

  // Payment details
  const payY = sumY - 100
  text(48, payY, 'Payment details', 9, true, muted)
  ;[
    'Beneficiary: Sierra Verde Coffee Exporters',
    'Bank: Bancolombia, Pitalito branch',
    'Account: 112-345678-90 (EUR)',
    'Reference: INV-2026-0142',
  ].forEach((l, i) => text(48, payY - 15 - i * 13, l, 10))
  text(300, payY, 'Notes', 9, true, muted)
  ;['Green coffee, crop 2025/26, packed in GrainPro liners.', 'Quality per approved pre-shipment sample PS-0921.', 'Please quote the invoice number with your payment.'].forEach((l, i) =>
    text(300, payY - 15 - i * 13, l, 9.5),
  )

  rule(48, 70, 547)
  text(48, 54, 'Sierra Verde Coffee Exporters, Pitalito, Huila, Colombia. Thank you for your business.', 8.5, false, muted)
  right(547, 54, 'Page 1 of 1', 8.5)

  const stream = ops.join('\n')
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
    `<< /Title ${lit('Invoice INV-2026-0142')} /Author ${lit('Sierra Verde Coffee Exporters')} >>`,
  ]
  let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
  const offsets: number[] = []
  objects.forEach((o, i) => {
    offsets.push(out.length)
    out += `${i + 1} 0 obj\n${o}\nendobj\n`
  })
  const xref = out.length
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  out += offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info ${objects.length} 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  return Uint8Array.from(out, (c) => c.charCodeAt(0))
}

/** Writes the invoice into demo/assets and returns its path. */
export function writeInvoicePdf(dates: InvoiceDates): string {
  const dir = new URL('./assets/', import.meta.url).pathname
  mkdirSync(dir, { recursive: true })
  const path = `${dir}INV-2026-0142.pdf`
  writeFileSync(path, invoicePdf(dates))
  return path
}

if (import.meta.main) {
  const issued = new Date()
  const due = new Date(issued)
  due.setDate(due.getDate() + 60)
  console.log('wrote', writeInvoicePdf({ issued, due }))
}
