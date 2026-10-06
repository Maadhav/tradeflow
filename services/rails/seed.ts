// Sandbox reference data of the third parties the rails play: the credit bureau's files and
// the KYC provider's decision rule. Nothing here is a customer: businesses and lenders sign up
// through the app, and their documents are entered by the business and confirmed by the buyer.
// All names are fictional.

import { keccak256, toHex } from 'viem'

export type CreditFile = {
  yearsTrading: number
  annualRevenueUsd: number
  onTimeRate: number // share of past invoices paid on time, 0..1
  avgDaysLate: number
  openDebtUsd: number
  priorLoans: number
}

/** Registration numbers are compared without case, spaces, dots or dashes. */
export const normalizeRegistration = (s: string) => s.toUpperCase().replace(/[\s.\-]/g, '')

/** Credit bureau files on record, keyed by country and normalized registration number. */
export const bureau: { name: string; country: string; registrationNumber: string; credit: CreditFile }[] = [
  {
    name: 'Sierra Verde Coffee Exporters',
    country: 'CO',
    registrationNumber: '900482115-3',
    credit: { yearsTrading: 9, annualRevenueUsd: 4_200_000, onTimeRate: 0.96, avgDaysLate: 2, openDebtUsd: 180_000, priorLoans: 14 },
  },
  {
    name: 'Pacific Freight Lines',
    country: 'SG',
    registrationNumber: '201412345K',
    credit: { yearsTrading: 12, annualRevenueUsd: 11_800_000, onTimeRate: 0.98, avgDaysLate: 1, openDebtUsd: 950_000, priorLoans: 31 },
  },
  {
    name: 'Medina Textiles',
    country: 'MX',
    registrationNumber: 'MTE180503KL2',
    credit: { yearsTrading: 4, annualRevenueUsd: 1_350_000, onTimeRate: 0.88, avgDaysLate: 6, openDebtUsd: 240_000, priorLoans: 5 },
  },
  {
    name: 'Rapid Parts Trading',
    country: 'AE',
    registrationNumber: 'CN-3307119',
    credit: { yearsTrading: 3, annualRevenueUsd: 900_000, onTimeRate: 0.86, avgDaysLate: 7, openDebtUsd: 160_000, priorLoans: 3 },
  },
]

/**
 * The bureau file for a registered company. Companies the bureau has no record of get a
 * synthetic file derived from keccak256(country | registration number), so the same company
 * always gets the same file.
 */
export function bureauFile(country: string, registrationNumber: string): CreditFile {
  const reg = normalizeRegistration(registrationNumber)
  const known = bureau.find((b) => b.country === country && normalizeRegistration(b.registrationNumber) === reg)
  if (known) return known.credit
  const h = keccak256(toHex(`${country}|${reg}`))
  const word = (i: number) => parseInt(h.slice(2 + i * 4, 6 + i * 4), 16) // 16-bit words of the hash
  const frac = (i: number) => word(i) / 0xffff
  const annualRevenueUsd = Math.round((500_000 + frac(1) * 11_500_000) / 10_000) * 10_000
  return {
    yearsTrading: 2 + (word(0) % 13),
    annualRevenueUsd,
    onTimeRate: (82 + (word(2) % 18)) / 100,
    avgDaysLate: word(3) % 10,
    openDebtUsd: Math.round((annualRevenueUsd * (0.05 + frac(4) * 0.2)) / 1_000) * 1_000,
    priorLoans: word(5) % 31,
  }
}

/** KYC provider decision: deterministic in the sandbox. */
export const KYC_BLOCKED_COUNTRIES = ['KP', 'IR', 'SY', 'CU']
export function kycDecision(country: string, funding: 'fiat' | 'stablecoin') {
  return {
    status: KYC_BLOCKED_COUNTRIES.includes(country) ? ('rejected' as const) : ('approved' as const),
    level: funding === 'fiat' ? 'retail-verified' : 'wallet-verified',
  }
}
