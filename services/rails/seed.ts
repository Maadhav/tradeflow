// Seed data for the rails sandbox: the businesses, their documents and credit files,
// the lenders and their KYC files. All names are fictional. Wallet addresses are fresh
// keys generated for this project (addresses.json); private keys stay in .secrets/.

import addresses from './addresses.json'
const A = addresses as Record<string, `0x${string}`>

export type Borrower = {
  id: string
  name: string
  country: string
  wallet: `0x${string}`
  bankAccount: string
  credit: {
    yearsTrading: number
    annualRevenueUsd: number
    onTimeRate: number // share of past invoices paid on time, 0..1
    avgDaysLate: number
    openDebtUsd: number
    priorLoans: number
  }
}

export type Document = {
  number: string
  type: 'invoice' | 'bill_of_lading' | 'equipment' | 'working_capital'
  borrowerId: string
  buyer: string
  buyerCountry: string
  amountMinor: number // 2 decimals
  currency: 'EUR' | 'USD'
  issuedAt: string
  dueInDays: number
  buyerConfirmed: boolean
  title: string
}

export type Lender = {
  id: string
  name: string
  country: string
  kycStatus: 'approved' | 'pending' | 'rejected'
  kycLevel: string
  wallet: `0x${string}`
  funding: 'fiat' | 'stablecoin'
  bankAccount?: string
}

export const borrowers: Borrower[] = [
  {
    id: 'biz-sierra-verde',
    name: 'Sierra Verde Coffee Exporters',
    country: 'CO',
    wallet: A['biz-sierra-verde'],
    bankAccount: 'CO-BANC-4471-2290',
    credit: { yearsTrading: 9, annualRevenueUsd: 4_200_000, onTimeRate: 0.96, avgDaysLate: 2, openDebtUsd: 180_000, priorLoans: 14 },
  },
  {
    id: 'biz-pacific-freight',
    name: 'Pacific Freight Lines',
    country: 'SG',
    wallet: A['biz-pacific-freight'],
    bankAccount: 'SG-DBS-0021-7788',
    credit: { yearsTrading: 12, annualRevenueUsd: 11_800_000, onTimeRate: 0.98, avgDaysLate: 1, openDebtUsd: 950_000, priorLoans: 31 },
  },
  {
    id: 'biz-medina-textiles',
    name: 'Medina Textiles',
    country: 'MX',
    wallet: A['biz-medina-textiles'],
    bankAccount: 'MX-SPEI-0129-4410',
    credit: { yearsTrading: 4, annualRevenueUsd: 1_350_000, onTimeRate: 0.88, avgDaysLate: 6, openDebtUsd: 240_000, priorLoans: 5 },
  },
  {
    id: 'biz-rapid-parts',
    name: 'Rapid Parts Trading',
    country: 'AE',
    wallet: A['biz-rapid-parts'],
    bankAccount: 'AE-ENBD-3307-1192',
    credit: { yearsTrading: 3, annualRevenueUsd: 900_000, onTimeRate: 0.86, avgDaysLate: 7, openDebtUsd: 160_000, priorLoans: 3 },
  },
]

export const documents: Document[] = [
  {
    number: 'INV-2026-0142',
    type: 'invoice',
    borrowerId: 'biz-sierra-verde',
    buyer: 'Kaffeehaus Berlin GmbH',
    buyerCountry: 'DE',
    amountMinor: 925_000,
    currency: 'EUR',
    issuedAt: '2026-10-01',
    dueInDays: 60,
    buyerConfirmed: true,
    title: 'Invoice advance: 4 containers of washed Arabica',
  },
  {
    number: 'BL-SGSIN-88231',
    type: 'bill_of_lading',
    borrowerId: 'biz-pacific-freight',
    buyer: 'Harbor Retail Group LLC',
    buyerCountry: 'US',
    amountMinor: 1_500_000,
    currency: 'USD',
    issuedAt: '2026-10-03',
    dueInDays: 90,
    buyerConfirmed: true,
    title: 'Supply chain finance: electronic bill of lading',
  },
  {
    number: 'EQ-2026-0077',
    type: 'equipment',
    borrowerId: 'biz-medina-textiles',
    buyer: 'Telares Industriales S.A.',
    buyerCountry: 'MX',
    amountMinor: 2_000_000,
    currency: 'USD',
    issuedAt: '2026-09-28',
    dueInDays: 180,
    buyerConfirmed: true,
    title: 'Equipment finance: 6 jacquard looms',
  },
  {
    number: 'INV-2026-0388',
    type: 'invoice',
    borrowerId: 'biz-rapid-parts',
    buyer: 'Gulf Auto Services LLC',
    buyerCountry: 'AE',
    amountMinor: 400_000,
    currency: 'USD',
    issuedAt: '2026-10-02',
    dueInDays: 1,
    buyerConfirmed: true,
    title: 'Invoice advance: spare parts order',
  },
  {
    number: 'INV-2026-0999',
    type: 'invoice',
    borrowerId: 'biz-sierra-verde',
    buyer: 'Northbrook Trading Ltd',
    buyerCountry: 'GB',
    amountMinor: 5_000_000,
    currency: 'EUR',
    issuedAt: '2026-10-04',
    dueInDays: 60,
    buyerConfirmed: false,
    title: 'Invoice advance: specialty coffee lot',
  },
]

export const lenders: Lender[] = [
  {
    id: 'lender-ana',
    name: 'Ana Ruiz',
    country: 'ES',
    kycStatus: 'approved',
    kycLevel: 'retail-verified',
    wallet: A['ana'],
    funding: 'fiat',
    bankAccount: 'ES91 2100 0418 4502 0005 1332',
  },
  {
    id: 'lender-ben',
    name: 'Ben Carter',
    country: 'US',
    kycStatus: 'approved',
    kycLevel: 'accredited',
    wallet: A['ben'],
    funding: 'stablecoin',
  },
  {
    id: 'lender-chen',
    name: 'Chen Wei',
    country: 'SG',
    kycStatus: 'pending',
    kycLevel: 'none',
    wallet: A['chen'],
    funding: 'stablecoin',
  },
]
