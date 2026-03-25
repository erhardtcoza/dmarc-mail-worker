import * as PostalMime from 'postal-mime'
import * as mimeDb from 'mime-db'
import * as unzipit from 'unzipit'
import * as pako from 'pako'
import { XMLParser } from 'fast-xml-parser'

import {
  Env,
  Attachment,
  DmarcRecordRow,
  AlignmentType,
  DispositionType,
  DMARCResultType,
  PolicyOverrideType,
} from './types'

export default {
  async email(message: EmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    await handleEmail(message, env, ctx)
  },
}

async function handleEmail(message: EmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
  const parser = new PostalMime.default()

  const rawEmail = new Response(message.raw)
  const email = await parser.parse(await rawEmail.arrayBuffer())

  if (!email.attachments || email.attachments.length === 0) {
    throw new Error('no attachments found')
  }

  const attachment = email.attachments[0]

  if (env.R2_BUCKET) {
    const date = new Date()
    await env.R2_BUCKET.put(
      `${date.getUTCFullYear()}/${date.getUTCMonth() + 1}/${attachment.filename}`,
      attachment.content
    )
  }

  const reportJSON = await getDMARCReportXML(attachment)
  const reportRows = getReportRows(reportJSON)

  await sendToAnalyticsEngine(env, reportRows)
  await storeInD1(env, reportRows)
}

async function getDMARCReportXML(attachment: Attachment) {
  let xml
  const xmlParser = new XMLParser()

  const extension = mimeDb[attachment.mimeType]?.extensions?.[0] || ''

  switch (extension) {
    case 'gz':
      xml = pako.inflate(new TextEncoder().encode(attachment.content as string), { to: 'string' })
      break

    case 'zip':
      xml = await getXMLFromZip(attachment.content)
      break

    case 'xml':
      xml = await new Response(attachment.content).text()
      break

    default:
      throw new Error(`unknown extension: ${extension}`)
  }

  return xmlParser.parse(xml)
}

async function getXMLFromZip(content: any) {
  const { entries } = await unzipit.unzipRaw(content)

  if (entries.length === 0) {
    throw new Error('zip file empty')
  }

  return await entries[0].text()
}

function getReportRows(report: any): DmarcRecordRow[] {
  const reportMetadata = report.feedback.report_metadata
  const policyPublished = report.feedback.policy_published
  const records = Array.isArray(report.feedback.record)
    ? report.feedback.record
    : [report.feedback.record]

  const listEvents: DmarcRecordRow[] = []

  for (let index = 0; index < records.length; index++) {
    const record = records[index]

    const reportRow: DmarcRecordRow = {
      reportMetadataReportId: reportMetadata.report_id.toString().replace('-', '_'),
      reportMetadataOrgName: reportMetadata.org_name || '',
      reportMetadataDateRangeBegin: parseInt(reportMetadata.date_range.begin) || 0,
      reportMetadataDateRangeEnd: parseInt(reportMetadata.date_range.end) || 0,
      reportMetadataError: JSON.stringify(reportMetadata.error) || '',

      policyPublishedDomain: policyPublished.domain || '',
      policyPublishedADKIM: AlignmentType[policyPublished.adkim as keyof typeof AlignmentType],
      policyPublishedASPF: AlignmentType[policyPublished.aspf as keyof typeof AlignmentType],
      policyPublishedP: DispositionType[policyPublished.p as keyof typeof DispositionType],
      policyPublishedSP: DispositionType[policyPublished.sp as keyof typeof DispositionType],
      policyPublishedPct: parseInt(policyPublished.pct) || 0,

      recordRowSourceIP: record.row.source_ip || '',
      recordRowCount: parseInt(record.row.count) || 0,
      recordRowPolicyEvaluatedDKIM:
        DMARCResultType[record.row.policy_evaluated.dkim as keyof typeof DMARCResultType],
      recordRowPolicyEvaluatedSPF:
        DMARCResultType[record.row.policy_evaluated.spf as keyof typeof DMARCResultType],
      recordRowPolicyEvaluatedDisposition:
        DispositionType[
          record.row.policy_evaluated.disposition as keyof typeof DispositionType
        ],

      recordRowPolicyEvaluatedReasonType:
        PolicyOverrideType[
          record.row.policy_evaluated?.reason?.type as keyof typeof PolicyOverrideType
        ],

      recordIdentifiersEnvelopeTo: record.identifiers.envelope_to || '',
      recordIdentifiersHeaderFrom: record.identifiers.header_from || '',
    }

    listEvents.push(reportRow)
  }

  return listEvents
}

async function sendToAnalyticsEngine(env: Env, reportRows: DmarcRecordRow[]) {
  if (!env.DMARC_ANALYTICS) return

  reportRows.forEach((recordRow, index) => {
    const blobs: string[] = []
    const doubles: number[] = []
    const indexes: string[] = []

    indexes.push(encodeURI(`${recordRow.reportMetadataReportId}-${index}`).slice(0, 32))

    blobs.push(recordRow.reportMetadataReportId)
    blobs.push(recordRow.reportMetadataOrgName)
    doubles.push(recordRow.reportMetadataDateRangeBegin)
    doubles.push(recordRow.reportMetadataDateRangeEnd)
    blobs.push(recordRow.reportMetadataError)

    blobs.push(recordRow.policyPublishedDomain)
    doubles.push(recordRow.policyPublishedADKIM)
    doubles.push(recordRow.policyPublishedASPF)
    doubles.push(recordRow.policyPublishedP)
    doubles.push(recordRow.policyPublishedSP)
    doubles.push(recordRow.policyPublishedPct)

    blobs.push(recordRow.recordRowSourceIP)
    doubles.push(recordRow.recordRowCount)
    doubles.push(recordRow.recordRowPolicyEvaluatedDKIM)
    doubles.push(recordRow.recordRowPolicyEvaluatedSPF)
    doubles.push(recordRow.recordRowPolicyEvaluatedDisposition)
    doubles.push(recordRow.recordRowPolicyEvaluatedReasonType)

    blobs.push(recordRow.recordIdentifiersEnvelopeTo)
    blobs.push(recordRow.recordIdentifiersHeaderFrom)

    env.DMARC_ANALYTICS.writeDataPoint({
      blobs,
      doubles,
      indexes,
    })
  })
}

async function storeInD1(env: Env, reportRows: DmarcRecordRow[]) {
  if (!env.DB) return

  const now = Date.now()

  for (const row of reportRows) {
    await env.DB.prepare(`
      INSERT INTO dmarc_records (
        report_id,
        org_name,
        domain,
        source_ip,
        count,
        spf,
        dkim,
        disposition,
        envelope_to,
        header_from,
        date_begin,
        date_end,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        row.reportMetadataReportId,
        row.reportMetadataOrgName,
        row.policyPublishedDomain,
        row.recordRowSourceIP,
        row.recordRowCount,
        row.recordRowPolicyEvaluatedSPF,
        row.recordRowPolicyEvaluatedDKIM,
        row.recordRowPolicyEvaluatedDisposition,
        row.recordIdentifiersEnvelopeTo,
        row.recordIdentifiersHeaderFrom,
        row.reportMetadataDateRangeBegin,
        row.reportMetadataDateRangeEnd,
        now
      )
      .run()
  }
}
