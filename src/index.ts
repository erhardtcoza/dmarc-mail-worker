import * as PostalMime from "postal-mime"
import * as mimeDb from "mime-db"
import * as unzipit from "unzipit"
import * as pako from "pako"
import { XMLParser } from "fast-xml-parser"

import {
Env,
Attachment,
DmarcRecordRow,
AlignmentType,
DispositionType,
DMARCResultType,
PolicyOverrideType,
} from "./types"

export default {
async email(message: EmailMessage, env: Env, ctx: ExecutionContext) {
await handleEmail(message, env)
},
}

async function handleEmail(message: EmailMessage, env: Env) {

const parser = new PostalMime.default()

const rawEmail = new Response(message.raw)
const email = await parser.parse(await rawEmail.arrayBuffer())

if (!email.attachments || email.attachments.length === 0) {
throw new Error("No DMARC attachments found")
}

const attachment = email.attachments[0]

if (env.R2_BUCKET) {
const date = new Date()

await env.R2_BUCKET.put(
`${date.getUTCFullYear()}/${date.getUTCMonth()+1}/${attachment.filename}`,
attachment.content
)
}

const reportJSON = await getDMARCReportXML(attachment)
const reportRows = getReportRows(reportJSON)

await sendToAnalyticsEngine(env, reportRows)
await storeInD1(env, reportRows)

}

async function getDMARCReportXML(attachment: Attachment) {

const parser = new XMLParser()

const extension = mimeDb[attachment.mimeType]?.extensions?.[0] || ""

let xml

const buffer = attachment.content instanceof ArrayBuffer
? attachment.content
: new TextEncoder().encode(attachment.content).buffer

switch (extension) {

case "gz":

try{
xml = pako.ungzip(new Uint8Array(buffer), { to: "string" })
}catch(e){
throw new Error("Failed to decompress GZIP DMARC report")
}

break

case "zip":

xml = await extractZipXML(buffer)
break

case "xml":

xml = new TextDecoder().decode(buffer)
break

default:

// fallback attempt
try{
xml = pako.ungzip(new Uint8Array(buffer), { to: "string" })
}catch{
xml = new TextDecoder().decode(buffer)
}

}

return parser.parse(xml)

}

async function extractZipXML(buffer: ArrayBuffer) {

const { entries } = await unzipit.unzip(buffer)

const files = Object.values(entries)

if (!files.length) {
throw new Error("ZIP DMARC report contained no files")
}

const file = files[0]

return await file.text()

}

function getReportRows(report: any): DmarcRecordRow[] {

const reportMetadata = report.feedback.report_metadata
const policyPublished = report.feedback.policy_published

const records = Array.isArray(report.feedback.record)
? report.feedback.record
: [report.feedback.record]

const rows: DmarcRecordRow[] = []

for (let record of records) {

rows.push({

reportMetadataReportId: reportMetadata.report_id.toString().replace("-", "_"),

reportMetadataOrgName: reportMetadata.org_name || "",

reportMetadataDateRangeBegin: parseInt(reportMetadata.date_range.begin) || 0,

reportMetadataDateRangeEnd: parseInt(reportMetadata.date_range.end) || 0,

reportMetadataError: JSON.stringify(reportMetadata.error) || "",

policyPublishedDomain: policyPublished.domain || "",

policyPublishedADKIM:
AlignmentType[policyPublished.adkim as keyof typeof AlignmentType],

policyPublishedASPF:
AlignmentType[policyPublished.aspf as keyof typeof AlignmentType],

policyPublishedP:
DispositionType[policyPublished.p as keyof typeof DispositionType],

policyPublishedSP:
DispositionType[policyPublished.sp as keyof typeof DispositionType],

policyPublishedPct: parseInt(policyPublished.pct) || 0,

recordRowSourceIP: record.row.source_ip || "",

recordRowCount: parseInt(record.row.count) || 0,

recordRowPolicyEvaluatedDKIM:
DMARCResultType[
record.row.policy_evaluated.dkim as keyof typeof DMARCResultType
],

recordRowPolicyEvaluatedSPF:
DMARCResultType[
record.row.policy_evaluated.spf as keyof typeof DMARCResultType
],

recordRowPolicyEvaluatedDisposition:
DispositionType[
record.row.policy_evaluated.disposition as keyof typeof DispositionType
],

recordRowPolicyEvaluatedReasonType:
PolicyOverrideType[
record.row.policy_evaluated?.reason?.type as keyof typeof PolicyOverrideType
],

recordIdentifiersEnvelopeTo: record.identifiers.envelope_to || "",

recordIdentifiersHeaderFrom: record.identifiers.header_from || "",

})

}

return rows

}

async function sendToAnalyticsEngine(env: Env, reportRows: DmarcRecordRow[]) {

if (!env.DMARC_ANALYTICS) return

reportRows.forEach((row, index) => {

const blobs:string=[]
const doubles:number=[]
const indexes:string=[]

indexes.push(
encodeURI(`${row.reportMetadataReportId}-${index}`).slice(0,32)
)

blobs.push(row.reportMetadataReportId)
blobs.push(row.reportMetadataOrgName)

doubles.push(row.reportMetadataDateRangeBegin)
doubles.push(row.reportMetadataDateRangeEnd)

blobs.push(row.reportMetadataError)

blobs.push(row.policyPublishedDomain)

doubles.push(row.policyPublishedADKIM)
doubles.push(row.policyPublishedASPF)
doubles.push(row.policyPublishedP)
doubles.push(row.policyPublishedSP)
doubles.push(row.policyPublishedPct)

blobs.push(row.recordRowSourceIP)

doubles.push(row.recordRowCount)
doubles.push(row.recordRowPolicyEvaluatedDKIM)
doubles.push(row.recordRowPolicyEvaluatedSPF)
doubles.push(row.recordRowPolicyEvaluatedDisposition)
doubles.push(row.recordRowPolicyEvaluatedReasonType)

blobs.push(row.recordIdentifiersEnvelopeTo)
blobs.push(row.recordIdentifiersHeaderFrom)

env.DMARC_ANALYTICS.writeDataPoint({
blobs,
doubles,
indexes
})

})

}

async function storeInD1(env: Env, reportRows: DmarcRecordRow[]) {

if (!env.DB) return

const now = Date.now()

for (const row of reportRows) {

await env.DB.prepare(`INSERT INTO dmarc_records (
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
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
