# Cyber Defense Lab Markdown reports

The Cyber Defense Lab can download a Markdown report for one stored execution
or for a bounded filtered history. Reports are generated from the authenticated
user's persisted simulation records; generating a report never reruns a
detector.

## Endpoints

- `GET /api/v1/cyber-defense/executions/{execution_id}/report.md`
- `GET /api/v1/cyber-defense/executions/report.md?from=&to=&verdict=`

Both endpoints require the existing bearer token and `read` scope. The filtered
report is capped at 200 executions and says so inside the Markdown file.

## Format

Each execution report contains metadata, a plain-language summary, the redacted
synthetic input, detector results and evidence, the simulation policy decision,
verified standards exercised by the authenticated API/detection path, recorded
timeline stages, limitations, reproduction steps, a generated-at time, and a
SHA-256 of the report body.

The report does not include bearer tokens, client secrets, actor identifiers, or
request keys. A detection is evidence about a trusted fixture, not proof of
compromise. A simulated block is a decision in the demonstration and does not
block real traffic or processes.

## Demo command

For a stable presentation build, run `npm run build && npm run start` in
`frontend/` after starting the backend. The Next.js development indicator is
disabled so it cannot overlap the navigation during a demo.
