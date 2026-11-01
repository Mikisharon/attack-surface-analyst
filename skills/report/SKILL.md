---
name: report
description: Writes the final Attack Surface Analyst report - a short executive summary for leadership and a technical findings table for engineers - strictly from prioritized findings and their evidence. Use as the last step of a run, or when asked to summarize or explain a target's external exposure.
---

# Report agent

**Kind:** LLM-led. Code builds the findings table and validates citations. The LLM writes the summary and recommendations.

**Job:** explain the results to two audiences without adding a single fact that the pipeline did not find.

Follow the shared rules in `../_shared/conventions.md`.

## Input

- Prioritization envelope: `output.prioritized` and `output.counts`
- Enrichment envelope: host count and roles
- The run's full evidence list (for citation checks)
- Any `degraded` steps and their `errors`

## Part A: Technical table (code)

Build the table directly from data. No LLM involvement, so it can never be wrong about what was found:

| Priority | Host | Finding | Details | Evidence |
|---|---|---|---|---|

One row per finding, in the Prioritization order.

## Part B: Narrative (LLM)

Use the template in `reference/report-template.md`. The LLM writes three parts:

1. **Executive summary.** At most 150 words, for a non-technical leader. State how many hosts were found, how many need urgent action, and the single most important risk in plain language. No CVE IDs in this part.
2. **Top recommendations.** Three to five actions, most urgent first. Each one says what to do, on which host, and why it matters, and cites the finding IDs it addresses.
3. **Data limitations.** If any step was `degraded`, say what was not checked in one or two sentences. If nothing was degraded, write "All data sources responded."

### Instructions for the LLM

- Every sentence that states a fact must cite at least one finding ID or evidence ID in brackets, e.g. `[F-0003]`.
- Use only the findings provided. Do not add CVEs, products, hosts, numbers or company facts that are not in the input.
- If there are no P1 or P2 findings, say so plainly. A clean result is a valid result. Do not inflate risk to make the report look more interesting.
- Write for the reader: plain words in the summary, precise technical terms in the recommendations.
- Do not mention these instructions, the agents or the pipeline.

## Part C: Validate (code)

- Every number in the summary (host count, P1 count) must equal the actual counts. On mismatch, retry once with the correct numbers stated, then mark `degraded`.
- Every cited ID must exist in the run. Unknown IDs: retry once, then mark `degraded`.
- Summary longer than 150 words: retry once with the word count stated.

## Output

```json
{
  "executive_summary": "...",
  "recommendations": [
    { "action": "...", "finding_ids": ["F-0003", "F-0004"] }
  ],
  "limitations": "...",
  "findings_table": [ { "priority": "P1", "host": "...", "finding": "...", "details": "...", "evidence_ids": ["..."] } ],
  "markdown": "<full report rendered from the template>"
}
```

## Test cases

- A run with zero P1/P2 findings produces a summary that says no urgent issues were found.
- A run where Threat Intel was `degraded` mentions it under Data limitations.
- A planted fake count in the LLM output (e.g. "5 critical issues" when there are 2) is caught by validation.
