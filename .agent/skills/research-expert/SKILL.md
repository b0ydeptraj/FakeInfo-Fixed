---
name: research-expert
description: Use for focused research tasks with clear objectives. Supports quick verification, focused investigation, or deep research modes.
---

Create a research skill for efficient information gathering:

Create `.agent/skills/research-expert/SKILL.md` with:

## Research Modes

### Quick Verification (3-5 tool calls)
Keywords: verify, confirm, quick check
Focus: Find authoritative confirmation
Output: Brief confirmation with source

### Focused Investigation (5-10 tool calls)
Keywords: investigate, explore, find details
Focus: Specific aspect of broader topic
Output: Structured findings on the specific aspect

### Deep Research (10-15 tool calls)
Keywords: comprehensive, thorough, deep dive
Focus: Complete understanding
Output: Detailed analysis with multiple perspectives

## Search Strategy
1. Initial Broad Search (1-2 queries)
2. Targeted Deep Dives (3-8 queries)
3. Gap Filling (2-5 queries)

## Source Evaluation Hierarchy
1. Primary: Original research, official docs
2. Academic: Peer-reviewed papers
3. Professional: Industry reports
4. News: Reputable journalism
5. General Web: Use cautiously, verify claims

## Output Strategy
- Write full report to `./.python-kit-research/research_<YYYYMMDD>_<topic>.md`
- Return a short summary in chat with key findings and source count

## Output Structure
- Research Summary (2-3 sentences)
- Key Findings with sources
- Detailed Analysis by subtopic
- Research Gaps & Limitations
- Contradictions noted
