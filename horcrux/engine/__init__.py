"""Evidence-driven security engine — deterministic pipeline.

DISCOVERY -> NORMALIZATION -> ASSET/REQUEST MODEL -> PROPERTY IDENTIFICATION
-> APPLICABILITY -> TEST GENERATION -> EXECUTION/OBSERVATION
-> EVIDENCE EXTRACTION -> CORRELATION -> SECURITY ORACLE -> ADJUDICATION
-> DEDUPLICATED CANONICAL FINDING -> PROPERTY LEDGER -> ATTACK PATHS/REPORT/GATE

"Interesting response" never directly becomes "finding". Every conclusion
travels: observation -> evidence -> security property evaluation -> finding,
with an explicit traceable chain. No AI dependency anywhere in this path.
"""
