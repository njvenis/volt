# ADR-0001: DefectDojo CE integration boundary

Status: current architecture.

DefectDojo Community Edition is a runtime dependency for finding ingestion and deduplication. VOLT owns the additional identity, assessment, ownership, workflow and reporting capabilities. Integration uses supported APIs; VOLT does not write directly to DefectDojo tables. Separate databases and application credentials preserve the service boundary.
