-- Versioned correction of unchanged factory mappings only.
-- Source: Directive (EU) 2022/2555, Article 21(2), reviewed 2026-11-02.
-- https://eur-lex.europa.eu/eli/dir/2022/2555/oj
-- One statement: conflicts roll back all reference edits. No tenant status writes.
WITH corrections (
    id, control_id, control_code, framework, old_source_code, old_source_title,
    old_legal_reference, old_coverage_level, old_rationale,
    new_source_code, new_legal_reference
) AS (VALUES
    (1007, 3, 'ISCY-03', 'NIS2', 'NIS2-21-2D', 'Security in acquisition, development and maintenance', 'NIS2 Art. 21(2)(d)', 'SUPPORTING', 'Projekt- und Demand-Governance verankert Security-Anforderungen frueh.', 'NIS2-21-2E', 'NIS2 Art. 21(2)(e)'),
    (1020, 7, 'ISCY-07', 'NIS2', 'NIS2-21-2D-F', 'Vulnerability handling and cyber hygiene', 'NIS2 Art. 21(2)(d), Art. 21(2)(f)', 'PRIMARY', 'CVE-Priorisierung und Remediation zahlen direkt auf NIS2 ein.', 'NIS2-21-2E-G', 'NIS2 Art. 21(2)(e), Art. 21(2)(g)'),
    (1026, 9, 'ISCY-09', 'NIS2', 'NIS2-21-2H-I', 'Access control and MFA', 'NIS2 Art. 21(2)(h), Art. 21(2)(i)', 'PRIMARY', 'IAM, MFA und Lifecycle sind direkte NIS2-Pflichten.', 'NIS2-21-2I-J', 'NIS2 Art. 21(2)(i), Art. 21(2)(j)'),
    (1029, 10, 'ISCY-10', 'NIS2', 'NIS2-21-2H-ASSET', 'Asset management', 'NIS2 Art. 21(2)(h)', 'PRIMARY', 'Asset-Transparenz ist Basis fuer Scope, Risiken und Meldebewertung.', 'NIS2-21-2I-ASSET', 'NIS2 Art. 21(2)(i)'),
    (1035, 12, 'ISCY-12', 'NIS2', 'NIS2-21-2D-CHANGE', 'Security in maintenance', 'NIS2 Art. 21(2)(d)', 'PRIMARY', 'Aenderungen muessen sicherheitsbezogen bewertet und kontrolliert werden.', 'NIS2-21-2E-CHANGE', 'NIS2 Art. 21(2)(e)'),
    (1042, 14, 'ISCY-14', 'NIS2', 'NIS2-21-2D-SDLC', 'Secure development and maintenance', 'NIS2 Art. 21(2)(d)', 'PRIMARY', 'Sichere Entwicklung wird auch fuer NIS2-Umsetzung benoetigt.', 'NIS2-21-2E-SDLC', 'NIS2 Art. 21(2)(e)'),
    (1044, 15, 'ISCY-15', 'NIS2', 'NIS2-21-2C-SUPPLY', 'Supply chain security', 'NIS2 Art. 21(2)(c)', 'PRIMARY', 'Third-Party Risk operationalisiert Lieferkettenpflichten.', 'NIS2-21-2D-SUPPLY', 'NIS2 Art. 21(2)(d)'),
    (1048, 16, 'ISCY-16', 'NIS2', 'NIS2-21-2C-COMP', 'Supply chain evidence', 'NIS2 Art. 21(2)(c)', 'SUPPORTING', 'Komponententransparenz verbessert Lieferkettenrisikobewertungen.', 'NIS2-21-2D-COMP', 'NIS2 Art. 21(2)(d)'),
    (1072, 24, 'ISCY-24', 'NIS2', 'NIS2-21-2B-EFFECTIVENESS', 'Effectiveness of measures', 'NIS2 Art. 21(2)(b)', 'PRIMARY', 'Wirksamkeitsbewertung wird in Verbesserungsmassnahmen uebersetzt.', 'NIS2-21-2F-EFFECTIVENESS', 'NIS2 Art. 21(2)(f)'),
    (1077, 26, 'ISCY-26', 'NIS2', 'NIS2-21-2H-HR', 'Human resources security', 'NIS2 Art. 21(2)(h)', 'PRIMARY', 'HR-Lifecycle ist direkt mit Zugriff, Rollen und Asset-Schutz gekoppelt.', 'NIS2-21-2I-HR', 'NIS2 Art. 21(2)(i)')
)
UPDATE iscy_control_regulatorymapping AS mapping
SET source_code = (SELECT new_source_code FROM corrections WHERE id = mapping.id),
    legal_reference = (SELECT new_legal_reference FROM corrections WHERE id = mapping.id),
    updated_at = CAST(CURRENT_TIMESTAMP AS TEXT)
WHERE EXISTS (
    SELECT 1 FROM corrections AS correction
    JOIN iscy_control_control AS control ON control.id = correction.control_id
    WHERE mapping.id = correction.id
      AND control.code = correction.control_code
      AND mapping.control_id = correction.control_id
      AND mapping.framework = correction.framework
      AND mapping.source_code = correction.old_source_code
      AND mapping.source_title = correction.old_source_title
      AND mapping.legal_reference = correction.old_legal_reference
      AND mapping.coverage_level = correction.old_coverage_level
      AND mapping.rationale = correction.old_rationale
);
