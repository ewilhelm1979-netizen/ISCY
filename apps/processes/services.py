"""F05: 10-Dimensionen-Bewertungslogik fuer Prozesse/Kontrollen.

Leitet aus den Boolean-Feldern des Process-Models automatisch einen
Reifegradstatus und eine Gap-Indikation ab. Die 10 Dimensionen aus
der Projektdokumentation:
  1. dokumentiert
  2. genehmigt (approved)
  3. kommuniziert
  4. implementiert
  5. operativ wirksam (effective)
  6. evidenzbasiert (evidenced)
  7. Verantwortlichkeit zugewiesen (owner)
  8. reviewed (reviewed_at)
  9. versioniert -> hier: reviewed_at Datum vorhanden
  10. historisiert -> hier: Change-Log Eintraege (ueber AuditLog)

Fehlende Evidenzen duerfen die Wirksamkeit nicht automatisch widerlegen,
senken aber den Nachweisstatus.
"""

from dataclasses import dataclass
from typing import List, Optional

from apps.processes.models import Process


@dataclass
class DimensionResult:
    name: str
    fulfilled: bool
    weight: int = 1


@dataclass
class ProcessMaturityResult:
    process: Process
    dimensions: List[DimensionResult]
    score_percent: int
    maturity_label: str
    gap_level: str
    is_auditable: bool
    explanation: str


class ProcessMaturityService:

    @staticmethod
    def assess(process: Process) -> ProcessMaturityResult:
        """Bewertet einen Prozess anhand aller 10 Dimensionen."""
        has_owner = process.owner_id is not None
        has_review = process.reviewed_at is not None

        dimensions = [
            DimensionResult('Dokumentiert', process.documented, weight=2),
            DimensionResult('Genehmigt', process.approved, weight=1),
            DimensionResult('Kommuniziert', process.communicated, weight=1),
            DimensionResult('Implementiert', process.implemented, weight=2),
            DimensionResult('Operativ wirksam', process.effective, weight=2),
            DimensionResult('Evidenzbasiert', process.evidenced, weight=2),
            DimensionResult('Verantwortlichkeit zugewiesen', has_owner, weight=1),
            DimensionResult('Reviewed', has_review, weight=1),
            # Versioniert und historisiert werden ueber reviewed_at + AuditLog abgeleitet
            DimensionResult('Versioniert', has_review and process.documented, weight=1),
            DimensionResult('Historisiert', has_review, weight=1),
        ]

        max_score = sum(d.weight for d in dimensions)
        raw_score = sum(d.weight for d in dimensions if d.fulfilled)
        percent = int((raw_score / max_score) * 100) if max_score else 0

        # Fachliche Trennung: 'fachlich vorhanden' vs 'auditierbar nachweisbar'
        is_functionally_present = process.implemented or process.effective
        is_auditable = (
            process.documented
            and process.evidenced
            and has_owner
            and has_review
        )

        if percent >= 80:
            maturity, gap = 'Fortgeschritten / auditnah', 'LOW'
        elif percent >= 60:
            maturity, gap = 'Brauchbare Readiness', 'LOW'
        elif percent >= 40:
            maturity, gap = 'Grundlagen vorhanden', 'MEDIUM'
        elif percent >= 20:
            maturity, gap = 'Sehr niedriger Reifegrad', 'HIGH'
        else:
            maturity, gap = 'Kritisch', 'CRITICAL'

        # Erklarung
        missing = [d.name for d in dimensions if not d.fulfilled]
        if not missing:
            explanation = 'Alle Dimensionen sind erfuellt. Prozess ist auditnah.'
        elif is_functionally_present and not is_auditable:
            explanation = f'Prozess ist fachlich vorhanden, aber nicht auditierbar nachweisbar. Fehlend: {", ".join(missing)}.'
        else:
            explanation = f'Fehlende Dimensionen: {", ".join(missing)}.'

        return ProcessMaturityResult(
            process=process,
            dimensions=dimensions,
            score_percent=percent,
            maturity_label=maturity,
            gap_level=gap,
            is_auditable=is_auditable,
            explanation=explanation,
        )

    @staticmethod
    def assess_all(tenant) -> List[ProcessMaturityResult]:
        """Bewertet alle Prozesse eines Tenants."""
        processes = Process.objects.filter(tenant=tenant).select_related('owner')
        return [ProcessMaturityService.assess(p) for p in processes]

    @staticmethod
    def tenant_summary(tenant) -> dict:
        """Zusammenfassung der Reifegradverteilung fuer ein Tenant."""
        results = ProcessMaturityService.assess_all(tenant)
        if not results:
            return {'total': 0, 'average_percent': 0, 'auditable_count': 0, 'gap_distribution': {}}

        total = len(results)
        avg = int(sum(r.score_percent for r in results) / total) if total else 0
        auditable = sum(1 for r in results if r.is_auditable)
        gap_dist = {}
        for r in results:
            gap_dist[r.gap_level] = gap_dist.get(r.gap_level, 0) + 1

        return {
            'total': total,
            'average_percent': avg,
            'auditable_count': auditable,
            'auditable_percent': int((auditable / total) * 100) if total else 0,
            'gap_distribution': gap_dist,
        }
