from django.conf import settings

from apps.evidence.models import EvidenceItem, RequirementEvidenceNeed
from apps.organizations.sector_catalog import get_sector_definition
from apps.requirements_app.models import Requirement


class EvidenceNeedService:
    DOMAIN_KEYWORDS = {
        'GOV': ['governance', 'scope', 'policy', 'roles', 'management'],
        'PROC': ['asset', 'prozess', 'process', 'inventory', 'register'],
        'SUP': ['supplier', 'liefer', 'third'],
        'IAM': ['identity', 'access', 'iam', 'mfa', 'privileg'],
        'CLOUD': ['cloud', 'shared responsibility', 'saas', 'hosting'],
        'SDLC': ['development', 'sdlc', 'change', 'release', 'code'],
        'CYBER': ['patch', 'vulnerability', 'hardening', 'hygiene'],
        'CRYPTO': ['crypto', 'verschlüssel', 'key'],
        'PHYS': ['physical', 'facility', 'zugang'],
        'DETECT': ['logging', 'monitoring', 'detection', 'alarm'],
        'INC': ['incident', 'meldung', 'response'],
        'BCM': ['backup', 'recovery', 'bcm', 'restore'],
        'AWARE': ['awareness', 'training', 'schulung'],
        'DOC': ['document', 'review', 'policy', 'version'],
    }

    @staticmethod
    def get_sector_packages(tenant):
        sector = get_sector_definition(getattr(tenant, 'sector', None))
        packages = {'ALL'}
        if sector.code in {'DIGITAL_PROVIDERS', 'DIGITAL_INFRASTRUCTURE', 'ICT_SERVICE_MANAGEMENT', 'MSSP'}:
            packages.add('DIGITAL')
        if sector.code in {'BANKING', 'FINANCIAL_MARKET_INFRASTRUCTURE'}:
            packages.add('FINANCE')
        if sector.kritis_related or sector.code in {'ENERGY', 'TRANSPORT', 'HEALTH', 'DRINKING_WATER', 'WASTEWATER', 'PUBLIC_ADMINISTRATION'}:
            packages.add('CRITICAL_INFRA')
        return packages

    @staticmethod
    def requirement_relevant(requirement, tenant):
        pkg = (requirement.sector_package or '').strip().upper()
        if not pkg or pkg == 'ALL':
            return True
        return pkg in EvidenceNeedService.get_sector_packages(tenant)

    @staticmethod
    def sync_for_session(session):
        tenant = session.tenant
        # F12: Konfigurierbare Schwellen aus Settings
        thresholds = getattr(settings, 'EVIDENCE_COVERAGE_THRESHOLDS', {'covered': 2, 'partial': 1})
        covered_threshold = thresholds.get('covered', 2)
        partial_threshold = thresholds.get('partial', 1)

        created = 0
        updated = 0
        for requirement in Requirement.objects.filter(is_active=True).order_by('framework', 'code'):
            if not EvidenceNeedService.requirement_relevant(requirement, tenant):
                continue
            evidence_qs = EvidenceItem.objects.filter(tenant=tenant, requirement=requirement)
            covered_count = evidence_qs.count()
            if covered_count >= covered_threshold:
                status = RequirementEvidenceNeed.Status.COVERED
            elif covered_count >= partial_threshold:
                status = RequirementEvidenceNeed.Status.PARTIAL
            else:
                status = RequirementEvidenceNeed.Status.OPEN
            defaults = {
                'title': f'Nachweis für {requirement.framework} {requirement.code}',
                'description': EvidenceNeedService.requirement_description(requirement),
                'is_mandatory': requirement.evidence_required,
                'status': status,
                'rationale': EvidenceNeedService.requirement_rationale(requirement),
                'covered_count': covered_count,
            }
            obj, was_created = RequirementEvidenceNeed.objects.update_or_create(
                tenant=tenant,
                session=session,
                requirement=requirement,
                defaults=defaults,
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated

    @staticmethod
    def related_needs_for_measure(measure, limit=4):
        qs = RequirementEvidenceNeed.objects.filter(tenant=measure.session.tenant)
        if measure.session_id:
            qs = qs.filter(session=measure.session)
        if measure.domain_id:
            domain_code = measure.domain.code.upper()
            keywords = EvidenceNeedService.DOMAIN_KEYWORDS.get(domain_code, [])
            filtered = []
            for need in qs.select_related('requirement'):
                haystack = ' '.join([
                    need.requirement.domain or '',
                    need.requirement.title or '',
                    need.requirement.description or '',
                    need.title or '',
                    need.description or '',
                ]).lower()
                if any(keyword.lower() in haystack for keyword in keywords):
                    filtered.append(need)
            if filtered:
                return filtered[:limit]
        return list(qs.select_related('requirement').order_by('status', 'requirement__framework', 'requirement__code')[:limit])

    @staticmethod
    def measure_need_summary(measure):
        needs = EvidenceNeedService.related_needs_for_measure(measure, limit=6)
        summary = {
            'open': 0,
            'partial': 0,
            'covered': 0,
            'total': len(needs),
            'items': needs,
        }
        for need in needs:
            if need.status == RequirementEvidenceNeed.Status.OPEN:
                summary['open'] += 1
            elif need.status == RequirementEvidenceNeed.Status.PARTIAL:
                summary['partial'] += 1
            elif need.status == RequirementEvidenceNeed.Status.COVERED:
                summary['covered'] += 1
        return summary

    @staticmethod
    def requirement_description(requirement):
        parts = [requirement.evidence_guidance or requirement.description]
        if requirement.mapping_version:
            parts.append(f'Mapping-Version: {requirement.mapping_version.program_name} {requirement.framework} v{requirement.mapping_version.version}')
        if requirement.primary_source:
            citation = requirement.primary_source.citation or requirement.primary_source.title
            parts.append(f'Quelle: {requirement.primary_source.authority} - {citation}')
        return ' | '.join(part for part in parts if part)

    @staticmethod
    def requirement_rationale(requirement):
        parts = [requirement.evidence_examples or 'Evidenzen, Richtlinien, Screenshots, Freigaben oder Prüfprotokolle hinterlegen.']
        if requirement.legal_reference:
            parts.append(f'Referenz: {requirement.legal_reference}')
        if requirement.primary_source and requirement.primary_source.url:
            parts.append(f'Quelle: {requirement.primary_source.url}')
        return ' | '.join(part for part in parts if part)
