from apps.catalog.models import AssessmentQuestion

from .models import MappingVersion, Requirement, RequirementQuestionMapping


class RegulatoryMappingService:
    FRAMEWORKS_FOR_REPORT = (
        Requirement.Framework.ISO27001,
        Requirement.Framework.NIS2,
        Requirement.Framework.KRITIS,
        Requirement.Framework.CRA,
    )

    @staticmethod
    def get_active_versions(frameworks=None):
        queryset = MappingVersion.objects.filter(status=MappingVersion.Status.ACTIVE)
        if frameworks:
            queryset = queryset.filter(framework__in=frameworks)
        return queryset.order_by('framework', '-effective_on', '-created_at')

    @staticmethod
    def build_version_snapshot(frameworks=None):
        versions = {}
        for version in RegulatoryMappingService.get_active_versions(frameworks).prefetch_related('sources', 'requirements'):
            versions[version.framework] = {
                'framework': version.framework,
                'title': version.title,
                'version': version.version,
                'program_name': version.program_name,
                'effective_on': version.effective_on.isoformat() if version.effective_on else '',
                'source_count': version.sources.count(),
                'requirement_count': version.requirements.count(),
                'notes': version.notes,
            }
        return versions

    @staticmethod
    def calculate_framework_readiness(session, framework: str) -> int:
        question_ids = list(
            RequirementQuestionMapping.objects.filter(
                mapping_version__status=MappingVersion.Status.ACTIVE,
                requirement__framework=framework,
                question__question_kind=AssessmentQuestion.Kind.MATURITY,
            )
            .values_list('question_id', flat=True)
            .distinct()
        )
        if not question_ids:
            return 0

        answers = {
            answer.question_id: answer
            for answer in session.answers.filter(question_id__in=question_ids).select_related('selected_option')
        }
        total = 0
        score = 0
        for question_id in question_ids:
            answer = answers.get(question_id)
            if answer and answer.selected_option and answer.selected_option.is_na:
                continue
            total += 1
            score += answer.score if answer else 0

        return min(100, int((score / (total * 5)) * 100)) if total else 0
