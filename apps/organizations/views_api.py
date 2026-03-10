"""V20: JSON-Endpoint fuer Sektor- und Laenderdaten (fuer Live-Updates im Frontend)."""
import json
from django.http import JsonResponse
from django.views import View
from .sector_catalog import get_sector_definition, SECTOR_DEFINITIONS
from .country_catalog import get_country_labels, EU_EEA_CODES


class SectorContextApiView(View):
    """Gibt Sektorkontext als JSON zurueck. Wird vom Frontend beim Dropdown-Wechsel aufgerufen."""
    def get(self, request):
        code = request.GET.get('code', 'OTHER')
        sector = get_sector_definition(code)
        countries = request.GET.getlist('countries', [])
        country_labels = get_country_labels(countries)
        is_multi = len(countries) > 1
        has_non_eu = any(c not in EU_EEA_CODES for c in countries)

        return JsonResponse({
            'code': sector.code,
            'label': sector.label,
            'nis2_group': sector.nis2_group,
            'nis2_annex': sector.nis2_annex,
            'indicative_classification': sector.indicative_classification,
            'reasoning': sector.reasoning,
            'downstream_impact': sector.downstream_impact,
            'roadmap_focus': sector.roadmap_focus,
            'key_domains': sector.key_domains,
            'special_regime': sector.special_regime,
            'kritis_related': sector.kritis_related,
            'kritis_note': getattr(sector, 'kritis_note', ''),
            'score_bonus': sector.score_bonus,
            'countries_display': ', '.join(country_labels) if country_labels else '-',
            'is_multi_country': is_multi,
            'has_non_eu_eea': has_non_eu,
        })
