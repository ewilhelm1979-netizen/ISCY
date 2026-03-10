"""V20: Risk-Matrix-Service fuer 5x5 Heatmap."""
from collections import defaultdict


class RiskMatrixService:
    """Baut eine 5x5 Risikomatrix mit Faerbung und Risikozaehlung."""

    LEVEL_MAP = {
        (5, 5): 'critical', (5, 4): 'critical', (4, 5): 'critical',
        (5, 3): 'high', (4, 4): 'high', (3, 5): 'high', (4, 3): 'high', (3, 4): 'high',
        (5, 2): 'high', (2, 5): 'high',
        (5, 1): 'medium', (1, 5): 'medium', (4, 2): 'medium', (2, 4): 'medium',
        (3, 3): 'medium', (3, 2): 'medium', (2, 3): 'medium',
        (4, 1): 'medium', (1, 4): 'medium',
        (3, 1): 'low', (1, 3): 'low', (2, 2): 'low', (2, 1): 'low', (1, 2): 'low',
        (1, 1): 'low',
    }

    COLORS = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#f59e0b',
        'low': '#22c55e',
    }

    BG_COLORS = {
        'critical': '#fef2f2',
        'high': '#fff7ed',
        'medium': '#fffbeb',
        'low': '#f0fdf4',
    }

    @staticmethod
    def build_matrix(risks):
        """Baut die 5x5 Matrix aus einer QuerySet von Risks.
        Returns: list of rows (likelihood 5->1), each row = list of cells.
        """
        count_map = defaultdict(list)
        for risk in risks:
            count_map[(risk.impact, risk.likelihood)].append(risk)

        matrix = []
        for likelihood in range(5, 0, -1):
            row = []
            for impact in range(1, 6):
                level = RiskMatrixService.LEVEL_MAP.get((impact, likelihood), 'low')
                cell_risks = count_map.get((impact, likelihood), [])
                row.append({
                    'impact': impact,
                    'likelihood': likelihood,
                    'level': level,
                    'color': RiskMatrixService.COLORS[level],
                    'bg_color': RiskMatrixService.BG_COLORS[level],
                    'count': len(cell_risks),
                    'risks': cell_risks,
                    'score': impact * likelihood,
                })
            matrix.append({'likelihood': likelihood, 'cells': row})
        return matrix

    @staticmethod
    def summary(risks):
        """Zaehlt Risiken nach Level."""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for risk in risks:
            level = RiskMatrixService.LEVEL_MAP.get((risk.impact, risk.likelihood), 'low')
            summary[level] += 1
            summary['total'] += 1
        return summary
