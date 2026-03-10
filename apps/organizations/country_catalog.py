from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class CountryDefinition:
    code: str
    label: str
    is_eu_eea: bool = False
    is_primary_market_germany: bool = False


COUNTRY_DEFINITIONS: List[CountryDefinition] = [
    CountryDefinition('DE', 'Deutschland', is_eu_eea=True, is_primary_market_germany=True),
    CountryDefinition('AT', 'Österreich', is_eu_eea=True),
    CountryDefinition('BE', 'Belgien', is_eu_eea=True),
    CountryDefinition('BG', 'Bulgarien', is_eu_eea=True),
    CountryDefinition('HR', 'Kroatien', is_eu_eea=True),
    CountryDefinition('CY', 'Zypern', is_eu_eea=True),
    CountryDefinition('CZ', 'Tschechien', is_eu_eea=True),
    CountryDefinition('DK', 'Dänemark', is_eu_eea=True),
    CountryDefinition('EE', 'Estland', is_eu_eea=True),
    CountryDefinition('FI', 'Finnland', is_eu_eea=True),
    CountryDefinition('FR', 'Frankreich', is_eu_eea=True),
    CountryDefinition('GR', 'Griechenland', is_eu_eea=True),
    CountryDefinition('HU', 'Ungarn', is_eu_eea=True),
    CountryDefinition('IE', 'Irland', is_eu_eea=True),
    CountryDefinition('IT', 'Italien', is_eu_eea=True),
    CountryDefinition('LV', 'Lettland', is_eu_eea=True),
    CountryDefinition('LT', 'Litauen', is_eu_eea=True),
    CountryDefinition('LU', 'Luxemburg', is_eu_eea=True),
    CountryDefinition('MT', 'Malta', is_eu_eea=True),
    CountryDefinition('NL', 'Niederlande', is_eu_eea=True),
    CountryDefinition('NO', 'Norwegen', is_eu_eea=True),
    CountryDefinition('PL', 'Polen', is_eu_eea=True),
    CountryDefinition('PT', 'Portugal', is_eu_eea=True),
    CountryDefinition('RO', 'Rumänien', is_eu_eea=True),
    CountryDefinition('SK', 'Slowakei', is_eu_eea=True),
    CountryDefinition('SI', 'Slowenien', is_eu_eea=True),
    CountryDefinition('ES', 'Spanien', is_eu_eea=True),
    CountryDefinition('SE', 'Schweden', is_eu_eea=True),
    CountryDefinition('IS', 'Island', is_eu_eea=True),
    CountryDefinition('LI', 'Liechtenstein', is_eu_eea=True),
    CountryDefinition('CH', 'Schweiz'),
    CountryDefinition('GB', 'Vereinigtes Königreich'),
    CountryDefinition('US', 'Vereinigte Staaten'),
    CountryDefinition('CA', 'Kanada'),
    CountryDefinition('IN', 'Indien'),
    CountryDefinition('JP', 'Japan'),
    CountryDefinition('SG', 'Singapur'),
    CountryDefinition('AU', 'Australien'),
    CountryDefinition('AE', 'Vereinigte Arabische Emirate'),
    CountryDefinition('BR', 'Brasilien'),
]

COUNTRY_MAP: Dict[str, CountryDefinition] = {item.code: item for item in COUNTRY_DEFINITIONS}
COUNTRY_CHOICES: List[Tuple[str, str]] = [(item.code, item.label) for item in COUNTRY_DEFINITIONS]
EU_EEA_CODES = {item.code for item in COUNTRY_DEFINITIONS if item.is_eu_eea}


def get_country_definition(code: str | None) -> CountryDefinition:
    if not code:
        return COUNTRY_MAP['DE']
    return COUNTRY_MAP.get(code, CountryDefinition(code=code, label=code))


def get_country_labels(codes: List[str] | None) -> List[str]:
    if not codes:
        return []
    return [get_country_definition(code).label for code in codes]
