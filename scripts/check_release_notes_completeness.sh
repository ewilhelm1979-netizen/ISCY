#!/usr/bin/env bash
set -euo pipefail

notes_path="${1:-}"
manifest_path="${ISCY_RELEASE_MANIFEST_PATH:-release/release-manifest.json}"

fail() {
    printf 'RC_NOTES_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}
require_phrase() {
    local category="$1"
    local phrase="$2"
    local message="$3"
    [[ "$notes_text" == *"$phrase"* ]] || fail "$category" "$message"
}
reject_phrase() {
    local category="$1"
    local phrase="$2"
    local message="$3"
    [[ "$notes_text" != *"$phrase"* ]] || fail "$category" "$message"
}

[[ -n "$notes_path" && -f "$notes_path" ]] \
    || fail file 'Das Release-Notes-Asset fehlt.'
[[ -f "$manifest_path" ]] || fail manifest 'Release-Manifest fehlt.'
command -v jq >/dev/null || fail prerequisite 'jq fehlt.'

release_status="$(jq -er '.release_status | select(type == "string")' "$manifest_path")" \
    || fail manifest 'Release-Status fehlt oder ist ungueltig.'
proposed_version="$(jq -er '.proposed_version | select(type == "string")' "$manifest_path")" \
    || fail manifest 'Zielversion fehlt oder ist ungueltig.'
notes_text="$(tr '\n\r\t' '   ' <"$notes_path" | tr -s ' ')"
backtick=$'\x60'

case "$release_status" in
    development_unreleased)
        require_phrase target_version "ISCY $proposed_version" \
            "Die Development-Zielversion $proposed_version fehlt."
        require_phrase release_status 'Status: Development / Unreleased.' \
            'Die eindeutige Development-/Unreleased-Kennzeichnung fehlt.'
        require_phrase predecessor "Basis: ${backtick}V23.7.33${backtick}" \
            'Die veroeffentlichte Basis V23.7.33 fehlt.'
        require_phrase unpublished 'Dieser Entwicklungsstand wurde noch nicht veroeffentlicht.' \
            'Die Abgrenzung zur Veroeffentlichung fehlt.'
        require_phrase no_tag 'noch keinen Tag' \
            'Die Abgrenzung zu einem Release-Tag fehlt.'
        require_phrase no_release 'noch kein GitHub Release' \
            'Die Abgrenzung zu einem GitHub Release fehlt.'
        require_phrase changelog 'unter Unreleased dokumentiert' \
            'Die Unreleased-Dokumentationsregel fehlt.'

        reject_phrase stable_published 'Stable Release veroeffentlicht' \
            'Development Notes duerfen keinen Stable Release behaupten.'
        reject_phrase released 'Release freigegeben' \
            'Development Notes duerfen keine Release-Freigabe behaupten.'
        reject_phrase candidate_ready 'Release Candidate bereit' \
            'Development Notes duerfen keinen fertigen Release Candidate behaupten.'
        reject_phrase stable_prepared 'Stabiler Release vorbereitet' \
            'Development Notes duerfen kein vorbereitetes Stable Release behaupten.'
        reject_phrase latest 'als Latest Release veroeffentlicht' \
            'Development Notes duerfen keinen Latest-Status behaupten.'

        printf 'DEV_NOTES_OK: %s ist eindeutig als unveroeffentlichter Development-Stand dokumentiert.\n' \
            "$proposed_version"
        ;;
    prepared_not_published)
        require_phrase target_version "ISCY $proposed_version" \
            "Die Zielversion $proposed_version fehlt."
        require_phrase release_status 'Status: Stabiler Release.' \
            'Der publikationsneutrale Stable-Release-Status fehlt.'
        require_phrase predecessor "Vorgänger: ${backtick}V23.7.33${backtick}" \
            'Der veroeffentlichte Vorgaenger V23.7.33 fehlt.'
        require_phrase nginx 'nginx:1.31-alpine' \
            'Die nginx-1.31-Maintenance fehlt.'
        require_phrase rust_toolchain "Rust ${backtick}1.97.0${backtick}" \
            'Die Rust-1.97-Produkttoolchain fehlt.'
        require_phrase msrv "MSRV bleibt Rust ${backtick}1.88.0${backtick}" \
            'Die unveraenderte MSRV 1.88 fehlt.'
        require_phrase nixpkgs 'nixos-26.05' \
            'Der nixpkgs-26.05-Stand fehlt.'
        require_phrase postgresql_18 'PostgreSQL 18.4' \
            'Der PostgreSQL-18.4-Kompatibilitaetsnachweis fehlt.'
        require_phrase postgresql_standard 'PostgreSQL 16 bleibt der Standard' \
            'PostgreSQL 16 ist nicht eindeutig als Standard dokumentiert.'
        require_phrase nis2_wizard 'NIS2-Relevanz-Wizard' \
            'Der dokumentierte NIS2-Relevanz-Wizard fehlt.'
        require_phrase applicability 'Applicability-Begruendung' \
            'Die nachvollziehbare Applicability-Begruendung fehlt.'
        require_phrase nis2_kritis 'NIS2- und KRITIS-Kontext' \
            'Die gemeinsame NIS2-/KRITIS-Einordnung fehlt.'
        require_phrase legal_boundary 'keine rechtsverbindliche Einstufung' \
            'Die rechtliche Abgrenzung der Relevanzbewertung fehlt.'
        require_phrase dora_boundary 'DORA-Konformitaetsbewertung erfolgt nicht' \
            'Die DORA-Unterstuetzung oder ihre fachliche Abgrenzung fehlt.'
        require_phrase cra_name 'Cyber Resilience Act (CRA)' \
            'Die ausgeschriebene CRA-Bezeichnung fehlt.'
        require_phrase cra_boundary 'keine automatische Konformitaetsbewertung oder CE-Freigabe' \
            'Die CRA-Unterstuetzung oder ihre Konformitaetsabgrenzung fehlt.'
        require_phrase certification_boundary 'keine automatische Zertifizierung' \
            'Die Zertifizierungsabgrenzung fehlt.'
        require_phrase legal_advice_boundary 'Rechtsberatung' \
            'Die Rechtsberatungsabgrenzung fehlt.'

        reject_phrase development_status 'Status: Development / Unreleased.' \
            'Candidate Notes duerfen keinen Development-Status enthalten.'
        reject_phrase development_placeholder 'unter Unreleased dokumentiert' \
            'Candidate Notes duerfen keinen Development-Platzhalter enthalten.'
        reject_phrase creation_pending 'Tag und GitHub Release noch nicht erstellt' \
            'Stable Release Notes duerfen keinen ausstehenden Erstellungszustand behaupten.'
        reject_phrase tag_pending 'Tag noch nicht erstellt' \
            'Stable Release Notes duerfen keinen ausstehenden Tag behaupten.'
        reject_phrase github_release_pending 'GitHub Release noch nicht erstellt' \
            'Stable Release Notes duerfen keinen ausstehenden GitHub Release behaupten.'
        reject_phrase unpublished 'noch nicht veroeffentlicht' \
            'Stable Release Notes duerfen keinen ausstehenden Veroeffentlichungszustand behaupten.'
        reject_phrase publication_pending 'Veroeffentlichung steht aus' \
            'Stable Release Notes duerfen keine ausstehende Veroeffentlichung behaupten.'
        reject_phrase publication_outstanding 'Veroeffentlichung ausstehend' \
            'Stable Release Notes duerfen keine ausstehende Veroeffentlichung behaupten.'
        reject_phrase draft_release 'Draft Release' \
            'Stable Release Notes duerfen keinen Draft-Release-Status behaupten.'
        reject_phrase prerelease 'Prerelease' \
            'Stable Release Notes duerfen keinen GitHub-Prerelease-Status behaupten.'
        reject_phrase already_published 'bereits veroeffentlicht' \
            'Stable Release Notes duerfen eine Veroeffentlichung nicht vorwegnehmen.'
        reject_phrase publication_success 'erfolgreich veroeffentlicht' \
            'Stable Release Notes duerfen eine erfolgreiche Veroeffentlichung nicht behaupten.'
        reject_phrase latest_release 'Latest Release veroeffentlicht' \
            'Stable Release Notes duerfen keinen Latest-Status behaupten.'
        reject_phrase asset_upload_success 'Asset-Upload erfolgreich' \
            'Stable Release Notes duerfen keinen erfolgreichen Asset-Upload behaupten.'

        printf 'RC_NOTES_OK: %s, Platform-Maintenance, PostgreSQL, Governance und rechtliche Grenzen sind konsistent.\n' \
            "$proposed_version"
        ;;
    *)
        fail manifest 'Nicht unterstuetzter Release-Status fuer Release Notes.'
        ;;
esac
