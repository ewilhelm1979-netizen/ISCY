use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{BufReader, Cursor, Read},
};

use calamine::{DataRef, Reader, Xlsx};
use quick_xml::{events::Event, Reader as XmlReader};
use serde::Serialize;
use serde_json::Value;
use zip::ZipArchive;

pub const IMPORT_MAX_UPLOAD_BYTES: usize = 12 * 1024 * 1024;
pub const IMPORT_PREVIEW_MAX_ROWS: usize = 200;
const IMPORT_ALLOWED_EXTENSIONS: &[&str] = &["csv", "xlsx", "xlsm"];
const XLSX_MAX_ARCHIVE_ENTRIES: usize = 512;
const XLSX_MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const XLSX_MAX_ENTRY_UNCOMPRESSED_BYTES: u64 = 32 * 1024 * 1024;
const XLSX_MAX_SHARED_STRINGS: usize = 250_000;
const XLSX_MAX_USED_CELLS: usize = 1_000_000;
const XLSX_MAX_IMPORT_ROWS: usize = 50_000;

const BUSINESS_UNIT_COLUMNS: &[&str] = &["name", "owner_email"];
const PROCESS_COLUMNS: &[&str] = &[
    "name",
    "scope",
    "description",
    "status",
    "business_unit",
    "documented",
    "implemented",
    "evidenced",
    "approved",
    "communicated",
    "effective",
];
const SUPPLIER_COLUMNS: &[&str] = &[
    "name",
    "service_description",
    "criticality",
    "contact_email",
    "contract_reference",
    "data_categories",
    "regions",
    "exit_dependency",
    "regulatory_scope",
    "review_status",
    "last_reviewed_at",
    "next_review_due_at",
    "evidence_required",
    "notes",
];
const ASSET_COLUMNS: &[&str] = &[
    "name",
    "asset_type",
    "criticality",
    "description",
    "business_unit",
    "confidentiality",
    "integrity",
    "availability",
    "lifecycle_status",
    "in_scope",
];

pub type ImportRows = Vec<HashMap<String, Value>>;

#[derive(Debug, Clone)]
pub struct ImportUploadFile {
    pub filename: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportMappingRow {
    pub expected: String,
    pub matched: String,
    pub status: String,
    pub synonyms: Vec<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportPreview {
    pub import_type: String,
    pub replace_existing: bool,
    pub file_name: String,
    pub file_kind: String,
    pub headers: Vec<String>,
    pub preview_rows: Vec<HashMap<String, String>>,
    pub mapping_rows: Vec<ImportMappingRow>,
    pub selected_mapping: HashMap<String, String>,
    pub extra_headers: Vec<String>,
    pub matched: usize,
    pub preview_row_count: usize,
    pub total_row_count: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct BuiltImportPreview {
    pub preview: ImportPreview,
    pub rows: ImportRows,
}

pub fn build_import_preview(
    file: &ImportUploadFile,
    import_type: &str,
    replace_existing: bool,
    selected_mapping: Option<HashMap<String, String>>,
) -> Result<BuiltImportPreview, String> {
    validate_import_upload_file(file)?;
    let normalized_import_type = normalize_import_type(import_type)?;
    let (headers, rows, file_kind) = parse_import_file(file)?;
    let selected_mapping =
        normalized_selected_mapping(normalized_import_type, &headers, selected_mapping);
    let (mapping_rows, extra_headers) =
        get_mapping_preview(normalized_import_type, &headers, &selected_mapping)?;
    let preview_rows = rows
        .iter()
        .take(IMPORT_PREVIEW_MAX_ROWS)
        .map(|row| {
            headers
                .iter()
                .map(|header| {
                    (
                        header.clone(),
                        row.get(header)
                            .map(value_to_preview_string)
                            .unwrap_or_default(),
                    )
                })
                .collect::<HashMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let matched = mapping_rows
        .iter()
        .filter(|row| row.status.eq_ignore_ascii_case("ok"))
        .count();
    let preview = ImportPreview {
        import_type: normalized_import_type.to_string(),
        replace_existing,
        file_name: file.filename.clone(),
        file_kind: file_kind.to_string(),
        headers,
        preview_rows,
        mapping_rows,
        selected_mapping,
        extra_headers,
        matched,
        preview_row_count: rows.len().min(IMPORT_PREVIEW_MAX_ROWS),
        total_row_count: rows.len(),
        truncated: rows.len() > IMPORT_PREVIEW_MAX_ROWS,
    };
    Ok(BuiltImportPreview { preview, rows })
}

pub fn selected_mapping_from_fields(
    import_type: &str,
    fields: &HashMap<String, String>,
) -> Result<Option<HashMap<String, String>>, String> {
    let expected = expected_columns(import_type)?;
    let has_mapping = expected
        .iter()
        .any(|expected| fields.contains_key(&mapping_field_name(expected)));
    if !has_mapping {
        return Ok(None);
    }
    Ok(Some(
        expected
            .iter()
            .map(|expected| {
                let value = fields
                    .get(&mapping_field_name(expected))
                    .map(String::as_str)
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_string();
                ((*expected).to_string(), value)
            })
            .collect(),
    ))
}

pub fn apply_mapping(
    rows: &[HashMap<String, Value>],
    import_type: &str,
    selected_mapping: &HashMap<String, String>,
) -> Result<ImportRows, String> {
    let expected = expected_columns(import_type)?;
    Ok(rows
        .iter()
        .map(|row| {
            expected
                .iter()
                .map(|expected| {
                    let value = selected_mapping
                        .get(*expected)
                        .map(String::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .and_then(|source| row.get(source))
                        .cloned()
                        .unwrap_or(Value::Null);
                    ((*expected).to_string(), value)
                })
                .collect::<HashMap<_, _>>()
        })
        .collect())
}

pub fn expected_columns(import_type: &str) -> Result<&'static [&'static str], String> {
    match normalize_import_type(import_type)? {
        "business_units" => Ok(BUSINESS_UNIT_COLUMNS),
        "processes" => Ok(PROCESS_COLUMNS),
        "suppliers" => Ok(SUPPLIER_COLUMNS),
        "assets" => Ok(ASSET_COLUMNS),
        _ => unreachable!("normalize_import_type guards allowed import types"),
    }
}

pub fn supports_required_name_mapping(selected_mapping: &HashMap<String, String>) -> bool {
    selected_mapping
        .get("name")
        .map(String::as_str)
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn parse_import_file(
    file: &ImportUploadFile,
) -> Result<(Vec<String>, ImportRows, &'static str), String> {
    match crate::file_extension(&file.filename).as_deref() {
        Some("csv") => {
            let raw = String::from_utf8(file.data.clone())
                .map_err(|_| "CSV-Datei muss UTF-8-kodiert sein.".to_string())?;
            let (headers, rows) = crate::parse_import_csv(&raw)?;
            Ok((headers, rows, "csv"))
        }
        Some("xlsx") | Some("xlsm") => {
            let (headers, rows) = parse_xlsx_file(&file.data)?;
            Ok((headers, rows, "xlsx"))
        }
        Some(extension) => Err(format!(
            "Dateityp \".{extension}\" ist fuer Imports nicht erlaubt. Erlaubt: .csv, .xlsx, .xlsm"
        )),
        None => Err("Import-Datei braucht eine erlaubte Endung: csv, xlsx oder xlsm.".to_string()),
    }
}

fn parse_xlsx_file(data: &[u8]) -> Result<(Vec<String>, ImportRows), String> {
    validate_xlsx_archive(data)?;
    let mut workbook = Xlsx::new(Cursor::new(data.to_vec()))
        .map_err(|err| format!("XLSX-Datei konnte nicht gelesen werden: {err}"))?;
    let sheet_name = workbook
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| "XLSX-Datei enthaelt kein Tabellenblatt.".to_string())?;
    let mut reader = workbook
        .worksheet_cells_reader(&sheet_name)
        .map_err(|err| format!("XLSX-Tabelle konnte nicht geoeffnet werden: {err}"))?;
    let mut sparse_rows = BTreeMap::<u32, BTreeMap<u32, String>>::new();
    let mut used_cells = 0_usize;

    while let Some(cell) = reader
        .next_cell()
        .map_err(|err| format!("XLSX-Tabelle konnte nicht sicher gelesen werden: {err}"))?
    {
        used_cells = used_cells
            .checked_add(1)
            .ok_or_else(|| "XLSX-Datei enthaelt zu viele verwendete Zellen.".to_string())?;
        if used_cells > XLSX_MAX_USED_CELLS {
            return Err("XLSX-Datei enthaelt zu viele verwendete Zellen.".to_string());
        }
        let value = xlsx_cell_to_string(cell.get_value());
        if value.is_empty() {
            continue;
        }
        let (row, column) = cell.get_position();
        sparse_rows.entry(row).or_default().insert(column, value);
        if sparse_rows.len() > XLSX_MAX_IMPORT_ROWS + 1 {
            return Err("XLSX-Datei enthaelt zu viele Importzeilen.".to_string());
        }
    }

    xlsx_rows_from_sparse(sparse_rows)
}

fn xlsx_rows_from_sparse(
    mut sparse_rows: BTreeMap<u32, BTreeMap<u32, String>>,
) -> Result<(Vec<String>, ImportRows), String> {
    let Some((_header_row, header_row)) = sparse_rows.pop_first() else {
        return Err("XLSX-Datei braucht eine Kopfzeile.".to_string());
    };
    let header_indexes = xlsx_header_indexes(&header_row)?;
    if header_indexes.is_empty() {
        return Err("XLSX-Datei braucht mindestens eine benannte Spalte.".to_string());
    }

    let mut rows = Vec::new();
    for row in sparse_rows.into_values() {
        let mut mapped = HashMap::new();
        let mut saw_value = false;
        for (column, header) in &header_indexes {
            let value = row.get(column).cloned().unwrap_or_default();
            if !value.is_empty() {
                saw_value = true;
            }
            mapped.insert(header.clone(), Value::String(value));
        }
        if saw_value {
            if rows.len() >= XLSX_MAX_IMPORT_ROWS {
                return Err("XLSX-Datei enthaelt zu viele Importzeilen.".to_string());
            }
            rows.push(mapped);
        }
    }

    Ok((
        header_indexes
            .iter()
            .map(|(_, header)| header.clone())
            .collect(),
        rows,
    ))
}

fn xlsx_header_indexes(header_row: &BTreeMap<u32, String>) -> Result<Vec<(u32, String)>, String> {
    let mut indexes = Vec::new();
    let mut seen = HashSet::new();
    for (column, value) in header_row {
        let header = value.trim().trim_start_matches('\u{feff}').to_string();
        if header.is_empty() {
            continue;
        }
        let lowered = header.to_ascii_lowercase();
        if !seen.insert(lowered) {
            return Err(format!("XLSX-Spalte kommt mehrfach vor: {header}"));
        }
        indexes.push((*column, header));
    }
    Ok(indexes)
}

fn xlsx_cell_to_string(cell: &DataRef<'_>) -> String {
    match cell {
        DataRef::Empty | DataRef::Error(_) => String::new(),
        DataRef::String(value) => value.trim().to_string(),
        DataRef::SharedString(value) => value.trim().to_string(),
        DataRef::Int(value) => value.to_string(),
        DataRef::Float(value) => {
            if value.fract() == 0.0 {
                (*value as i64).to_string()
            } else {
                value.to_string()
            }
        }
        DataRef::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        DataRef::DateTime(value) => value.to_string(),
        DataRef::DateTimeIso(value) => value.trim().to_string(),
        DataRef::DurationIso(value) => value.trim().to_string(),
    }
}

fn validate_xlsx_archive(data: &[u8]) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(data))
        .map_err(|_| "XLSX-Datei enthaelt kein gueltiges Office-Archiv.".to_string())?;
    if archive.len() > XLSX_MAX_ARCHIVE_ENTRIES {
        return Err("XLSX-Datei enthaelt zu viele Archiv-Eintraege.".to_string());
    }

    let mut total_uncompressed = 0_u64;
    let mut shared_strings_index = None;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| "XLSX-Archiv konnte nicht sicher gelesen werden.".to_string())?;
        if !file.is_file() {
            continue;
        }
        if file.size() > XLSX_MAX_ENTRY_UNCOMPRESSED_BYTES {
            return Err("XLSX-Datei ueberschreitet das sichere Entpack-Limit.".to_string());
        }
        total_uncompressed = total_uncompressed
            .checked_add(file.size())
            .ok_or_else(|| "XLSX-Datei ueberschreitet das sichere Entpack-Limit.".to_string())?;
        if total_uncompressed > XLSX_MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err("XLSX-Datei ueberschreitet das sichere Entpack-Limit.".to_string());
        }
        let normalized_name = file.name().replace('\\', "/").to_ascii_lowercase();
        if normalized_name == "sharedstrings.xml" || normalized_name.ends_with("/sharedstrings.xml")
        {
            shared_strings_index = Some(index);
        }
    }

    if let Some(index) = shared_strings_index {
        let file = archive
            .by_index(index)
            .map_err(|_| "XLSX-Shared-Strings konnten nicht sicher gelesen werden.".to_string())?;
        validate_shared_strings_xml(file, XLSX_MAX_SHARED_STRINGS, XLSX_MAX_USED_CELLS)?;
    }
    Ok(())
}

fn validate_shared_strings_xml<R: Read>(
    reader: R,
    max_unique_strings: usize,
    max_references: usize,
) -> Result<(), String> {
    let bounded = reader.take(XLSX_MAX_ENTRY_UNCOMPRESSED_BYTES + 1);
    let mut xml = XmlReader::from_reader(BufReader::new(bounded));
    let mut buffer = Vec::with_capacity(4096);
    let mut saw_root = false;
    let mut actual_unique_strings = 0_usize;

    loop {
        buffer.clear();
        match xml.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                let local_name = element.local_name();
                if local_name.as_ref() == b"sst" && !saw_root {
                    saw_root = true;
                    validate_shared_string_root_attributes(
                        &element,
                        max_unique_strings,
                        max_references,
                    )?;
                } else if local_name.as_ref() == b"si" {
                    actual_unique_strings =
                        actual_unique_strings.checked_add(1).ok_or_else(|| {
                            "XLSX-Shared-Strings ueberschreiten das sichere Import-Limit."
                                .to_string()
                        })?;
                    if actual_unique_strings > max_unique_strings {
                        return Err(
                            "XLSX-Shared-Strings ueberschreiten das sichere Import-Limit."
                                .to_string(),
                        );
                    }
                }
            }
            Ok(Event::Empty(element)) => {
                let local_name = element.local_name();
                if local_name.as_ref() == b"sst" && !saw_root {
                    saw_root = true;
                    validate_shared_string_root_attributes(
                        &element,
                        max_unique_strings,
                        max_references,
                    )?;
                } else if local_name.as_ref() == b"si" {
                    actual_unique_strings =
                        actual_unique_strings.checked_add(1).ok_or_else(|| {
                            "XLSX-Shared-Strings ueberschreiten das sichere Import-Limit."
                                .to_string()
                        })?;
                    if actual_unique_strings > max_unique_strings {
                        return Err(
                            "XLSX-Shared-Strings ueberschreiten das sichere Import-Limit."
                                .to_string(),
                        );
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => {
                return Err("XLSX-Shared-Strings sind nicht gueltig.".to_string());
            }
        }
    }

    if !saw_root {
        return Err("XLSX-Shared-Strings sind nicht gueltig.".to_string());
    }
    Ok(())
}

fn validate_shared_string_root_attributes(
    element: &quick_xml::events::BytesStart<'_>,
    max_unique_strings: usize,
    max_references: usize,
) -> Result<(), String> {
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|_| "XLSX-Shared-Strings sind nicht gueltig.".to_string())?;
        let local_name = attribute.key.local_name();
        let limit = if local_name.as_ref() == b"uniqueCount" {
            Some(max_unique_strings)
        } else if local_name.as_ref() == b"count" {
            Some(max_references)
        } else {
            None
        };
        let Some(limit) = limit else {
            continue;
        };
        let raw = std::str::from_utf8(attribute.value.as_ref())
            .map_err(|_| "XLSX-Shared-Strings sind nicht gueltig.".to_string())?;
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("XLSX-Shared-Strings sind nicht gueltig.".to_string());
        }
        let declared = raw
            .parse::<u64>()
            .map_err(|_| "XLSX-Shared-Strings sind nicht gueltig.".to_string())?;
        if declared > limit as u64 {
            return Err("XLSX-Shared-Strings ueberschreiten das sichere Import-Limit.".to_string());
        }
    }
    Ok(())
}

fn get_mapping_preview(
    import_type: &str,
    headers: &[String],
    selected_mapping: &HashMap<String, String>,
) -> Result<(Vec<ImportMappingRow>, Vec<String>), String> {
    let expected = expected_columns(import_type)?;
    let selected_values = selected_mapping
        .values()
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let extra_headers = headers
        .iter()
        .filter(|header| !selected_values.contains(&header.to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();
    let rows = expected
        .iter()
        .map(|expected| {
            let matched = selected_mapping.get(*expected).cloned().unwrap_or_default();
            ImportMappingRow {
                expected: (*expected).to_string(),
                matched: matched.clone(),
                status: if matched.trim().is_empty() {
                    "missing".to_string()
                } else {
                    "ok".to_string()
                },
                synonyms: column_synonyms(expected)
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                required: *expected == "name",
            }
        })
        .collect::<Vec<_>>();
    Ok((rows, extra_headers))
}

fn normalized_selected_mapping(
    import_type: &str,
    headers: &[String],
    selected_mapping: Option<HashMap<String, String>>,
) -> HashMap<String, String> {
    let default_mapping = default_mapping(import_type, headers).unwrap_or_else(|_| HashMap::new());
    let Some(selected_mapping) = selected_mapping else {
        return default_mapping;
    };
    default_mapping
        .into_iter()
        .map(|(expected, default_value)| {
            let value = selected_mapping
                .get(&expected)
                .cloned()
                .map(|value| value.trim().to_string())
                .unwrap_or(default_value);
            (expected, value)
        })
        .collect()
}

fn default_mapping(
    import_type: &str,
    headers: &[String],
) -> Result<HashMap<String, String>, String> {
    let expected = expected_columns(import_type)?;
    let normalized = headers
        .iter()
        .map(|header| (header.trim().to_ascii_lowercase(), header.clone()))
        .collect::<HashMap<_, _>>();
    Ok(expected
        .iter()
        .map(|expected| {
            let matched = normalized
                .get(&expected.to_ascii_lowercase())
                .cloned()
                .or_else(|| {
                    column_synonyms(expected)
                        .iter()
                        .find_map(|synonym| normalized.get(&synonym.to_ascii_lowercase()).cloned())
                })
                .unwrap_or_default();
            ((*expected).to_string(), matched)
        })
        .collect())
}

fn normalize_import_type(import_type: &str) -> Result<&'static str, String> {
    let normalized = import_type.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "business_units" => Ok("business_units"),
        "processes" => Ok("processes"),
        "suppliers" => Ok("suppliers"),
        "assets" => Ok("assets"),
        _ => Err(format!(
            "Importtyp ist nicht unterstuetzt: {}",
            import_type.trim()
        )),
    }
}

fn column_synonyms(column: &str) -> &'static [&'static str] {
    match column {
        "name" => &["Name"],
        "owner_email" => &["OwnerEmail", "Verantwortlicher"],
        "scope" => &["Scope"],
        "description" => &["Beschreibung", "Service"],
        "status" => &["Status"],
        "business_unit" => &["BusinessUnit", "Geschaeftsbereich"],
        "documented" => &["Dokumentiert"],
        "implemented" => &["Umgesetzt"],
        "evidenced" => &["Nachweisbar"],
        "approved" => &["Genehmigt"],
        "communicated" => &["Kommuniziert"],
        "effective" => &["Wirksam"],
        "service_description" => &["Beschreibung", "Service"],
        "criticality" => &["Kritikalitaet"],
        "asset_type" => &["Typ"],
        "confidentiality" => &["Vertraulichkeit"],
        "integrity" => &["Integritaet"],
        "availability" => &["Verfuegbarkeit"],
        "lifecycle_status" => &["Lifecycle"],
        "in_scope" => &["ImScope"],
        _ => &[],
    }
}

fn mapping_field_name(expected: &str) -> String {
    format!("map_{expected}")
}

fn validate_import_upload_file(file: &ImportUploadFile) -> Result<(), String> {
    if file.data.is_empty() {
        return Err("Import-Datei ist leer.".to_string());
    }
    if file.data.len() > IMPORT_MAX_UPLOAD_BYTES {
        return Err(format!(
            "Import-Datei ist zu gross ({:.1} MB). Maximum: 12 MB.",
            file.data.len() as f64 / 1024.0 / 1024.0
        ));
    }
    let extension = crate::file_extension(&file.filename).ok_or_else(|| {
        "Import-Datei braucht eine erlaubte Endung: csv, xlsx oder xlsm.".to_string()
    })?;
    if !IMPORT_ALLOWED_EXTENSIONS
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    {
        return Err(format!(
            "Dateityp \".{extension}\" ist fuer Imports nicht erlaubt. Erlaubt: .csv, .xlsx, .xlsm"
        ));
    }
    Ok(())
}

fn value_to_preview_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_string_preflight_rejects_unbounded_declared_capacity() {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="{}"><si><t>Name</t></si></sst>"#,
            XLSX_MAX_SHARED_STRINGS + 1
        );
        let error = validate_shared_strings_xml(
            Cursor::new(xml.into_bytes()),
            XLSX_MAX_SHARED_STRINGS,
            XLSX_MAX_USED_CELLS,
        )
        .unwrap_err();
        assert!(error.contains("sichere Import-Limit"));
    }

    #[test]
    fn shared_string_preflight_counts_elements_when_metadata_understates_them() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3" uniqueCount="1"><si><t>A</t></si><si><t>B</t></si><si><t>C</t></si></sst>"#;
        let error = validate_shared_strings_xml(Cursor::new(xml), 2, 10).unwrap_err();
        assert!(error.contains("sichere Import-Limit"));
    }

    #[test]
    fn sparse_xlsx_rows_do_not_expand_the_coordinate_rectangle() {
        let mut rows = BTreeMap::new();
        rows.insert(
            0,
            BTreeMap::from([(0, "name".to_string()), (16_383, "description".to_string())]),
        );
        rows.insert(
            1_048_575,
            BTreeMap::from([
                (0, "endpoint".to_string()),
                (16_383, "far but sparse".to_string()),
            ]),
        );

        let (headers, imported) = xlsx_rows_from_sparse(rows).unwrap();
        assert_eq!(headers, vec!["name", "description"]);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0]["name"], "endpoint");
        assert_eq!(imported[0]["description"], "far but sparse");
    }

    #[test]
    fn ordinary_shared_strings_remain_supported() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2"><si><t>Name</t></si><si><t>Beschreibung</t></si></sst>"#;
        validate_shared_strings_xml(Cursor::new(xml), 2, 2).unwrap();
    }
}
