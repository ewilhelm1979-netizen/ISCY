use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
};

use calamine::{Data, Reader, Xlsx};
use serde::Serialize;
use serde_json::Value;

pub const IMPORT_MAX_UPLOAD_BYTES: usize = 12 * 1024 * 1024;
pub const IMPORT_PREVIEW_MAX_ROWS: usize = 200;
const IMPORT_ALLOWED_EXTENSIONS: &[&str] = &["csv", "xlsx", "xlsm"];

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
const SUPPLIER_COLUMNS: &[&str] = &["name", "service_description", "criticality"];
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
    let mut workbook = Xlsx::new(Cursor::new(data.to_vec()))
        .map_err(|err| format!("XLSX-Datei konnte nicht gelesen werden: {err}"))?;
    let sheet_name = workbook
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| "XLSX-Datei enthaelt kein Tabellenblatt.".to_string())?;
    let range = workbook
        .worksheet_range(&sheet_name)
        .map_err(|err| format!("XLSX-Tabelle konnte nicht geoeffnet werden: {err}"))?;
    let mut iter = range.rows();
    let header_row = iter
        .next()
        .ok_or_else(|| "XLSX-Datei braucht eine Kopfzeile.".to_string())?;
    let header_indexes = xlsx_header_indexes(header_row)?;
    if header_indexes.is_empty() {
        return Err("XLSX-Datei braucht mindestens eine benannte Spalte.".to_string());
    }

    let mut rows = Vec::new();
    for row in iter {
        let mut mapped = HashMap::new();
        let mut saw_value = false;
        for (index, header) in &header_indexes {
            let value = row.get(*index).map(xlsx_cell_to_string).unwrap_or_default();
            if !value.is_empty() {
                saw_value = true;
            }
            mapped.insert(header.clone(), Value::String(value));
        }
        if saw_value {
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

fn xlsx_header_indexes(header_row: &[Data]) -> Result<Vec<(usize, String)>, String> {
    let mut indexes = Vec::new();
    let mut seen = HashSet::new();
    for (index, cell) in header_row.iter().enumerate() {
        let header = xlsx_cell_to_string(cell);
        let header = header.trim().trim_start_matches('\u{feff}').to_string();
        if header.is_empty() {
            continue;
        }
        let lowered = header.to_ascii_lowercase();
        if !seen.insert(lowered) {
            return Err(format!("XLSX-Spalte kommt mehrfach vor: {header}"));
        }
        indexes.push((index, header));
    }
    Ok(indexes)
}

fn xlsx_cell_to_string(cell: &Data) -> String {
    match cell {
        Data::Empty | Data::Error(_) => String::new(),
        Data::String(value) => value.trim().to_string(),
        Data::Int(value) => value.to_string(),
        Data::Float(value) => {
            if value.fract() == 0.0 {
                (*value as i64).to_string()
            } else {
                value.to_string()
            }
        }
        Data::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Data::DateTime(value) => value.to_string(),
        Data::DateTimeIso(value) => value.trim().to_string(),
        Data::DurationIso(value) => value.trim().to_string(),
    }
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
