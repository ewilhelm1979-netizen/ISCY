use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    let input = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("docs/ISCY_Handbuch.md");
    let output = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("docs/ISCY_Handbuch.pdf");

    let markdown = fs::read_to_string(input)?;
    let lines = markdown_to_pdf_lines(&markdown, 94);
    let pdf = pdf_document(&lines, 72);
    if let Some(parent) = Path::new(output).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output, pdf)?;
    println!("Handbuch-PDF geschrieben: {output}");
    Ok(())
}

fn markdown_to_pdf_lines(markdown: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_code = false;
    for raw in markdown.lines() {
        let line = raw.trim_end();
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        let normalized = if in_code {
            line.to_string()
        } else {
            normalize_markdown_line(line)
        };
        if normalized.trim().is_empty() {
            lines.push(String::new());
            continue;
        }
        lines.extend(wrap_text(&normalized, width));
    }
    lines
}

fn normalize_markdown_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.starts_with("# ") {
        return trimmed.trim_start_matches("# ").to_ascii_uppercase();
    }
    if trimmed.starts_with("## ") {
        return format!("{}:", trimmed.trim_start_matches("## "));
    }
    if trimmed.starts_with("### ") {
        return format!("{}:", trimmed.trim_start_matches("### "));
    }
    if trimmed.starts_with("- ") {
        return format!(
            "- {}",
            strip_inline_markdown(trimmed.trim_start_matches("- "))
        );
    }
    if trimmed.starts_with("|") {
        return strip_inline_markdown(&trimmed.replace('|', " | "));
    }
    strip_inline_markdown(trimmed)
}

fn strip_inline_markdown(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '`' | '*' | '_' => {}
            '[' => {
                let mut label = String::new();
                for next in chars.by_ref() {
                    if next == ']' {
                        break;
                    }
                    label.push(next);
                }
                if matches!(chars.peek(), Some('(')) {
                    for next in chars.by_ref() {
                        if next == ')' {
                            break;
                        }
                    }
                }
                output.push_str(&label);
            }
            ch if ch.is_control() && ch != '\t' => {}
            ch if ch.is_ascii() => output.push(ch),
            'ä' => output.push_str("ae"),
            'ö' => output.push_str("oe"),
            'ü' => output.push_str("ue"),
            'Ä' => output.push_str("Ae"),
            'Ö' => output.push_str("Oe"),
            'Ü' => output.push_str("Ue"),
            'ß' => output.push_str("ss"),
            _ => output.push('?'),
        }
    }
    output
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in value.split_whitespace() {
        if current.len() + word.len() + usize::from(!current.is_empty()) > width
            && !current.is_empty()
        {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

fn pdf_document(lines: &[String], lines_per_page: usize) -> Vec<u8> {
    let page_count = (lines.len().max(1) + lines_per_page - 1) / lines_per_page;
    let object_count = 3 + (page_count * 2);
    let mut objects = vec![String::new(); object_count];
    let page_ids = (0..page_count)
        .map(|index| 4 + index * 2)
        .collect::<Vec<_>>();
    let kids = page_ids
        .iter()
        .map(|id| format!("{id} 0 R"))
        .collect::<Vec<_>>()
        .join(" ");

    objects[0] = "<< /Type /Catalog /Pages 2 0 R >>".to_string();
    objects[1] = format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>");
    objects[2] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string();

    for page_index in 0..page_count {
        let page_id = 4 + page_index * 2;
        let content_id = page_id + 1;
        let start = page_index * lines_per_page;
        let end = (start + lines_per_page).min(lines.len());
        let content = page_content(&lines[start..end]);
        objects[page_id - 1] = format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        );
        objects[content_id - 1] = format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.len(),
            content
        );
    }

    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", index + 1, object));
    }
    let xref_start = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    pdf.push_str("0000000000 65535 f\n");
    for offset in offsets {
        pdf.push_str(&format!("{offset:010} 00000 n\n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref_start
    ));
    pdf.into_bytes()
}

fn page_content(lines: &[String]) -> String {
    let mut content = String::from("BT\n/F1 9 Tf\n42 800 Td\n10 TL\n");
    for line in lines {
        content.push_str(&format!("({}) Tj\nT*\n", pdf_escape(line)));
    }
    content.push_str("ET\n");
    content
}

fn pdf_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}
