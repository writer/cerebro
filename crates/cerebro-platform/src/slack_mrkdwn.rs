const SLACK_HORIZONTAL_RULE: &str = "────────────────────────";

/// Render the Markdown subset emitted by the Rust agent as Slack mrkdwn.
///
/// Unknown syntax is preserved verbatim. Model-authored Slack control tokens
/// remain readable but inert so rendering cannot create a notification side
/// effect.
pub(super) fn render_slack_mrkdwn(markdown: &str) -> String {
    let lines = markdown.split('\n').collect::<Vec<_>>();
    let mut rendered = Vec::with_capacity(lines.len());
    let mut index = 0;
    let mut in_code_block = false;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            rendered.push(line.to_owned());
            index += 1;
            continue;
        }
        if in_code_block {
            rendered.push(line.to_owned());
            index += 1;
            continue;
        }

        if index + 1 < lines.len()
            && let (Some(header), Some(separator)) = (
                markdown_table_cells(trimmed),
                markdown_table_cells(lines[index + 1].trim()),
            )
            && is_markdown_table_separator(&separator)
        {
            rendered.push(render_table_row(&header, true));
            index += 2;
            while index < lines.len() {
                let Some(row) = markdown_table_cells(lines[index].trim()) else {
                    break;
                };
                rendered.push(render_table_row(&row, false));
                index += 1;
            }
            continue;
        }

        let normalized = if let Some(heading) = markdown_heading(trimmed) {
            format!("*{}*", render_inline_slack_mrkdwn(heading))
        } else if is_markdown_horizontal_rule(trimmed) {
            SLACK_HORIZONTAL_RULE.to_owned()
        } else if let Some((indent, item)) = markdown_bullet(line) {
            format!("{indent}• {}", render_inline_slack_mrkdwn(item))
        } else {
            render_inline_slack_mrkdwn(line)
        };
        rendered.push(normalized);
        index += 1;
    }
    if in_code_block {
        rendered.push("```".into());
    }

    rendered.join("\n")
}

fn render_inline_slack_mrkdwn(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find('`') {
        let open = cursor + offset;
        output.push_str(&render_inline_markup(&value[cursor..open]));
        let delimiter_len = value[open..]
            .bytes()
            .take_while(|byte| *byte == b'`')
            .count();
        let delimiter = &value[open..open + delimiter_len];
        let content_start = open + delimiter_len;
        let Some(close_offset) = value[content_start..].find(delimiter) else {
            output.push_str(&value[open..]);
            return output;
        };
        let close = content_start + close_offset + delimiter_len;
        output.push_str(&value[open..close]);
        cursor = close;
    }
    output.push_str(&render_inline_markup(&value[cursor..]));
    output
}

fn inert_slack_control_syntax(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find('<') {
        let open = cursor + offset;
        output.push_str(&value[cursor..open]);
        let marker = value.as_bytes().get(open + 1).copied();
        if !matches!(marker, Some(b'@' | b'#' | b'!')) {
            output.push('<');
            cursor = open + 1;
            continue;
        }
        let Some(end_offset) = value[open + 2..].find('>') else {
            output.push_str(&value[open..]);
            return output;
        };
        let end = open + 2 + end_offset;
        let token = &value[open + 2..end];
        let display = token.split_once('|').map_or(token, |(_, display)| display);
        output.push(if marker == Some(b'#') { '#' } else { '@' });
        output.push_str(display);
        cursor = end + 1;
    }
    output.push_str(&value[cursor..]);
    output
}

fn render_inline_markup(value: &str) -> String {
    let mut balanced = value.to_owned();
    if !value.matches("**").count().is_multiple_of(2) {
        balanced.push_str("**");
    }
    if !value.matches("__").count().is_multiple_of(2) {
        balanced.push_str("__");
    }
    let value = balanced.as_str();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < value.len() {
        if value[cursor..].starts_with("**") || value[cursor..].starts_with("__") {
            output.push('*');
            cursor += 2;
            continue;
        }

        let image = value[cursor..].starts_with("![");
        if (image || value[cursor..].starts_with('['))
            && let Some((end, label, url)) = markdown_link(value, cursor, image)
            && (url.starts_with("https://") || url.starts_with("http://"))
            && !label.contains('<')
            && !label.contains('>')
            && !url.contains('<')
            && !url.contains('>')
            && !url.contains('|')
        {
            output.push('<');
            output.push_str(url);
            output.push('|');
            output.push_str(label);
            output.push('>');
            cursor = end;
            continue;
        }

        let character = value[cursor..]
            .chars()
            .next()
            .expect("cursor remains on a character boundary");
        output.push(character);
        cursor += character.len_utf8();
    }
    inert_slack_control_syntax(&output)
}

fn markdown_link(value: &str, start: usize, image: bool) -> Option<(usize, &str, &str)> {
    let open = start + usize::from(image);
    let label_start = open + 1;
    let close = label_start + value[label_start..].find("](")?;
    let url_start = close + 2;
    let mut depth = 0;
    for (offset, character) in value[url_start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => {
                let end = url_start + offset;
                return Some((end + 1, &value[label_start..close], &value[url_start..end]));
            }
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn markdown_heading(value: &str) -> Option<&str> {
    let marker_bytes = value.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&marker_bytes) || value.as_bytes().get(marker_bytes) != Some(&b' ') {
        return None;
    }
    Some(value[marker_bytes + 1..].trim())
}

fn markdown_bullet(value: &str) -> Option<(&str, &str)> {
    let marker = value
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())?
        .0;
    let marker_byte = *value.as_bytes().get(marker)?;
    if !matches!(marker_byte, b'-' | b'+' | b'*')
        || !value[marker + 1..].starts_with(char::is_whitespace)
    {
        return None;
    }
    Some((&value[..marker], value[marker + 1..].trim_start()))
}

fn markdown_table_cells(value: &str) -> Option<Vec<String>> {
    let body = value.strip_prefix('|')?.strip_suffix('|')?;
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    let mut code_delimiter = 0;
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let character = body[index..]
            .chars()
            .next()
            .expect("table cursor remains on a character boundary");
        if escaped {
            cell.push(character);
            escaped = false;
            index += character.len_utf8();
            continue;
        }
        if character == '\\' {
            escaped = true;
            cell.push(character);
            index += 1;
            continue;
        }
        if character == '`' {
            let run = bytes[index..]
                .iter()
                .take_while(|byte| **byte == b'`')
                .count();
            if code_delimiter == 0 {
                code_delimiter = run;
            } else if code_delimiter == run {
                code_delimiter = 0;
            }
            cell.push_str(&body[index..index + run]);
            index += run;
            continue;
        }
        if character == '|' && code_delimiter == 0 {
            cells.push(cell.trim().to_owned());
            cell.clear();
        } else {
            cell.push(character);
        }
        index += character.len_utf8();
    }
    cells.push(cell.trim().to_owned());
    (cells.len() >= 2).then_some(cells)
}

fn is_markdown_table_separator(cells: &[String]) -> bool {
    cells.iter().all(|cell| {
        let marker = cell.trim().trim_matches(':');
        marker.len() >= 3 && marker.bytes().all(|byte| byte == b'-')
    })
}

fn render_table_row(cells: &[String], header: bool) -> String {
    let cells = cells
        .iter()
        .map(|cell| {
            let rendered = render_inline_slack_mrkdwn(cell);
            if header && !rendered.is_empty() {
                format!("*{rendered}*")
            } else {
                rendered
            }
        })
        .collect::<Vec<_>>();
    format!("• {}", cells.join(" — "))
}

fn is_markdown_horizontal_rule(value: &str) -> bool {
    let compact = value.replace(' ', "");
    compact.len() >= 3
        && compact
            .bytes()
            .all(|byte| matches!(byte, b'-' | b'_' | b'*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_headings_bold_and_links() {
        assert_eq!(
            render_slack_mrkdwn(
                "## Current state\n\n**Healthy** — [open run](https://example.com/run)",
            ),
            "*Current state*\n\n*Healthy* — <https://example.com/run|open run>"
        );
    }

    #[test]
    fn renders_bullets_without_touching_inline_or_fenced_code() {
        assert_eq!(
            render_slack_mrkdwn(
                "- first\n  * **second**\n\nUse `**literal**`.\n```rust\n# not a heading\n**not bold**\n```",
            ),
            "• first\n  • *second*\n\nUse `**literal**`.\n```rust\n# not a heading\n**not bold**\n```"
        );
    }

    #[test]
    fn keeps_mentions_readable_without_activating_notifications() {
        let input =
            "Ask <@U123> in <#C123|security>, notify <!channel>, and keep [local](doc:runbook).";
        assert_eq!(
            render_slack_mrkdwn(input),
            "Ask @U123 in #security, notify @channel, and keep [local](doc:runbook)."
        );
    }

    #[test]
    fn renders_tables_without_dropping_cells() {
        assert_eq!(
            render_slack_mrkdwn(
                "| Check | State | Owner |\n| :--- | ---: | --- |\n| Session | **Ready** | <@U123> |\n| Empty | | retained |",
            ),
            "• *Check* — *State* — *Owner*\n• Session — *Ready* — @U123\n• Empty —  — retained"
        );
    }

    #[test]
    fn preserves_horizontal_rules_as_visible_structure_and_is_idempotent() {
        let rendered = render_slack_mrkdwn("# State\n---\n- **Ready**");
        assert_eq!(rendered, "*State*\n────────────────────────\n• *Ready*");
        assert_eq!(render_slack_mrkdwn(&rendered), rendered);
    }

    #[test]
    fn closes_unbalanced_fences_and_strong_emphasis() {
        assert_eq!(
            render_slack_mrkdwn("The result is:\n```text\nhealthy"),
            "The result is:\n```text\nhealthy\n```"
        );
        assert_eq!(
            render_slack_mrkdwn("The source is **healthy."),
            "The source is *healthy.*"
        );
        assert_eq!(
            render_slack_mrkdwn("The source is __healthy."),
            "The source is *healthy.*"
        );
    }

    #[test]
    fn preserves_balanced_parentheses_in_markdown_link_urls() {
        assert_eq!(
            render_slack_mrkdwn("[open run](https://example.com/run_(latest))"),
            "<https://example.com/run_(latest)|open run>"
        );
    }
}
