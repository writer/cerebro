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
    let markup_source = inline_markup_outside_code(value);
    let close_single_asterisk = has_unclosed_single_emphasis(&markup_source, '*');
    let close_single_underscore = has_unclosed_single_emphasis(&markup_source, '_');
    let mut strong_asterisk_open = false;
    let mut strong_underscore_open = false;
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find('`') {
        let open = cursor + offset;
        output.push_str(&render_inline_markup(
            &value[cursor..open],
            &mut strong_asterisk_open,
            &mut strong_underscore_open,
        ));
        let delimiter_len = value[open..]
            .bytes()
            .take_while(|byte| *byte == b'`')
            .count();
        let delimiter = &value[open..open + delimiter_len];
        let content_start = open + delimiter_len;
        let Some(close_offset) = value[content_start..].find(delimiter) else {
            output.push_str(&render_inline_markup(
                &value[content_start..],
                &mut strong_asterisk_open,
                &mut strong_underscore_open,
            ));
            cursor = value.len();
            break;
        };
        let close = content_start + close_offset + delimiter_len;
        output.push_str(&value[open..close]);
        cursor = close;
    }
    output.push_str(&render_inline_markup(
        &value[cursor..],
        &mut strong_asterisk_open,
        &mut strong_underscore_open,
    ));
    if strong_asterisk_open {
        output.push('*');
    }
    if strong_underscore_open {
        output.push('*');
    }
    if close_single_asterisk {
        output.push('*');
    }
    if close_single_underscore {
        output.push('_');
    }
    output
}

fn inline_markup_outside_code(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find('`') {
        let open = cursor + offset;
        output.push_str(&value[cursor..open]);
        let delimiter_len = value[open..]
            .bytes()
            .take_while(|byte| *byte == b'`')
            .count();
        let delimiter = &value[open..open + delimiter_len];
        let content_start = open + delimiter_len;
        let Some(close_offset) = value[content_start..].find(delimiter) else {
            output.push_str(&value[content_start..]);
            return output;
        };
        cursor = content_start + close_offset + delimiter_len;
    }
    output.push_str(&value[cursor..]);
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

fn render_inline_markup(
    value: &str,
    strong_asterisk_open: &mut bool,
    strong_underscore_open: &mut bool,
) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < value.len() {
        if let Some(mut end) = raw_url_end(value, cursor) {
            // A raw URL is allowed to contain `*` and `_`, but when the URL is
            // inside an open strong span a terminal double delimiter belongs
            // to the surrounding Markdown. Leave it for the delimiter state
            // machine instead of swallowing it as part of the URL.
            let closes_open_strong = (*strong_asterisk_open && value[cursor..end].ends_with("**"))
                || (*strong_underscore_open && value[cursor..end].ends_with("__"));
            let closes_open_single = (has_unclosed_single_emphasis(&value[..cursor], '*')
                && value[cursor..end].ends_with('*'))
                || (has_unclosed_single_emphasis(&value[..cursor], '_')
                    && value[cursor..end].ends_with('_'));
            if closes_open_strong {
                end -= 2;
            } else if closes_open_single {
                end -= 1;
            }
            if end == cursor {
                continue;
            }
            output.push_str(&value[cursor..end]);
            cursor = end;
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
        if matches!(character, '*' | '_') {
            let run = value[cursor..]
                .chars()
                .take_while(|candidate| *candidate == character)
                .count();
            if matches!(run, 2 | 3) {
                let previous_is_word = value[..cursor]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_alphanumeric);
                let run_bytes = run * character.len_utf8();
                let next_is_word = value[cursor + run_bytes..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric);
                let emphasis_open = if character == '*' {
                    &mut *strong_asterisk_open
                } else {
                    &mut *strong_underscore_open
                };
                if !*emphasis_open && !previous_is_word && next_is_word {
                    output.push('*');
                    *emphasis_open = true;
                } else if *emphasis_open && previous_is_word && !next_is_word {
                    output.push('*');
                    *emphasis_open = false;
                } else {
                    output.push_str(&value[cursor..cursor + run_bytes]);
                }
                cursor += run_bytes;
                continue;
            }
        }
        output.push(character);
        cursor += character.len_utf8();
    }
    inert_slack_control_syntax(&output)
}

fn has_unclosed_single_emphasis(value: &str, delimiter: char) -> bool {
    let mut open = false;
    let mut cursor = 0;
    while cursor < value.len() {
        let image = value[cursor..].starts_with("![");
        if (image || value[cursor..].starts_with('['))
            && let Some((end, _, _)) = markdown_link(value, cursor, image)
        {
            cursor = end;
            continue;
        }
        if let Some(mut end) = raw_url_end(value, cursor) {
            if open && value[cursor..end].ends_with(delimiter) {
                end -= delimiter.len_utf8();
            }
            if end > cursor {
                cursor = end;
                continue;
            }
        }
        let remainder = &value[cursor..];
        if remainder.starts_with(delimiter) {
            let run = remainder
                .chars()
                .take_while(|character| *character == delimiter)
                .count();
            if run == 1 {
                let previous_is_word = value[..cursor]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_alphanumeric);
                let next_is_word = remainder[delimiter.len_utf8()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric);
                if !open && !previous_is_word && next_is_word {
                    open = true;
                } else if open && previous_is_word && !next_is_word {
                    open = false;
                }
            }
            cursor += run;
            continue;
        }
        cursor += remainder
            .chars()
            .next()
            .expect("single delimiter cursor remains on a character boundary")
            .len_utf8();
    }
    open
}

fn raw_url_end(value: &str, start: usize) -> Option<usize> {
    if !value[start..].starts_with("https://") && !value[start..].starts_with("http://") {
        return None;
    }
    Some(
        value[start..]
            .char_indices()
            .find_map(|(offset, character)| {
                (offset > 0 && (character.is_whitespace() || matches!(character, '<' | '>')))
                    .then_some(start + offset)
            })
            .unwrap_or(value.len()),
    )
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
    let body = value.strip_prefix('|').unwrap_or(value);
    let body = body.strip_suffix('|').unwrap_or(body);
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
        assert_eq!(
            render_slack_mrkdwn("Check | State\n--- | ---\nSource | Healthy"),
            "• *Check* — *State*\n• Source — Healthy"
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
        assert_eq!(
            render_slack_mrkdwn("Use `literal text."),
            "Use literal text."
        );
        assert_eq!(
            render_slack_mrkdwn("The *source is healthy."),
            "The *source is healthy.*"
        );
        assert_eq!(
            render_slack_mrkdwn("The _source is healthy."),
            "The _source is healthy._"
        );
        assert_eq!(
            render_slack_mrkdwn("**Source `provider-x` is down**"),
            "*Source `provider-x` is down*"
        );
        assert_eq!(render_slack_mrkdwn("source_runtime"), "source_runtime");
        assert_eq!(render_slack_mrkdwn("2*3"), "2*3");
        assert_eq!(render_slack_mrkdwn("source_"), "source_");
        assert_eq!(render_slack_mrkdwn("source__runtime"), "source__runtime");
        assert_eq!(render_slack_mrkdwn("2**3"), "2**3");
        assert_eq!(render_slack_mrkdwn("source**"), "source**");
        assert_eq!(render_slack_mrkdwn("source__"), "source__");
        let triple = render_slack_mrkdwn("***source***");
        assert_eq!(triple, "*source*");
        assert_eq!(render_slack_mrkdwn(&triple), triple);
    }

    #[test]
    fn preserves_balanced_parentheses_in_markdown_link_urls() {
        assert_eq!(
            render_slack_mrkdwn("[open run](https://example.com/run_(latest))"),
            "<https://example.com/run_(latest)|open run>"
        );
    }

    #[test]
    fn preserves_emphasis_delimiters_inside_raw_and_markdown_urls() {
        assert_eq!(
            render_slack_mrkdwn("See https://example.com/run__alpha__latest for the receipt."),
            "See https://example.com/run__alpha__latest for the receipt."
        );
        assert_eq!(
            render_slack_mrkdwn("See https://example.com/run__alpha for the receipt."),
            "See https://example.com/run__alpha for the receipt."
        );
        assert_eq!(
            render_slack_mrkdwn("See [the latest run](https://example.com/run__alpha__(latest))."),
            "See <https://example.com/run__alpha__(latest)|the latest run>."
        );
        assert_eq!(
            render_slack_mrkdwn(
                "The **current** receipt is https://example.com/run__alpha__latest."
            ),
            "The *current* receipt is https://example.com/run__alpha__latest."
        );
        assert_eq!(
            render_slack_mrkdwn("**See https://example.com/run__alpha"),
            "*See https://example.com/run__alpha*"
        );
        for input in [
            "**See https://example.com**",
            "**See https://example.com** now",
            "__See https://example.com__",
            "__See https://example.com__ now",
        ] {
            let rendered = render_slack_mrkdwn(input);
            assert_eq!(render_slack_mrkdwn(&rendered), rendered, "{input}");
            assert_eq!(rendered.matches('*').count(), 2, "{input}");
        }
    }
}
