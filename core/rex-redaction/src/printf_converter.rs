use std::collections::HashSet;

// handle single-line printf format pattern and convert them to regex
pub fn printf_to_regex(printf_pattern: &str) -> Result<String, Vec<String>> {
    let mut result = String::with_capacity(printf_pattern.len() * 2);
    let mut chars = printf_pattern.chars().peekable();
    let mut literal_buffer = String::new();
    let mut unsupported_specifiers = Vec::new();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if !literal_buffer.is_empty() {
                result.push_str(&literal_buffer);
                literal_buffer.clear();
            }

            if chars.peek().is_some() {
                // Parse format specifier and skip flags (#, 0, -, +, ., *, space), width, and precision
                let mut format_mod = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit()
                        || ch == '#'
                        || ch == '0'
                        || ch == '-'
                        || ch == '+'
                        || ch == ' '
                        || ch == '.'
                        || ch == '*'
                    {
                        format_mod.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }

                // handle length modifiers (zu)
                let mut length_mod = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == 'z' || ch == 'l' {
                        length_mod.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(spec_ch) = chars.next() {
                    if let Some(regex_pattern) = format_specifier_to_regex(spec_ch) {
                        result.push_str(&regex_pattern);
                    } else {
                        let full_specifier = format!("%{format_mod}{length_mod}{spec_ch}");
                        unsupported_specifiers.push(full_specifier);
                    }
                }
            }
        } else {
            literal_buffer.push(ch);
        }
    }

    if !literal_buffer.is_empty() {
        result.push_str(&literal_buffer);
    }

    if unsupported_specifiers.is_empty() {
        Ok(result)
    } else {
        Err(unsupported_specifiers)
    }
}

fn format_specifier_to_regex(specifier: char) -> Option<String> {
    match specifier {
        's' => Some(r"(\S+)".to_string()),
        'd' => Some(r"(-?\d+)".to_string()),
        'u' => Some(r"(\d+)".to_string()),
        'm' => Some(".*?".to_string()),
        _ => None,
    }
}

pub fn collect_unsupported_specifiers(redaction_entries: &str) -> HashSet<String> {
    let unsupported_specifiers: HashSet<String> = redaction_entries
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| printf_to_regex(line).err())
        .flatten()
        .collect();

    unsupported_specifiers
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Given: Individual printf format specifiers
    /// When: printf_to_regex is called on each specifier  
    /// Then: Each specifier is converted to its regex equivalent
    #[rstest]
    #[case("%s", r"(\S+)")]
    #[case("%d", r"(-?\d+)")]
    #[case("%zu", r"(\d+)")]
    #[case("%m", ".*?")]
    #[case("%lld", r"(-?\d+)")]
    fn test_printf_to_regex_all_specifiers(#[case] input: &str, #[case] expected: String) {
        assert_eq!(printf_to_regex(input).unwrap(), expected);
    }

    /// Given: Individual printf format specifier characters (both supported and unsupported)
    /// When: format_specifier_to_regex is called on each specifier
    /// Then: Supported specifiers return their corresponding regex patterns, unsupported ones return None
    #[rstest]
    #[case('s', Some(r"(\S+)".to_string()), "%s conversion fialed")]
    #[case('d', Some(r"(-?\d+)".to_string()), "%d conversion fialed")]
    #[case('u', Some(r"(\d+)".to_string()), "%u conversion fialed")]
    #[case('m', Some(".*?".to_string()), "%m conversion fialed")]
    #[case('f', None, "%f specifier should return None (unsupported)")]
    #[case('p', None, "%p specifier should return None (unsupported)")]
    #[case('l', None, "%l modifier should return None (unsupported)")]
    fn test_format_specifier_to_regex(
        #[case] specifier: char,
        #[case] expected: Option<String>,
        #[case] description: &str,
    ) {
        let result = format_specifier_to_regex(specifier);
        assert_eq!(result, expected, "Failed: {}", description);
    }

    /// Given: Redaction dictionary entries containing printf format patterns including valid, invalid, comments
    /// When: collect_unsupported_specifiers is called on the dictionary content
    /// Then: All unsupported format specifiers are collected into a set, ignoring comments and empty lines
    #[rstest]
    #[case(
        "valid pattern %s\nanother valid %d\nyet another %u",
        vec![],
        "should return empty set when all specifiers are supported"
    )]
    #[case(
        "# Only comments\n  \n# More comments  \n",
        vec![],
        "should return empty set for input with only comments and whitespace"
    )]
    #[case(
        "error %f occurred %p\nerror %f again\nprocessing %x bytes",
        vec!["%f", "%x", "%p"],
        "should deduplicate unsupported specifiers"
    )]
    #[case(
        "complex pattern %.2f %f %lu %lld",
        vec!["%f", "%.2f"],
        "should collect all unsupported specifiers from complex patterns"
    )]
    fn test_collect_unsupported_specifiers(
        #[case] redaction_entries: &str,
        #[case] expected_unsupported: Vec<&str>,
        #[case] description: &str,
    ) {
        let result = collect_unsupported_specifiers(redaction_entries);
        let expected_set: HashSet<String> =
            expected_unsupported.iter().map(|s| s.to_string()).collect();

        assert_eq!(result, expected_set, "Failed: {}", description);
    }
}
