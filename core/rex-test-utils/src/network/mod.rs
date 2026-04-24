/// Parse nslookup output to extract IP addresses (both IPv4 and IPv6)
///
/// Example nslookup output:
/// ```txt
/// Server:         10.0.0.1
/// Address:        10.0.0.1#53
///
/// Non-authoritative answer:
/// Name:   example.com
/// Address: 98.87.170.74
/// Address: 98.87.170.71
/// Address: 98.82.161.185
/// Address: 2600:9000:21f8:a800:1::
/// Address: 2600:9000:21f8:c800:1::
/// ```
pub fn parse_nslookup_output(output: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let mut in_answer_section = false;

    for line in output.lines() {
        let line = line.trim();

        // Skip until we find the answer section
        if line.contains("Non-authoritative answer") || line.starts_with("Name:") {
            in_answer_section = true;
            continue;
        }

        // Parse Address lines in the answer section
        if in_answer_section && line.starts_with("Address:") {
            // Extract IP address after "Address:"
            if let Some(ip_part) = line.split_whitespace().nth(1) {
                // Remove port if present (e.g., "10.0.0.1#53" -> "10.0.0.1")
                let ip = ip_part.split('#').next().unwrap_or(ip_part);

                // Validate it's either an IPv4 or IPv6 address
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::parse_nslookup_output;
    use rstest::rstest;

    /// Given: nslookup output with various formats (IPv4, IPv6, with ports, whitespace, invalid addresses)
    /// When: parsing the nslookup output
    /// Then: the correct IP addresses should be extracted
    #[rstest]
    #[case::standard_output_with_ipv4_and_ipv6(
        r#"Server:         10.0.0.1
Address:        10.0.0.1#53

Non-authoritative answer:
Name:   example.com
Address: 98.87.170.74
Address: 98.87.170.71
Address: 2600:9000:21f8:a800:1::
Address: 2600:9000:21f8:c800:1::"#,
        vec![
            "98.87.170.74",
            "98.87.170.71",
            "2600:9000:21f8:a800:1::",
            "2600:9000:21f8:c800:1::"
        ]
    )]
    #[case::name_section_trigger(
        r#"Server: 8.8.8.8
Address: 8.8.8.8#53

Name: example.com
Address: 93.184.216.34"#,
        vec!["93.184.216.34"]
    )]
    #[case::addresses_with_port_numbers(
        r#"Non-authoritative answer:
Name: test.com
Address: 192.168.1.1#80
Address: 10.0.0.1#443"#,
        vec!["192.168.1.1", "10.0.0.1"]
    )]
    #[case::ipv6_only(
        r#"Non-authoritative answer:
Name: ipv6.google.com
Address: 2607:f8b0:4004:c1b::65
Address: 2607:f8b0:4004:c1b::71"#,
        vec!["2607:f8b0:4004:c1b::65", "2607:f8b0:4004:c1b::71"]
    )]
    #[case::whitespace_handling(
        r#"   Non-authoritative answer:   
  Name:   test.com  
   Address:    192.168.1.1   
 Address:  10.0.0.1#53  "#,
        vec!["192.168.1.1", "10.0.0.1"]
    )]
    #[case::invalid_addresses_filtered_out(
        r#"Non-authoritative answer:
Name: test.com
Address: invalid-ip
Address: 192.168.1.1
Address: not.an.ip.address"#,
        vec!["192.168.1.1"]
    )]
    #[case::address_line_without_ip(
        r#"Non-authoritative answer:
Name: test.com
Address:
Address: 192.168.1.1"#,
        vec!["192.168.1.1"]
    )]
    fn test_parse_valid_nslookup_output(
        #[case] nslookup_output: &str,
        #[case] expected_ips: Vec<&str>,
    ) {
        let result = parse_nslookup_output(nslookup_output);
        assert_eq!(result, expected_ips);
    }

    /// Given: nslookup output with no valid addresses (empty string or error response)
    /// When: parsing the nslookup output
    /// Then: an empty vector should be returned
    #[rstest]
    #[case::empty_string("")]
    #[case::no_answer_section(
        r#"Server: 8.8.8.8
Address: 8.8.8.8#53

** server can't find example.invalid: NXDOMAIN"#
    )]
    fn test_parse_nslookup_output_returns_empty(#[case] nslookup_output: &str) {
        let result = parse_nslookup_output(nslookup_output);
        assert!(result.is_empty());
    }
}
