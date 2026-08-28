use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::str::FromStr;

// Use miniscript's re-exported bitcoin to avoid version conflicts
use miniscript::bitcoin;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::ForEachKey;
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub derivation_path: String,
    pub full_derivation: String,
    pub xpub: String,
    pub derived_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct DescriptorAnalysis {
    pub valid: bool,
    pub error: Option<String>,
    pub descriptor_type: Option<String>,
    pub policy: Option<String>,
    pub script_hex: Option<String>,
    pub script_asm: Option<String>,
    pub address: Option<String>,
    pub keys: Vec<KeyInfo>,
    pub raw_descriptor: Option<String>,
    pub timelock_info: Vec<String>,
}

fn extract_timelocks(desc_str: &str) -> Vec<String> {
    let mut timelocks = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = desc_str[search_from..].find("after(") {
        let start = search_from + pos + 6;
        if let Some(end) = desc_str[start..].find(')') {
            let val_str = &desc_str[start..start + end];
            if let Ok(val) = val_str.parse::<u32>() {
                if val >= 500_000_000 {
                    let datetime = format_timestamp(val);
                    timelocks.push(format!("after({}) — Timelock: {} (Unix timestamp)", val, datetime));
                } else {
                    timelocks.push(format!("after({}) — Timelock: block height {}", val, val));
                }
            }
            search_from = start + end;
        } else {
            break;
        }
    }
    search_from = 0;
    while let Some(pos) = desc_str[search_from..].find("older(") {
        let start = search_from + pos + 6;
        if let Some(end) = desc_str[start..].find(')') {
            let val_str = &desc_str[start..start + end];
            if let Ok(val) = val_str.parse::<u32>() {
                timelocks.push(format!("older({}) — Relative timelock: {} blocks", val, val));
            }
            search_from = start + end;
        } else {
            break;
        }
    }
    timelocks
}

fn format_timestamp(ts: u32) -> String {
    let ts = ts as i64;
    let days_since_epoch = ts / 86400;
    let time_of_day = ts % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let mut days = days_since_epoch;
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let months_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for (i, &md) in months_days.iter().enumerate() {
        if days < md {
            month = i + 1;
            break;
        }
        days -= md;
    }
    let day = days + 1;

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
        "{} {}, {} {:02}:{:02} UTC",
        month_names[month - 1],
        day,
        year,
        hours,
        minutes
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Build a human-readable policy description from a descriptor string
fn build_policy_description(desc_str: &str) -> String {
    let mut result = String::new();

    // Strip outer wrapper (wsh, wpkh, sh, etc.)
    let inner = if let Some(pos) = desc_str.find('(') {
        let wrapper = &desc_str[..pos];
        result.push_str(&format!("Type: {}\n", wrapper));
        let end = desc_str.rfind(')').unwrap_or(desc_str.len());
        &desc_str[pos + 1..end]
    } else {
        desc_str
    };

    // Parse the miniscript structure into readable form
    result.push_str("\nSpending conditions:\n");
    result.push_str(&parse_miniscript_node(inner, 0));
    result
}

fn parse_miniscript_node(s: &str, indent: usize) -> String {
    let prefix = "  ".repeat(indent);
    let s = s.trim();

    if s.starts_with("andor(") {
        let inner = &s[6..s.len()-1];
        let parts = split_top_level(inner);
        if parts.len() == 3 {
            let mut out = format!("{}AND-OR condition:\n", prefix);
            out.push_str(&format!("{}  IF: {}\n", prefix, summarize_condition(&parts[0])));
            out.push_str(&format!("{}  THEN: {}\n", prefix, summarize_condition(&parts[1])));
            out.push_str(&format!("{}  ELSE: {}\n", prefix, summarize_condition(&parts[2])));
            return out;
        }
    }
    if s.starts_with("and_v(") || s.starts_with("and_b(") || s.starts_with("and_n(") {
        let inner = &s[6..s.len()-1];
        let parts = split_top_level(inner);
        if parts.len() == 2 {
            let mut out = format!("{}AND (both required):\n", prefix);
            out.push_str(&format!("{}  • {}\n", prefix, summarize_condition(&parts[0])));
            out.push_str(&format!("{}  • {}\n", prefix, summarize_condition(&parts[1])));
            return out;
        }
    }
    if s.starts_with("or_d(") || s.starts_with("or_b(") || s.starts_with("or_c(") || s.starts_with("or_i(") {
        let inner = &s[5..s.len()-1];
        let parts = split_top_level(inner);
        if parts.len() == 2 {
            let mut out = format!("{}OR (either suffices):\n", prefix);
            out.push_str(&format!("{}  • {}\n", prefix, summarize_condition(&parts[0])));
            out.push_str(&format!("{}  • {}\n", prefix, summarize_condition(&parts[1])));
            return out;
        }
    }
    if s.starts_with("multi(") || s.starts_with("sortedmulti(") {
        let inner_start = s.find('(').unwrap() + 1;
        let inner = &s[inner_start..s.len()-1];
        let parts = split_top_level(inner);
        if let Some(threshold) = parts.first() {
            let total = parts.len() - 1;
            return format!("{}{}-of-{} multisig\n", prefix, threshold.trim(), total);
        }
    }
    if s.starts_with("thresh(") {
        let inner = &s[7..s.len()-1];
        let parts = split_top_level(inner);
        if let Some(threshold) = parts.first() {
            let total = parts.len() - 1;
            return format!("{}Threshold: {}-of-{} conditions\n", prefix, threshold.trim(), total);
        }
    }
    if s.starts_with("pk(") || s.starts_with("pk_k(") || s.starts_with("pk_h(") {
        let inner_start = s.find('(').unwrap() + 1;
        let key = &s[inner_start..s.len()-1];
        return format!("{}Key: {}\n", prefix, abbreviate_key(key));
    }
    if s.starts_with("pkh(") {
        let key = &s[4..s.len()-1];
        return format!("{}Key hash: {}\n", prefix, abbreviate_key(key));
    }
    if s.starts_with("after(") {
        let val = &s[6..s.len()-1];
        if let Ok(v) = val.parse::<u32>() {
            if v >= 500_000_000 {
                return format!("{}Absolute timelock: {} ({})\n", prefix, val, format_timestamp(v));
            } else {
                return format!("{}Absolute timelock: block height {}\n", prefix, val);
            }
        }
        return format!("{}Absolute timelock: {}\n", prefix, val);
    }
    if s.starts_with("older(") {
        let val = &s[6..s.len()-1];
        return format!("{}Relative timelock: {} blocks\n", prefix, val);
    }
    if s.starts_with("v:") {
        return parse_miniscript_node(&s[2..], indent);
    }
    if s.starts_with("j:") || s.starts_with("n:") || s.starts_with("l:") ||
       s.starts_with("u:") || s.starts_with("t:") || s.starts_with("d:") ||
       s.starts_with("s:") || s.starts_with("c:") || s.starts_with("a:") {
        return parse_miniscript_node(&s[2..], indent);
    }

    format!("{}{}\n", prefix, abbreviate_key(s))
}

fn summarize_condition(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("multi(") || s.starts_with("sortedmulti(") {
        let inner_start = s.find('(').unwrap() + 1;
        let inner = &s[inner_start..s.len()-1];
        let parts = split_top_level(inner);
        if let Some(threshold) = parts.first() {
            let total = parts.len() - 1;
            return format!("{}-of-{} multisig", threshold.trim(), total);
        }
    }
    if s.starts_with("pk(") || s.starts_with("pk_k(") {
        let inner_start = s.find('(').unwrap() + 1;
        let key = &s[inner_start..s.len()-1];
        return format!("Key {}", abbreviate_key(key));
    }
    if s.starts_with("pkh(") {
        let key = &s[4..s.len()-1];
        return format!("Key hash {}", abbreviate_key(key));
    }
    if s.starts_with("after(") {
        let val = &s[6..s.len()-1];
        if let Ok(v) = val.parse::<u32>() {
            if v >= 500_000_000 {
                return format!("Timelock until {}", format_timestamp(v));
            }
        }
        return format!("Timelock after {}", val);
    }
    if s.starts_with("older(") {
        return format!("Relative timelock: {} blocks", &s[6..s.len()-1]);
    }
    if s.starts_with("and_v(") || s.starts_with("and_b(") {
        let inner = &s[6..s.len()-1];
        let parts = split_top_level(inner);
        if parts.len() == 2 {
            return format!("{} AND {}", summarize_condition(&parts[0]), summarize_condition(&parts[1]));
        }
    }
    if s.starts_with("or_d(") || s.starts_with("or_b(") || s.starts_with("or_c(") || s.starts_with("or_i(") {
        let inner = &s[5..s.len()-1];
        let parts = split_top_level(inner);
        if parts.len() == 2 {
            return format!("{} OR {}", summarize_condition(&parts[0]), summarize_condition(&parts[1]));
        }
    }
    if s.starts_with("v:") || s.starts_with("j:") || s.starts_with("n:") ||
       s.starts_with("l:") || s.starts_with("u:") || s.starts_with("t:") ||
       s.starts_with("d:") || s.starts_with("s:") || s.starts_with("c:") ||
       s.starts_with("a:") {
        return summarize_condition(&s[2..]);
    }
    abbreviate_key(s)
}

fn abbreviate_key(key: &str) -> String {
    if let Some(bracket_start) = key.find('[') {
        if let Some(bracket_end) = key.find(']') {
            let origin = &key[bracket_start + 1..bracket_end];
            let fp = origin.split('/').next().unwrap_or("?");
            return format!("[{}...]", fp);
        }
    }
    if key.len() > 20 {
        format!("{}...{}", &key[..8], &key[key.len()-8..])
    } else {
        key.to_string()
    }
}

fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Expand multipath descriptors like <0;1> into separate descriptors
fn expand_multipath(desc_str: &str) -> Vec<(String, String)> {
    if !desc_str.contains('<') || !desc_str.contains(';') {
        return vec![("single".to_string(), desc_str.to_string())];
    }

    let base = if let Some(hash_pos) = desc_str.rfind('#') {
        &desc_str[..hash_pos]
    } else {
        desc_str
    };

    let mut receive = base.to_string();
    let mut change = base.to_string();

    while receive.contains('<') {
        if let Some(start) = receive.find('<') {
            if let Some(end) = receive[start..].find('>') {
                let pattern = &receive[start..start + end + 1].to_string();
                let inner = &pattern[1..pattern.len() - 1];
                if let Some(semi) = inner.find(';') {
                    let first = &inner[..semi];
                    let second = &inner[semi + 1..];
                    receive = receive.replacen(pattern.as_str(), first, 1);
                    change = change.replacen(pattern.as_str(), second, 1);
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    vec![
        ("receive (path 0)".to_string(), receive),
        ("change (path 1)".to_string(), change),
    ]
}

/// Derive a concrete public key from an xpub string and child path segments.
/// The key_str is the full key string from the descriptor like:
///   [d1a8c956/48h/0h/203h/2h]xpub6ED39.../0/*
/// After multipath expansion and at_derivation_index, the wildcard is replaced with the index.
/// The derived descriptor key string will look like:
///   [d1a8c956/48h/0h/203h/2h]xpub6ED39.../0/3
/// We need to take the xpub, parse it, and derive child keys for the remaining path (e.g., /0/3).
fn derive_pubkey_from_key_str(key_str: &str, secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>) -> (String, String) {
    // Parse the key string to extract xpub and child path
    // Format: [fingerprint/origin_path]xpub.../child/path
    // or just: xpub.../child/path

    let after_bracket = if let Some(bracket_end) = key_str.find(']') {
        &key_str[bracket_end + 1..]
    } else {
        key_str
    };

    // Split into xpub base and child derivation path
    // xpub is always 111 chars for mainnet (xpub...) but let's be safe and find the first /
    // after the xpub prefix
    let (xpub_str, child_path_parts) = split_xpub_and_path(after_bracket);

    // Parse the xpub
    let xpub = match Xpub::from_str(xpub_str) {
        Ok(x) => x,
        Err(_) => return (after_bracket.to_string(), String::new()),
    };

    // Build the child derivation path
    let mut child_numbers: Vec<ChildNumber> = Vec::new();
    for part in &child_path_parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
            (&part[..part.len()-1], true)
        } else {
            (&part[..], false)
        };
        if let Ok(num) = num_str.parse::<u32>() {
            let child = if hardened {
                ChildNumber::from_hardened_idx(num).unwrap_or(ChildNumber::from_normal_idx(0).unwrap())
            } else {
                ChildNumber::from_normal_idx(num).unwrap_or(ChildNumber::from_normal_idx(0).unwrap())
            };
            child_numbers.push(child);
        }
    }

    // Build full derivation description
    let full_deriv = format!("{}/{}", xpub_str, child_path_parts.join("/"));

    // Derive the child key
    if child_numbers.is_empty() {
        // No child path to derive, the xpub itself is the key
        return (xpub.public_key.to_string(), full_deriv);
    }

    // Derive step by step
    let mut current = xpub;
    for child in &child_numbers {
        match current.ckd_pub(secp, *child) {
            Ok(derived) => current = derived,
            Err(e) => {
                return (format!("derivation error: {}", e), full_deriv);
            }
        }
    }

    (current.public_key.to_string(), full_deriv)
}

/// Split "xpub6ED39.../0/3" into ("xpub6ED39...", ["0", "3"])
fn split_xpub_and_path(s: &str) -> (&str, Vec<String>) {
    // xpub strings are base58, they don't contain '/'
    // Find the first '/' after the initial xpub/tpub
    if let Some(first_slash) = s.find('/') {
        let xpub_part = &s[..first_slash];
        let path_part = &s[first_slash + 1..];
        let parts: Vec<String> = path_part.split('/').map(|s| s.to_string()).collect();
        (xpub_part, parts)
    } else {
        (s, vec![])
    }
}

fn derive_single_descriptor(
    desc_str: &str,
    index: u32,
    network: Network,
    label: &str,
) -> DescriptorAnalysis {
    let secp = Secp256k1::verification_only();

    // Parse the descriptor
    let desc = match Descriptor::<DescriptorPublicKey>::from_str(desc_str) {
        Ok(d) => d,
        Err(e) => {
            return DescriptorAnalysis {
                valid: false,
                error: Some(format!("Parse error ({}): {}", label, e)),
                descriptor_type: None,
                policy: None,
                script_hex: None,
                script_asm: None,
                address: None,
                keys: vec![],
                raw_descriptor: Some(desc_str.to_string()),
                timelock_info: vec![],
            };
        }
    };

    // Collect key info before derivation (from the original descriptor with wildcards)
    let mut key_origins: Vec<(String, String, String)> = Vec::new(); // (fingerprint, origin_path, xpub)
    desc.for_each_key(|key| {
        let key_str = key.to_string();
        if let Some(bracket_start) = key_str.find('[') {
            if let Some(bracket_end) = key_str.find(']') {
                let origin = &key_str[bracket_start + 1..bracket_end];
                let parts: Vec<&str> = origin.splitn(2, '/').collect();
                let fp = parts.first().unwrap_or(&"unknown").to_string();
                let path = if parts.len() > 1 {
                    format!("m/{}", parts[1])
                } else {
                    "m".to_string()
                };
                let xpub_part = &key_str[bracket_end + 1..];
                let xpub_display = xpub_part.split('/').next().unwrap_or(xpub_part);
                key_origins.push((fp, path, xpub_display.to_string()));
            }
        } else {
            // Key without origin info
            let xpub_display = key_str.split('/').next().unwrap_or(&key_str);
            key_origins.push(("unknown".to_string(), "m".to_string(), xpub_display.to_string()));
        }
        true
    });

    // Derive at the specified index — this replaces /* with the concrete index
    let derived = match desc.at_derivation_index(index) {
        Ok(d) => d,
        Err(e) => {
            let keys: Vec<KeyInfo> = key_origins.iter().map(|(fp, path, xpub)| KeyInfo {
                fingerprint: fp.clone(),
                derivation_path: path.clone(),
                full_derivation: String::new(),
                xpub: xpub.clone(),
                derived_pubkey: String::new(),
            }).collect();
            return DescriptorAnalysis {
                valid: true,
                error: Some(format!("Derivation error at index {} ({}): {}", index, label, e)),
                descriptor_type: Some(format!("{:?}", desc.desc_type())),
                policy: None,
                script_hex: None,
                script_asm: None,
                address: None,
                keys,
                raw_descriptor: Some(desc_str.to_string()),
                timelock_info: extract_timelocks(desc_str),
            };
        }
    };

    // Now iterate over derived descriptor keys and actually derive pubkeys
    let mut keys: Vec<KeyInfo> = Vec::new();
    let mut derived_key_idx = 0usize;
    derived.for_each_key(|key| {
        let key_str = key.to_string();

        // Get origin info from original descriptor
        let (fp, origin_path, xpub_display) = if derived_key_idx < key_origins.len() {
            key_origins[derived_key_idx].clone()
        } else {
            ("unknown".to_string(), "m".to_string(), String::new())
        };

        // Derive the actual pubkey from the xpub + child path
        let (derived_pubkey, full_derivation) = derive_pubkey_from_key_str(&key_str, &secp);

        keys.push(KeyInfo {
            fingerprint: fp,
            derivation_path: origin_path,
            full_derivation,
            xpub: xpub_display,
            derived_pubkey,
        });

        derived_key_idx += 1;
        true
    });

    // Get script
    let script = derived.explicit_script().ok();
    let script_hex = script.as_ref().map(|s| {
        s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    });
    let script_asm = script.as_ref().map(|s| format!("{}", s));

    // Get address
    let address = derived.address(network).ok().map(|a| a.to_string());

    // Get policy
    let policy = {
        let desc_string = desc.to_string();
        Some(build_policy_description(&desc_string))
    };

    DescriptorAnalysis {
        valid: true,
        error: None,
        descriptor_type: Some(format!("{:?}", desc.desc_type())),
        policy,
        script_hex,
        script_asm,
        address,
        keys,
        raw_descriptor: Some(desc_str.to_string()),
        timelock_info: extract_timelocks(desc_str),
    }
}

#[derive(Serialize)]
pub struct MultiPathResult {
    pub paths: Vec<PathResult>,
    pub timelock_info: Vec<String>,
    pub descriptor_type: Option<String>,
    pub policy: Option<String>,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct PathResult {
    pub label: String,
    pub analysis: DescriptorAnalysis,
}

#[wasm_bindgen]
pub fn analyze_descriptor(descriptor: &str, index: u32, network_str: &str) -> String {
    let network = match network_str {
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => Network::Bitcoin,
    };

    let desc_str = descriptor.trim();

    // Expand multipath
    let paths = expand_multipath(desc_str);

    let mut path_results = Vec::new();
    let mut first_error = None;
    let mut descriptor_type = None;
    let mut policy = None;
    let mut all_valid = true;

    for (label, path_desc) in &paths {
        let analysis = derive_single_descriptor(path_desc, index, network, label);
        if !analysis.valid {
            all_valid = false;
            if first_error.is_none() {
                first_error = analysis.error.clone();
            }
        }
        if descriptor_type.is_none() {
            descriptor_type = analysis.descriptor_type.clone();
        }
        if policy.is_none() {
            policy = analysis.policy.clone();
        }
        path_results.push(PathResult {
            label: label.clone(),
            analysis,
        });
    }

    let timelock_info = extract_timelocks(desc_str);

    let result = MultiPathResult {
        paths: path_results,
        timelock_info,
        descriptor_type,
        policy,
        valid: all_valid,
        error: first_error,
    };

    serde_json::to_string(&result).unwrap_or_else(|e| {
        format!(r#"{{"valid":false,"error":"Serialization error: {}","paths":[],"timelock_info":[],"descriptor_type":null,"policy":null}}"#, e)
    })
}

#[derive(Serialize)]
pub struct ExportedAddress {
    pub index: u32,
    pub path: String,
    pub address: String,
    pub script_type: String,
}

#[derive(Serialize)]
pub struct ExportResult {
    pub valid: bool,
    pub error: Option<String>,
    pub rows: Vec<ExportedAddress>,
}

/// Derive addresses for indices [start, start + count) across all paths of a
/// (possibly multipath) descriptor. Returns a JSON ExportResult.
#[wasm_bindgen]
pub fn export_addresses(descriptor: &str, start: u32, count: u32, network_str: &str) -> String {
    let network = match network_str {
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => Network::Bitcoin,
    };

    let desc_str = descriptor.trim();
    let paths = expand_multipath(desc_str);
    let multipath = paths.len() > 1;

    let mut rows: Vec<ExportedAddress> = Vec::new();

    for (label, path_desc) in &paths {
        // Fail fast if this path's descriptor does not parse
        if let Err(e) = Descriptor::<DescriptorPublicKey>::from_str(path_desc) {
            return serde_json::to_string(&ExportResult {
                valid: false,
                error: Some(format!("Parse error ({}): {}", label, e)),
                rows: vec![],
            })
            .unwrap_or_else(|e| format!(r#"{{"valid":false,"error":"Serialization error: {}","rows":[]}}"#, e));
        }

        for offset in 0..count {
            let index = start.saturating_add(offset);
            let analysis = derive_single_descriptor(path_desc, index, network, label);

            if !analysis.valid || analysis.address.is_none() {
                return serde_json::to_string(&ExportResult {
                    valid: false,
                    error: Some(format!(
                        "Failed to derive index {} ({}){}",
                        index,
                        label,
                        analysis
                            .error
                            .map(|e| format!(": {}", e))
                            .unwrap_or_default()
                    )),
                    rows: vec![],
                })
                .unwrap_or_else(|e| format!(r#"{{"valid":false,"error":"Serialization error: {}","rows":[]}}"#, e));
            }

            rows.push(ExportedAddress {
                index,
                path: if multipath { label.clone() } else { String::new() },
                address: analysis.address.unwrap_or_default(),
                script_type: analysis.descriptor_type.unwrap_or_default(),
            });
        }
    }

    serde_json::to_string(&ExportResult {
        valid: true,
        error: None,
        rows,
    })
    .unwrap_or_else(|e| format!(r#"{{"valid":false,"error":"Serialization error: {}","rows":[]}}"#, e))
}

/// Validate a descriptor checksum
#[wasm_bindgen]
pub fn validate_checksum(descriptor: &str) -> String {
    let desc_str = descriptor.trim();

    match Descriptor::<DescriptorPublicKey>::from_str(desc_str) {
        Ok(_) => {
            serde_json::json!({
                "valid": true,
                "message": "Descriptor and checksum are valid"
            }).to_string()
        }
        Err(e) => {
            let err_str = format!("{}", e);
            serde_json::json!({
                "valid": false,
                "message": format!("Invalid: {}", err_str)
            }).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_multipath() {
        // wpkh multipath descriptor (testnet tpub)
        let desc = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/<0;1>/*)";
        let result = export_addresses(desc, 0, 3, "bitcoin");
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["valid"].as_bool().unwrap(), "export failed: {}", result);
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 6); // 3 indices x 2 paths
        assert_eq!(rows[0]["path"], "receive (path 0)");
        assert_eq!(rows[3]["path"], "change (path 1)");
        assert!(rows[0]["address"].as_str().unwrap().starts_with("bc1q"));
        assert_eq!(rows[0]["script_type"], "Wpkh");
        println!("{}", serde_json::to_string_pretty(&rows[0]).unwrap());
    }

    #[test]
    fn test_export_single_path() {
        let desc = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
        let result = export_addresses(desc, 5, 2, "bitcoin");
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["valid"].as_bool().unwrap(), "export failed: {}", result);
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["index"], 5);
        assert_eq!(rows[0]["path"], "");
    }

    #[test]
    fn test_export_invalid() {
        let result = export_addresses("wpkh(invalid)", 0, 1, "bitcoin");
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(!v["valid"].as_bool().unwrap());
    }
}
