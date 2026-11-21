//! Minimal zero-dependency JSON serializer & RFC-8259 parser for clean, safe IPC.

pub fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[allow(dead_code)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    pub fn s(v: impl Into<String>) -> Self {
        Json::Str(v.into())
    }

    pub fn to_string_compact(&self) -> String {
        let mut buf = String::new();
        self.write_to(&mut buf);
        buf
    }

    fn write_to(&self, buf: &mut String) {
        match self {
            Json::Null => buf.push_str("null"),
            Json::Bool(b) => buf.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => buf.push_str(&n.to_string()),
            Json::Uint(n) => buf.push_str(&n.to_string()),
            Json::Float(f) => {
                if f.is_finite() {
                    buf.push_str(&format!("{:.2}", f));
                } else {
                    buf.push_str("0");
                }
            }
            Json::Str(s) => buf.push_str(&escape_str(s)),
            Json::Array(items) => {
                buf.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        buf.push(',');
                    }
                    item.write_to(buf);
                }
                buf.push(']');
            }
            Json::Object(fields) => {
                buf.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        buf.push(',');
                    }
                    buf.push_str(&escape_str(k));
                    buf.push(':');
                    v.write_to(buf);
                }
                buf.push('}');
            }
        }
    }
}

/// Parsed dynamic JSON value for decoding Docker/Podman/Hyprland IPC JSON.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

#[allow(dead_code)]
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) if *n >= 0.0 && n.is_finite() => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

pub fn parse_json(input: &str) -> Result<Value, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        if self.depth > 64 {
            return Err("JSON nesting too deep".into());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(Value::Str),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b't') => self.expect_lit(b"true", Value::Bool(true)),
            Some(b'f') => self.expect_lit(b"false", Value::Bool(false)),
            Some(b'n') => self.expect_lit(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            other => Err(format!("unexpected byte {:?} at {}", other, self.pos)),
        }
    }

    fn expect_lit(&mut self, lit: &[u8], val: Value) -> Result<Value, String> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if matches!(b, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid utf8 number".to_string())?;
        let n = s
            .parse::<f64>()
            .map_err(|_| format!("invalid number '{s}'"))?;
        Ok(Value::Num(n))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"'".into());
        }
        self.pos += 1;
        let mut out = String::new();
        while let Some(b) = self.peek() {
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.peek().ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or_else(|| "short unicode escape".to_string())?;
                            self.pos += 4;
                            let hex_s = std::str::from_utf8(hex).map_err(|_| "bad unicode")?;
                            let code = u32::from_str_radix(hex_s, 16)
                                .map_err(|_| "bad unicode hex")?;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        other => out.push(other as char),
                    }
                }
                c if c < 0x80 => out.push(c as char),
                _ => {
                    // Multi-byte UTF-8 sequence starting at self.pos - 1
                    let start = self.pos - 1;
                    while let Some(nb) = self.peek() {
                        if (nb & 0xC0) == 0x80 {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let slice = std::str::from_utf8(&self.bytes[start..self.pos])
                        .unwrap_or("\u{FFFD}");
                    out.push_str(slice);
                }
            }
        }
        Err("unterminated string".into())
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.pos += 1; // '['
        self.depth += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                self.depth -= 1;
                return Ok(Value::Array(items));
            }
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(items));
                }
                other => return Err(format!("expected ',' or ']', got {:?} at {}", other, self.pos)),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.pos += 1; // '{'
        self.depth += 1;
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                self.depth -= 1;
                return Ok(Value::Object(entries));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(entries));
                }
                other => return Err(format!("expected ',' or '}}', got {:?} at {}", other, self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quote_chars() {
        assert_eq!(escape_str("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn serializes_nested_object() {
        let obj = Json::Object(vec![
            ("port", Json::Uint(3000)),
            ("ok", Json::Bool(true)),
            ("tags", Json::Array(vec![Json::s("web"), Json::s("next")])),
        ]);
        assert_eq!(
            obj.to_string_compact(),
            r#"{"port":3000,"ok":true,"tags":["web","next"]}"#
        );
    }

    #[test]
    fn parses_nested_docker_json() {
        let raw = r#"[{"Id":"18f4ac219e3f0000","Names":["/floci"],"Image":"floci/floci:latest","State":"running","Status":"Up 2 minutes","Ports":[{"IP":"0.0.0.0","PrivatePort":4566,"PublicPort":4566,"Type":"tcp"}]}]"#;
        let v = parse_json(raw).expect("parse ok");
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].get("Image").and_then(Value::as_str), Some("floci/floci:latest"));
        let ports = arr[0].get("Ports").and_then(Value::as_array).unwrap();
        assert_eq!(ports[0].get("PublicPort").and_then(Value::as_u64), Some(4566));
    }
}
