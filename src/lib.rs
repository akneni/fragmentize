mod utils;

use std::{
    collections::{HashMap, HashSet},
    mem,
};

// Maps character's ascii codes to their token
const TOKEN_MAPPING: [Option<Token>; 128] = [
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Token::Tab),
    Some(Token::NewLine),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Token::Space),
    Some(Token::Exclamation),
    None,
    Some(Token::HashTag),
    Some(Token::DollarSign),
    Some(Token::ModOperator),
    Some(Token::Ampersand),
    None,
    Some(Token::OpenParen),
    Some(Token::CloseParen),
    Some(Token::Asterisk),
    Some(Token::Plus),
    Some(Token::Comma),
    Some(Token::Minus),
    Some(Token::Period),
    Some(Token::ForwardSlash),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Token::Colon),
    Some(Token::Semicolon),
    Some(Token::LessThan),
    Some(Token::Equal),
    Some(Token::GreaterThan),
    Some(Token::QuestionMark),
    Some(Token::At),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Token::OpenSquareBracket),
    Some(Token::BackSlash),
    Some(Token::CloseSquareBracket),
    Some(Token::Carrot),
    None,
    Some(Token::Tick),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Token::OpenCurlyBrace),
    Some(Token::Pipe),
    Some(Token::CloseCurlyBrace),
    Some(Token::Tilda),
    None,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Token<'a> {
    Object(&'a str),
    Literal(&'a str),
    Comment(&'a str),
    HashTag,
    GreaterThan,
    LessThan,
    Equal,
    Exclamation,
    Period,
    OpenParen,
    CloseParen,
    OpenCurlyBrace,
    CloseCurlyBrace,
    OpenSquareBracket,
    CloseSquareBracket,
    Semicolon,
    Comma,
    Asterisk,
    Plus,
    Minus,
    ForwardSlash,
    BackSlash,
    Pipe,
    Ampersand,
    ModOperator,
    Carrot,
    Colon,
    At,
    DollarSign,
    Tilda,
    Tick,
    QuestionMark,
    NewLine,
    Space,
    Tab,
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OwnedToken {
    Object(String),
    Literal(String),
    Comment(String),
    HashTag,
    GreaterThan,
    LessThan,
    Equal,
    Exclamation,
    Period,
    OpenParen,
    CloseParen,
    OpenCurlyBrace,
    CloseCurlyBrace,
    OpenSquareBracket,
    CloseSquareBracket,
    Semicolon,
    Comma,
    Asterisk,
    Plus,
    Minus,
    ForwardSlash,
    BackSlash,
    Pipe,
    Ampersand,
    ModOperator,
    Carrot,
    Colon,
    At,
    DollarSign,
    Tilda,
    Tick,
    QuestionMark,
    NewLine,
    Space,
    Tab,
}

impl OwnedToken {
    pub fn to_token(&self) -> Token<'_> {
        match self {
            OwnedToken::Object(s) => Token::Object(s),
            OwnedToken::Literal(s) => Token::Literal(s),
            OwnedToken::Comment(s) => Token::Comment(s),

            OwnedToken::HashTag => Token::HashTag,
            OwnedToken::GreaterThan => Token::GreaterThan,
            OwnedToken::LessThan => Token::LessThan,
            OwnedToken::Equal => Token::Equal,
            OwnedToken::Exclamation => Token::Exclamation,
            OwnedToken::Period => Token::Period,
            OwnedToken::OpenParen => Token::OpenParen,
            OwnedToken::CloseParen => Token::CloseParen,
            OwnedToken::OpenCurlyBrace => Token::OpenCurlyBrace,
            OwnedToken::CloseCurlyBrace => Token::CloseCurlyBrace,
            OwnedToken::OpenSquareBracket => Token::OpenSquareBracket,
            OwnedToken::CloseSquareBracket => Token::CloseSquareBracket,
            OwnedToken::Semicolon => Token::Semicolon,
            OwnedToken::Comma => Token::Comma,
            OwnedToken::Asterisk => Token::Asterisk,
            OwnedToken::Plus => Token::Plus,
            OwnedToken::Minus => Token::Minus,
            OwnedToken::ForwardSlash => Token::ForwardSlash,
            OwnedToken::BackSlash => Token::BackSlash,
            OwnedToken::Pipe => Token::Pipe,
            OwnedToken::Ampersand => Token::Ampersand,
            OwnedToken::ModOperator => Token::ModOperator,
            OwnedToken::Carrot => Token::Carrot,
            OwnedToken::Colon => Token::Colon,
            OwnedToken::At => Token::At,
            OwnedToken::DollarSign => Token::DollarSign,
            OwnedToken::Tilda => Token::Tilda,
            OwnedToken::Tick => Token::Tick,
            OwnedToken::QuestionMark => Token::QuestionMark,
            OwnedToken::NewLine => Token::NewLine,
            OwnedToken::Space => Token::Space,
            OwnedToken::Tab => Token::Tab,
        }
    }
}

impl<'a> Token<'a> {
    pub fn tokens_to_string(tokens: &[Token]) -> String {
        let mut string = String::new();

        for &t in tokens.iter() {
            if let Token::Object(s) = t {
                string.push_str(s);
            } else if let Token::Literal(s) = t {
                string.push_str(s);
            } else if let Token::Comment(c) = t {
                string.push_str(c);
            } else {
                for i in 0..TOKEN_MAPPING.len() {
                    if let Some(c) = TOKEN_MAPPING[i] {
                        if c == t {
                            string.push((i as u8) as char);
                            break;
                        }
                    }
                }
            }
        }
        string
    }
}

/// Returns an error if there are any duplicate definitions
/// Otherwise, adds all definitions in `src` to `dst`
pub fn merge_defines<'a>(dst: &mut Vec<&'a [Token<'a>]>, src: &[&'a [Token<'a>]]) -> Result<(), String> {
    let mut dst_set = HashSet::new();

    for &tokens in dst.iter() {
        let s = get_define_name(tokens);
        dst_set.insert(s);
    }

    for &tokens in src.iter() {
        let s = get_define_name(tokens);
        if dst_set.contains(&s) {
            return Err(format!("Duplicate #define definitions for {}", s));
        }
    }

    dst.extend_from_slice(src);

    Ok(())
}

/// Returns an error if there are any duplicate definitions
/// Otherwise, adds all definitions in `src` to `dst`
pub fn merge_includes<'a>(dst: &mut Vec<&'a [Token<'a>]>, src: &[&'a [Token<'a>]]) {
    let mut dst_set = HashSet::new();

    for &tokens in dst.iter() {
        let s = get_include_name(tokens);
        dst_set.insert(s);
    }

    for &tokens in src.iter() {
        let s = get_include_name(tokens);
        if !dst_set.contains(&s) {
            dst.push(tokens);
        }
    }
}

/// Returns an error if there are any duplicate definitions
/// Otherwise, adds all definitions in `src` to `dst`
pub fn merge_udts<'a>(dst: &mut Vec<&'a [Token<'a>]>, src: &[&'a [Token<'a>]]) -> Result<(), String> {
    let mut dst_set = HashSet::new();

    for &tokens in dst.iter() {
        let s = get_udt_name(tokens);
        dst_set.insert(s);
    }

    for &tokens in src.iter() {
        let s = get_udt_name(tokens);
        if dst_set.contains(&s) {
            return Err(format!("Duplicate struct definitions for {}", s));
        }
    }

    dst.extend_from_slice(src);

    Ok(())
}

/// Expects raw source code and an include path (in the form `"../include/filename.h"`)
/// This will do nothing and return `code` if the include statement already exists, otherwise
/// it will insert it at the end of all the include statements
pub fn insert_self_include(code: String, include: &str) -> String {
    let mut code_lines: Vec<&str> = code.lines().collect();

    let contains_include = code_lines.iter().any(|&line| {
        line.trim().starts_with("#") && line.contains("include") && line.contains(include)
    });

    if contains_include {
        return code;
    }

    let mut line_idx: usize = 0;

    for (i, &line) in code_lines.iter().enumerate() {
        let is_include_statement = line.trim().starts_with("#")
            && line.contains("include")
            && (line.contains("<") || line.contains("\""));

        if is_include_statement {
            line_idx = i;
        }
    }

    let include_line = format!("#include {}", include);

    if code_lines.len() == 0 {
        code_lines.push(&include_line);
    } else {
        code_lines.insert(line_idx + 1, &include_line);
    }

    code_lines.join("\n")
}

/// Filters out `#include "XXX.h"` where `file_name` is `"XXX"`
pub fn filter_out_includes<'a>(
    includes: &Vec<&'a [Token]>,
    file_name: &str,
) -> Vec<&'a [Token<'a>]> {
    let include_str_name = [
        format!("{}.h\"", file_name),
        format!("/{}.h\"", file_name),
        format!("\\{}.h\"", file_name),
    ];

    includes
        .clone()
        .into_iter()
        .filter(|&x| {
            if let Some(Token::Literal(s)) = x.last() {
                if s == &include_str_name[0] {
                    return false;
                } else if include_str_name[1..]
                    .iter()
                    .any(|inc_name| s.ends_with(inc_name))
                {
                    return false;
                }
            }

            true
        })
        .collect()
}

/// Passing the below list to this function would return `3` (gets the next token, not the current token)
/// `[object-token-curr, whitespace, whitespace, object-token-next]`
#[inline]
pub fn next_non_whitespace_token(tokens: &[Token]) -> usize {
    let mut idx = 1;
    while idx < tokens.len()
        && matches!(
            tokens[idx],
            Token::Space | Token::Tab | Token::NewLine | Token::Comment(_)
        )
    {
        idx += 1;
    }

    idx
}


pub fn tokenize<'a>(code: &'a str) -> Result<Vec<Token<'a>>, String> {
    let code_bytes = code.as_bytes();
    let mut tokens = Vec::with_capacity(4096);

    let mut idx: usize = 0;
    while idx < code.len() {
        match code_bytes[idx] as char {
            ' ' => {
                tokens.push(Token::Space);
                idx += 1;
                continue;
            }
            '\t' => {
                tokens.push(Token::Tab);
                idx += 1;
                continue;
            }
            '\n' => {
                tokens.push(Token::NewLine);
                idx += 1;
                continue;
            }
            '"' => {
                let len = find_len_string_literal(&code_bytes[idx..])?;

                let val = &code[idx..(idx + len)];
                let tok = Token::Literal(val);
                tokens.push(tok);
                idx += len;
                continue;
            }
            '\'' => {
                let len = find_len_char_literal(&code_bytes[idx..])?;

                let val = &code[idx..(idx + len)];
                let tok = Token::Literal(val);
                tokens.push(tok);
                idx += len;
                continue;
            }
            '/' => {
                if matches!(code_bytes[idx + 1] as char, '*' | '/') {
                    let len = find_len_comment(&code_bytes[idx..]);
                    let val = &code[idx..(idx + len)];
                    let tok = Token::Comment(val);
                    tokens.push(tok);
                    idx += len;
                    continue;
                }
            }
            _ => {}
        }

        if let Some(sym) = is_symbol(&code[idx..]) {
            tokens.push(sym);
            idx += 1;
            continue;
        }
        let new_idx = find_len_object(code_bytes, idx);
        let val = &code[idx..new_idx];
        let tok = Token::Object(val);
        tokens.push(tok);
        idx = new_idx;
    }

    Ok(tokens)
}

#[inline]
fn is_symbol<'a>(code: &'a str) -> Option<Token<'a>> {
    let char = code.chars().next();
    if let Some(char) = char {
        let char_code = char as usize;
        if char_code > TOKEN_MAPPING.len() {
            return None;
        }
        return TOKEN_MAPPING[char_code];
    }
    None
}

fn find_len_object(code_bytes: &[u8], mut curr_idx: usize) -> usize {
    curr_idx += 1;
    while curr_idx < code_bytes.len() {
        let ascii_char = code_bytes[curr_idx] as usize;
        if ascii_char < TOKEN_MAPPING.len() {
            if TOKEN_MAPPING[ascii_char].is_some() || ascii_char == ' ' as usize {
                return curr_idx;
            }
        }
        curr_idx += 1;
    }
    return curr_idx;
}

/// `code_bytes` must be a slice such that the start of the slice is the same as the start of the string (first character must be a `"`)
fn find_len_string_literal(code_bytes: &[u8]) -> Result<usize, String> {
    let mut idx: usize = 1;
    while idx < code_bytes.len() {
        if code_bytes[idx] == '\n' as u8 && code_bytes[idx-1] != '\\' as u8 {
            break;
        }
        if code_bytes[idx] == '"' as u8 && code_bytes[idx-1] != '\\' as u8  {
            idx += 1;
            return Ok(idx);
        }
        idx += 1;
    }
    let curr_str = String::from_utf8(code_bytes[..30].to_vec()).unwrap();
    Err(format!("String literal not closed: `{}`", curr_str))
}

/// `code_bytes` must be a slice such that the start of the slice is the same as the start of the string (first character must be a `'`)
fn find_len_char_literal(code_bytes: &[u8]) -> Result<usize, String> {
    let mut idx: usize = 1;
    while idx < code_bytes.len() {
        if code_bytes[idx] == '\'' as u8 && code_bytes[idx-1] != '\\' as u8{
            idx += 1;
            return Ok(idx);            
        }
        idx += 1;
    }
    let curr_line = String::from_utf8(code_bytes[..15].to_vec()).unwrap();
    Err(format!("Character literal not closed: `{}`", curr_line))
}

/// `code_bytes` must be a slice such that the start of the slice is the same as the start of the comment (first characters must be `//` or `/*`)
fn find_len_comment(code_bytes: &[u8]) -> usize {
    #[cfg(debug_assertions)]
    {
        if code_bytes[0] != '/' as u8 || !(matches!(code_bytes[1] as char, '*' | '/')) {
            panic!("Not a comment");
        }
    }

    let mut idx = 2;
    match code_bytes[1] as char {
        '*' => {
            while idx < code_bytes.len() {
                if code_bytes[idx] == '*' as u8 && code_bytes[idx + 1] == '/' as u8 {
                    idx += 2;
                    break;
                }
                idx += 1;
            }
        }
        '/' => {
            while idx < code_bytes.len() && code_bytes[idx] != '\n' as u8 {
                idx += 1;
            }
        }
        _ => unsafe { std::hint::unreachable_unchecked() },
    }

    idx
}

/// Reconstructs the soruce code excluding the ranges specified
pub fn reconstruct_source(tokens: &[Token], exclude_ranges: &[&[Token]]) -> String {
    let mut new_tokens = vec![];

    let mut exlcude_map: HashMap<&[Token], Vec<&[Token]>> = HashMap::new();

    for &range in exclude_ranges {
        if range.len() < 3 {
            unreachable!();
        }

        let entry = exlcude_map.entry(&range[0..3]).or_default();
        entry.push(range);
    }

    let mut idx = 0;

    while idx < tokens.len() {
        if idx + 3 >= tokens.len() {
            new_tokens.push(tokens[idx]);
            idx += 1;
            continue;
        }

        if let Some(vec) = exlcude_map.get(&tokens[idx..(idx + 3)]) {
            let mut skip_len = 0;

            for &range in vec {
                if range.len() > tokens[idx..].len() {
                    continue;
                }
                if range == &tokens[idx..(idx + range.len())] {
                    skip_len = range.len();
                    break;
                }
            }

            if skip_len > 0 {
                idx += skip_len;
                continue;
            }
        }

        new_tokens.push(tokens[idx]);
        idx += 1;
    }

    Token::tokens_to_string(&new_tokens)
}


// If there's a preceding comment, it will include it
// Extracts function declarations and definitions
pub fn get_fn_def<'a>(tokens: &'a Vec<Token>) -> Vec<&'a [Token<'a>]> {
    let mut fn_defs = vec![];
    let mut idx: usize = 0;
    
    while idx < tokens.len() {
        let mut next_idx = idx;
        
        // Skip comments (but we'll look back for them when we find a function)
        if let Token::Comment(_) = tokens[idx] {
            utils::skip_to_end_comment(tokens, &mut next_idx);
            if next_idx >= tokens.len() {
                break;
            }
        }

        if let Token::Object(obj) = tokens[next_idx] {
            // Skip control flow keywords
            if matches!(obj, "for" | "while" | "if" | "switch") {
                utils::skip_to(tokens, Token::CloseParen, &mut next_idx);
                idx = next_idx;
                continue;
            } else if obj == "include" {
                utils::skip_to_oneof(
                    tokens,
                    &[Token::GreaterThan, Token::Literal("\"")],
                    &mut next_idx,
                );
                idx = next_idx;
                continue;
            } else if obj == "define" {
                utils::skip_to(tokens, Token::NewLine, &mut next_idx);
                idx = next_idx;
                continue;
            } else if matches!(obj, "return") {
                idx = next_idx + 1;
                continue;
            }

            let start_idx = next_idx;
            let mut has_open_paren = false;
            let mut has_close_paren = false;
            let mut objects_before_paren = 0;
            let mut paren_start = 0;
            
            let mut j = next_idx;
            while j < tokens.len() {
                match &tokens[j] {
                    Token::Object(_) => {
                        if !has_open_paren {
                            objects_before_paren += 1;
                        }
                    }
                    Token::OpenParen => {
                        if !has_open_paren {
                            paren_start = j;
                        }
                        has_open_paren = true;
                    }
                    Token::CloseParen => {
                        has_close_paren = true;
                    }
                    Token::OpenCurlyBrace | Token::Semicolon => {
                        // Function definition (with body) or declaration (without body)
                        if has_open_paren && has_close_paren 
                            && is_likely_function(&tokens[start_idx..j], objects_before_paren, paren_start - start_idx) {
                            // Look backward for any preceding comments
                            let actual_start = utils::find_preceding_comment_start(tokens, start_idx);
                            fn_defs.push(&tokens[actual_start..j]);
                        }
                        break;
                    }
                    Token::Equal => {
                        // Variable assignment, not a function
                        break;
                    }
                    _ => {}
                }
                j += 1;
            }
            idx = j + 1;
            continue;
        }
        idx += 1;
    }

    fn_defs
}

pub fn get_includes<'a>(tokens: &'a Vec<Token>) -> Vec<&'a [Token<'a>]> {
    let mut includes = vec![];

    let mut idx: usize = 0;
    while idx < tokens.len() {
        let mut next_idx = idx;
        if let Token::Comment(_) = tokens[next_idx] {
            utils::skip_to_end_comment(tokens, &mut next_idx);
            if next_idx >= tokens.len() {
                break;
            }
        }

        if next_idx >= tokens.len() {
            break;
        }

        if let Token::HashTag = tokens[next_idx] {
            let next_nwt = next_non_whitespace_token(&tokens[next_idx..]);
            if tokens[next_idx + next_nwt] != Token::Object("include") {
                idx += next_nwt;
                continue;
            }

            let mut end = next_idx + next_nwt;
            utils::skip_to_oneof(tokens, &[Token::GreaterThan, Token::Literal("")], &mut end);

            includes.push(&tokens[idx..(end + 1)]);
            idx = end + 1;
        } else {
            idx += 1;
        }
    }

    includes
}

/// Extracts the user defined types (UDTs)
pub fn get_udts<'a>(tokens: &'a Vec<Token>) -> Vec<&'a [Token<'a>]> {
    let mut udts = vec![];
    if tokens.len() < 3 {
        return udts;
    }

    let mut idx: usize = 0;
    while idx < tokens.len() - 2 {
        let start_idx = idx;

        if let Token::Comment(_) = tokens[idx] {
            utils::skip_to_end_comment(tokens, &mut idx);
        }

        if let Token::Object(obj) = tokens[idx] {
            if !matches!(obj, "typedef" | "struct" | "union" | "enum") {
                idx += 1;
                continue;
            }

            let next_idx = if obj == "typedef" {
                let x = idx + next_non_whitespace_token(&tokens[idx..]);
                if x >= tokens.len() {
                    unreachable!();
                }
                x
            } else {
                idx
            };

            let mut conditions = [
                false, // Contains at least one set of curly braces
                true,  // Contains no `=` characters
            ];
            match tokens[next_idx] {
                Token::Object("struct") | Token::Object("enum") | Token::Object("union") => {
                    idx = next_idx;
                    let mut curlybrace_stack = 0;

                    while idx < tokens.len() {
                        match tokens[idx] {
                            Token::OpenCurlyBrace => curlybrace_stack += 1,
                            Token::CloseCurlyBrace => {
                                if curlybrace_stack == 0 {
                                    unreachable!();
                                }

                                conditions[0] = true;
                                curlybrace_stack -= 1;
                            }
                            Token::Semicolon => {
                                if curlybrace_stack == 0 {
                                    if conditions.iter().all(|&i| i) {
                                        let x = &tokens[start_idx..=idx];
                                        udts.push(x);
                                    }
                                    break;
                                }
                            }
                            Token::Equal => conditions[1] = false,
                            _ => {}
                        }
                        idx += 1;
                    }
                }
                _ => {
                    idx = next_idx;
                }
            }
        } else {
            idx += 1;
        }
    }

    udts
}

pub fn get_defines<'a>(tokens: &'a Vec<Token>) -> Vec<&'a [Token<'a>]> {
    let mut defines = vec![];

    let mut idx: usize = 0;

    while idx < tokens.len() {
        if tokens[idx] != Token::HashTag
            && mem::discriminant(&tokens[idx]) != mem::discriminant(&Token::Comment(""))
        {
            let valid_prefixes = &[Token::HashTag, Token::Comment("")];
            utils::skip_to_oneof(tokens, valid_prefixes, &mut idx);
        }

        let start_idx = idx;

        if let Token::Comment(_) = tokens[idx] {
            utils::skip_to_end_comment(tokens, &mut idx);
        }

        if idx + 1 >= tokens.len() || tokens[idx + 1] != Token::Object("define") {
            idx += 2;
            continue;
        }
        idx += 1;

        utils::skip_to(tokens, Token::NewLine, &mut idx);
        while idx < tokens.len() && tokens[idx - 1] == Token::BackSlash {
            utils::skip_to(tokens, Token::NewLine, &mut idx);
        }

        defines.push(&tokens[start_idx..idx]);
    }

    defines
}

/// Gets the name of a function
pub fn get_fn_name<'a>(tokens: &'a [Token]) -> Option<&'a str >{
    let mut num_closed_paren = 0;

    for i in (0..tokens.len()).rev() {
        match tokens[i] {
            Token::CloseParen => {
                num_closed_paren += 1;
            }
            Token::OpenParen => {
                num_closed_paren -= 1;
                if num_closed_paren == 0 {
                    for j in (0..i).rev() {
                        if let Token::Object(s) = tokens[j] {
                            return Some(s);
                        }
                    }
                }
            }
            _ => {},
        }
    }

    None
}

/// Gets the name of the struct
/// Ex) for `struct Point {...}`, this would return "Point"
pub fn get_udt_name<'a>(tokens: &'a [Token]) -> &'a str {
    if tokens.len() < 3 {
        unreachable!("Token string is not a valid user defined type definition");
    }

    let mut idx = 0;
    let mut num_unclosed_braces = 0;

    while idx < tokens.len() {
        match tokens[idx] {
            Token::Object("struct") | Token::Object("enum") | Token::Object("union") => {
                let next_idx = idx + next_non_whitespace_token(&tokens[idx..]);

                if next_idx + 1 >= tokens.len() {
                    unreachable!("Invalid UDT (1)");
                }
                if let Token::Object(obj) = tokens[next_idx] {
                    return obj;
                }
            }
            Token::OpenCurlyBrace => num_unclosed_braces += 1,
            Token::CloseCurlyBrace => {
                if num_unclosed_braces == 0 {
                    unreachable!("Invalid UDT (unmatched close curly brace)");
                }

                num_unclosed_braces -= 1;

                if num_unclosed_braces == 0 {
                    let next_idx = idx + next_non_whitespace_token(&tokens[idx..]);
                    if next_idx + 1 >= tokens.len() {
                        unreachable!("Invalid UDT (2)");
                    }

                    if let Token::Object(obj) = tokens[next_idx] {
                        return obj;
                    }
                }
            }
            _ => {}
        }
        idx += 1;
    }

    unreachable!("Invalid UDT (end)");
}

/// Gets the name of the define statement
/// Ex) for `#define FOO 42`, this would return "FOO"
pub fn get_define_name<'a>(tokens: &'a [Token]) -> &'a str {
    let mut idx = 0;
    if let Token::Comment(_) = tokens[idx] {
        utils::skip_to_end_comment(tokens, &mut idx);
    }

    if tokens.len() < 5 || tokens[idx] != Token::HashTag {
        unreachable!("Token string is not a valid define macro (1)");
    }

    let mut define_seen = false;

    for &t in &tokens[(idx + 1)..] {
        match t {
            Token::Object("define") => {
                if define_seen {
                    unreachable!("Token string is not a valid define macro (2)");
                }
                define_seen = true;
            }
            Token::Object(obj) => {
                if define_seen {
                    return obj;
                } else {
                    unreachable!("Token string is not a valid define macro (3)");
                }
            }
            _ => {}
        }
    }

    unreachable!("Token string is not a valid define macro (4)");
}

pub fn get_include_name<'a>(tokens: &'a [Token]) -> String {
    let mut idx = 0;
    if let Token::Comment(_) = tokens[idx] {
        utils::skip_to_end_comment(tokens, &mut idx);
    }

    assert!(tokens[0] == Token::HashTag);

    let target_tok = [Token::LessThan, Token::Literal("")];
    utils::skip_to_oneof(tokens, &target_tok, &mut idx);

    match tokens[idx] {
        Token::LessThan => {
            let mut end_idx = idx;
            utils::skip_to(tokens, Token::GreaterThan, &mut end_idx);

            return Token::tokens_to_string(&tokens[(idx + 1)..end_idx]);
        }
        Token::Literal(s) => {
            return s.trim_end_matches('"').to_string();
        }
        _ => unreachable!(),
    }
}

// Heuristic to determine if token sequence is likely a function
pub fn is_likely_function(tokens: &[Token], objects_before_paren: usize, paren_start: usize) -> bool {
    // Need at least 2 objects (return type + function name)
    if objects_before_paren < 2 {
        return false;
    }
    
    // Check for type keywords before the parenthesis (strong signal)
    let has_type_keyword = tokens[..paren_start].iter().any(|tok| {
        if let Token::Object(obj) = tok {
            matches!(
                *obj,
                "void" | "int" | "char" | "float" | "double" | "long" 
                | "short" | "unsigned" | "signed" | "struct" | "union" 
                | "enum" | "static" | "extern" | "inline" | "const"
                | "volatile" | "register" | "auto" | "restrict" | "_Noreturn"
            )
        } else {
            false
        }
    });
    
    if has_type_keyword {
        return true;
    }
    
    // Check inside parameters for type keywords or "type name" patterns
    let param_has_types = utils::has_type_keywords_in_params(tokens);
    if param_has_types {
        return true;
    }
    
    // Check for operators inside parens (suggests function call, not declaration)
    let has_operators_in_params = utils::has_operators_in_params(tokens);
    if has_operators_in_params {
        return false;
    }
    
    // Default: if we have 2+ objects before paren, assume it's a function
    true
}

#[cfg(test)]
mod lexer_tests {
    use std::fs;

    use super::*;

    #[test]
    fn test_get_defines() {
        let s = fs::read_to_string("tests/lexer-define.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let defines = get_defines(&tokens);

        let mut log_dump = "".to_string();
        for &def in &defines {
            let x = format!("{:?}\n\n", def);
            log_dump.push_str(&x);
        }

        fs::write("tests/lexer.test_get_defines.log", format!("{}", log_dump)).unwrap();

        assert_eq!(
            defines.len(),
            s.split("#define").collect::<Vec<&str>>().len() - 1
        );
    }

    #[test]
    fn test_get_udts() {
        let s = fs::read_to_string("tests/lexer-UDT.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let defines = get_udts(&tokens);

        let mut log_dump = "".to_string();
        for &def in &defines {
            let x = format!("{:?}\n\n", def);
            log_dump.push_str(&x);
        }

        fs::write("tests/lexer.test_get_udts.log", format!("{}", log_dump)).unwrap();
    }

    #[test]
    fn test_get_define_name() {
        let s = fs::read_to_string("tests/lexer-define.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let defines = get_defines(&tokens);

        let mut names = vec![];
        for &d in &defines {
            names.push(get_define_name(d));
        }

        assert_eq!(
            defines.len(),
            s.split("#define").collect::<Vec<&str>>().len() - 1
        );

        fs::write(
            "tests/lexer.test_get_define_name.log",
            format!("{:#?}", names),
        )
        .unwrap();
    }

    #[test]
    fn test_get_udt_name() {
        let s = fs::read_to_string("tests/lexer-UDT.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let structs = get_udts(&tokens);

        let mut names = vec![];
        for &d in &structs {
            names.push(get_udt_name(d));
        }

        let mut dump = "".to_string();

        for (i, n) in names.into_iter().enumerate() {
            dump.push_str(&format!("{}) {}\n", i + 1, n));
        }

        fs::write("tests/lexer.test_get_udt_name.log", format!("{}", dump)).unwrap();
    }

    #[test]
    fn test_get_fn_def() {
        let s = fs::read_to_string("tests/lexer-fn-def.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let fn_defs = get_fn_def(&tokens);

        let mut log_dump = "".to_string();
        for &def in &fn_defs {
            let x = format!("{:?}\n\n", def);
            log_dump.push_str(&x);
        }

        fs::write("tests/lexer.test_get_fn_def.log", format!("{}", log_dump)).unwrap();

        assert_eq!(fn_defs.len(), 21);
    }

    #[test]
    fn test_get_fn_name() {
        let s = fs::read_to_string("tests/lexer-fn-def.c").unwrap();
        let tokens = tokenize(&s).unwrap();

        let fn_defs = get_fn_def(&tokens);

        let mut log_dump = "".to_string();
        for &def in &fn_defs {
            let name = get_fn_name(def).unwrap();
            log_dump.push_str(name);
            log_dump.push('\n');

        }

        fs::write("tests/lexer.test_get_fn_name.log", format!("{}", log_dump)).unwrap();

        assert_eq!(fn_defs.len(), 21);
    }
}
