use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionConfig {
    pub cookie_jar_path: Option<PathBuf>,
    pub csrf_extract_regex: Option<String>,
    pub csrf_injection: CsrfInjectionLocation,
    pub auth_header: Option<String>,
    pub jwt_manipulation: Option<JwtManipulation>,
    pub jwt_signing_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CsrfInjectionLocation {
    #[default]
    Header,
    Query,
    Body,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JwtManipulation {
    StripAlg,
    Hs256WithKey,
    JwkEmbed { jwk: String },
}
