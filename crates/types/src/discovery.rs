use serde::{Deserialize, Serialize};
use crate::injection_context::InjectionContext;
use crate::Method;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: Method,
    pub injection_points: Vec<InjectionPoint>,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InjectionPoint {
    pub name: String,
    pub location: ParameterLocation,
    pub context: InjectionContext,
    pub content_type_hint: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParameterLocation {
    Query,
    Header,
    Path,
    Body,
    Cookie,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoverySource {
    OpenApi,
    GraphQlIntrospection,
    ParamMining,
    HarFile,
}
