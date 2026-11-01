//! Provenance for the built-in deterministic assistance, never model inference.

use serde::Serialize;

pub const BACKEND: &str = "rust_stub";
pub const MODEL_ID: &str = "iscy-rust-llm-stub-v1";
pub const ASSESSMENT_STATUS: &str = "STUB_GENERATED";

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StubProvenance {
    pub schema_version: u32,
    pub generation_method: &'static str,
    pub generator_id: &'static str,
    pub inference_performed: bool,
    pub model_configuration_applied: bool,
    pub requires_human_review: bool,
}

pub const fn provenance() -> StubProvenance {
    StubProvenance {
        schema_version: 1,
        generation_method: "deterministic_stub",
        generator_id: MODEL_ID,
        inference_performed: false,
        model_configuration_applied: false,
        requires_human_review: true,
    }
}
