// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str;
use std::vec::Vec;
use strum::AsRefStr;

#[derive(AsRefStr)]
enum ErrorInfo {
    #[strum(serialize = "invalid operator")]
    InvalidOp,

    #[strum(serialize = "annotation cannot be empty")]
    _AnnotationEmpty,

    #[strum(serialize = "missing operator")]
    MissingOp,

    #[strum(serialize = "unsupported operator")]
    UnsupportedOp,

    #[strum(serialize = "keyunwrap parameters must include annotation")]
    UnwrapParamsNoAnnotation,

    #[strum(serialize = "keyunwrap parameters must include Dc")]
    UnwrapParamsNoDc,

    #[strum(serialize = "keywrap parameters should not include Ec")]
    WrapParamsExpectEmptyEc,

    #[strum(serialize = "keywrap parameters should not include optsdata")]
    WrapParamsExpectEmptyOptsdata,
}

pub const OP_KEY_UNWRAP: &str = "keyunwrap";
pub const OP_KEY_WRAP: &str = "keywrap";

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyProviderInput {
    // Operation is either "keywrap" or "keyunwrap"
    // attestation-agent can only handle the case of "keyunwrap"
    op: String,
    // For attestation-agent, keywrapparams should be empty.
    pub keywrapparams: KeyWrapParams,
    pub keyunwrapparams: KeyUnwrapParams,
}

impl KeyProviderInput {
    pub fn valid(&self) -> Result<()> {
        match self.op.as_str() {
            OP_KEY_WRAP => bail!(
                "{}: {:?}: {}",
                ErrorInfo::UnsupportedOp.as_ref(),
                self.op,
                "use a different key provider to encrypt images"
            ),
            OP_KEY_UNWRAP => Ok(()),
            "" => Err(anyhow!(ErrorInfo::MissingOp.as_ref())),
            _ => Err(anyhow!("{}: {:?}", ErrorInfo::InvalidOp.as_ref(), self.op)),
        }?;

        self.keywrapparams.valid()?;
        self.keyunwrapparams.valid()?;

        Ok(())
    }

    pub fn with_op(self, op: String) -> Self {
        KeyProviderInput { op, ..self }
    }

    pub fn with_key_wrap_params(self, params: KeyWrapParams) -> Self {
        KeyProviderInput {
            keywrapparams: params,
            ..self
        }
    }

    pub fn with_key_unwrap_params(self, params: KeyUnwrapParams) -> Self {
        KeyProviderInput {
            keyunwrapparams: params,
            ..self
        }
    }
}

impl TryFrom<Vec<u8>> for KeyProviderInput {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let input_string = String::from_utf8(bytes)?;

        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)?;

        input.valid()?;

        Ok(input)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyWrapParams {
    // For attestation-agent, ec is null
    pub ec: Option<Ec>,
    // For attestation-agent, optsdata is null
    pub optsdata: Option<String>,
}

impl KeyWrapParams {
    pub fn valid(&self) -> Result<()> {
        let ec_empty = if let Some(ec) = self.ec.clone() {
            ec.empty()
        } else {
            true
        };

        if !ec_empty {
            return Err(anyhow!(ErrorInfo::WrapParamsExpectEmptyEc.as_ref()));
        }

        let optsdata_empty = if let Some(ref optsdata) = self.optsdata {
            optsdata.is_empty()
        } else {
            true
        };

        if !optsdata_empty {
            return Err(anyhow!(ErrorInfo::WrapParamsExpectEmptyOptsdata.as_ref()));
        }

        Ok(())
    }

    pub fn with_ec(self, ec: Ec) -> Self {
        KeyWrapParams {
            ec: Some(ec),
            ..self
        }
    }

    pub fn with_opts_data(self, data: String) -> Self {
        KeyWrapParams {
            optsdata: Some(data),
            ..self
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct Ec {
    #[serde(rename = "Parameters")]
    pub parameters: HashMap<String, Vec<String>>,
    #[serde(rename = "DecryptConfig")]
    pub decrypt_config: Dc,
}

impl Ec {
    pub fn empty(self) -> bool {
        self.parameters.is_empty() && self.decrypt_config.empty()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyUnwrapParams {
    pub dc: Option<Dc>,
    pub annotation: Option<String>,
}

impl KeyUnwrapParams {
    pub fn valid(&self) -> Result<()> {
        // "empty" means "not defined" or "not set"
        let dc_empty = if let Some(dc) = self.dc.clone() {
            dc.empty()
        } else {
            true
        };

        if dc_empty {
            return Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref()));
        }

        let annotation_empty = if let Some(ref annotation) = self.annotation {
            annotation.is_empty()
        } else {
            true
        };

        if annotation_empty {
            return Err(anyhow!(ErrorInfo::UnwrapParamsNoAnnotation.as_ref()));
        }

        Ok(())
    }

    pub fn with_dc(self, dc: Dc) -> Self {
        KeyUnwrapParams {
            dc: Some(dc),
            ..self
        }
    }

    pub fn with_base64_annotation(self, base64_annotation: String) -> Self {
        KeyUnwrapParams {
            annotation: Some(base64_annotation),
            ..self
        }
    }

    pub fn with_annotation(self, annotation: String) -> Self {
        self.with_base64_annotation(base64::engine::general_purpose::STANDARD.encode(annotation))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct Dc {
    // Name is expected to be AGENT_NAME.
    // Values are expected to be base-64 encoded.
    #[serde(rename = "Parameters")]
    pub parameters: HashMap<String, Vec<String>>,
}

impl Dc {
    pub fn empty(self) -> bool {
        self.parameters.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapOutput {
    pub keywrapresults: KeyWrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapResults {
    pub annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapOutput {
    pub keyunwrapresults: KeyUnwrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapResults {
    pub optsdata: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(None, None, Ok(()))]
    #[case(Some(Ec::default()), Some("".into()), Ok(()))]
    #[case(None, Some("foo".into()), Err(anyhow!("{}", ErrorInfo::WrapParamsExpectEmptyOptsdata.as_ref())))]
    #[case(Some(Ec::default()), None, Ok(()))]
    #[case(Some(Ec::default()), Some("foo".into()), Err(anyhow!("{}", ErrorInfo::WrapParamsExpectEmptyOptsdata.as_ref())))]
    #[case(None, Some("".into()), Ok(()))]
    fn test_key_wrap_params_valid(
        #[case] ec: Option<Ec>,
        #[case] opts: Option<String>,
        #[case] result: Result<()>,
    ) {
        // Create a string containing details of the test
        let mut params = KeyWrapParams::default();

        if let Some(ec) = ec {
            params = params.with_ec(ec);
        }

        if let Some(opts) = opts {
            params = params.with_opts_data(opts);
        }

        let res = params.valid();

        assert_eq!(format!("{res:?}"), format!("{result:?}"));
    }

    #[rstest]
    #[case(None, None, Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())))]
    #[case(Some(Dc::default()), None, Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())))]
    #[case(None, Some("".into()), Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())))]
    #[case(Some(Dc { parameters: HashMap::from([("attestation-agent".into(), vec![base64::engine::general_purpose::STANDARD.encode("kbc-name::kbs-uri")])])}), None, Err(anyhow!(ErrorInfo::UnwrapParamsNoAnnotation.as_ref())))]
    #[case(Some(Dc { parameters: HashMap::from([("attestation-agent".into(), vec![base64::engine::general_purpose::STANDARD.encode("kbc-name::kbs-uri")])])}), Some("".into()), Err(anyhow!(ErrorInfo::UnwrapParamsNoAnnotation.as_ref())))]
    #[case(Some(Dc { parameters: HashMap::from([("attestation-agent".into(), vec![base64::engine::general_purpose::STANDARD.encode("kbc-name::kbs-uri")])])}), Some("foo".into()), Ok(()))]
    fn test_key_unwrap_params_valid(
        #[case] dc: Option<Dc>,
        #[case] annotation: Option<String>,
        #[case] result: Result<()>,
    ) {
        // Create a string containing details of the test
        let mut params = KeyUnwrapParams::default();

        if let Some(dc) = dc {
            params = params.with_dc(dc);
        }

        if let Some(an) = annotation {
            params = params.with_annotation(an);
        }

        let res = params.valid();

        assert_eq!(format!("{res:?}"), format!("{result:?}"));
    }

    #[rstest]
    #[case(b"", Err(anyhow!("EOF while parsing a value at line 1 column 0")))]
    #[case(b"foobar", Err(anyhow!("expected ident at line 1 column 2")))]
    #[case(b"{\"op\":\"\",\"keywrapparams\":{},\"keyunwrapparams\":{}}", Err(anyhow!(ErrorInfo::MissingOp.as_ref())))]
    #[case(b"{\"op\":\"invalid\",\"keywrapparams\":{},\"keyunwrapparams\":{}}", Err(anyhow!(
        "{}: \"invalid\"",
        ErrorInfo::InvalidOp.as_ref(),
    )))]
    #[case(b"{\"op\":\"keywrap\",\"keywrapparams\":{},\"keyunwrapparams\":{}}", Err(anyhow!(
        "{}: \"keywrap\": use a different key provider to encrypt images",
        ErrorInfo::UnsupportedOp.as_ref(),
    )))]
    #[case(b"{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{}}", Err(anyhow!(
        "{}",
        ErrorInfo::UnwrapParamsNoDc.as_ref(),
    )))]
    #[case(b"{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{\"dc\":{\"Parameters\":{\"foo\":[\"bar\",\"baz\"]}},\"annotation\":\"annotation\"}}", Ok(()))]
    fn test_key_provider_input(#[case] input: &[u8], #[case] result: Result<()>) {
        let res = KeyProviderInput::try_from(input.to_vec());
        println!("{res:?}");
        assert_eq!(res.is_ok(), result.is_ok());
        if result.is_err() {
            assert_eq!(format!("{:?}", result.err()), format!("{:?}", res.err()));
        }
    }
}
