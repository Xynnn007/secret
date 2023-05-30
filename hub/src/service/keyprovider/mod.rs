// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str;
use std::vec::Vec;

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
    use super::*;

    #[test]
    fn test_key_wrap_params_valid() {
        #[derive(Debug)]
        struct TestData {
            ec: Option<Ec>,
            opts: Option<String>,
            result: Result<()>,
        }

        let tests = &[
            TestData {
                ec: None,
                opts: None,
                result: Ok(()),
            },
            TestData {
                ec: Some(Ec::default()),
                opts: Some("".into()),
                result: Ok(()),
            },
            TestData {
                ec: None,
                opts: Some("foo".into()),
                result: Err(anyhow!("{}", ErrorInfo::WrapParamsExpectEmptyOptsdata.as_ref())),
            },
            TestData {
                ec: Some(Ec::default()),
                opts: None,
                result: Ok(()),
            },
            TestData {
                ec: Some(Ec::default()),
                opts: Some("foo".into()),
                result: Err(anyhow!("{}", ErrorInfo::WrapParamsExpectEmptyOptsdata.as_ref())),
            },
            TestData {
                ec: None,
                opts: Some("".into()),
                result: Ok(()),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let mut params = KeyWrapParams::default();

            if let Some(ec) = d.ec.clone() {
                params = params.with_ec(ec);
            }

            if let Some(opts) = d.opts.clone() {
                params = params.with_opts_data(opts);
            }

            let result = params.valid();

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_key_unwrap_params_valid() {
        #[derive(Debug)]
        struct TestData {
            dc: Option<Dc>,
            annotation: Option<String>,
            result: Result<()>,
        }

        let kbc_name = "kbc-name";
        let kbs_uri = "kbs-uri";

        let annotation_value = format!("{}::{}", kbc_name, kbs_uri);

        let annotation_base64 = base64::engine::general_purpose::STANDARD.encode(annotation_value);

        let mut valid_dc: Dc = Dc::default();
        valid_dc
            .parameters
            .insert("attestation-agent".into(), vec![annotation_base64]);

        let tests = &[
            TestData {
                dc: None,
                annotation: None,
                result: Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())),
            },
            TestData {
                dc: Some(Dc::default()),
                annotation: None,
                result: Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())),
            },
            TestData {
                dc: None,
                annotation: Some("".into()),
                result: Err(anyhow!(ErrorInfo::UnwrapParamsNoDc.as_ref())),
            },
            TestData {
                dc: Some(valid_dc.clone()),
                annotation: None,
                result: Err(anyhow!(ErrorInfo::UnwrapParamsNoAnnotation.as_ref())),
            },
            TestData {
                dc: Some(valid_dc.clone()),
                annotation: Some("".into()),
                result: Err(anyhow!(ErrorInfo::UnwrapParamsNoAnnotation.as_ref())),
            },
            TestData {
                dc: Some(valid_dc.clone()),
                annotation: Some("foo".into()),
                result: Ok(()),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let mut params = KeyUnwrapParams::default();

            if let Some(dc) = d.dc.clone() {
                params = params.with_dc(dc);
            }

            if let Some(an) = d.annotation.clone() {
                params = params.with_annotation(an);
            }

            let result = params.valid();

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_key_provider_input() {
        #[derive(Debug)]
        struct TestData {
            input: Vec<u8>,
            result: Result<KeyProviderInput>,
        }

        let serde_eof_error = "EOF while parsing a value at line 1 column 0";

        let default_input = KeyProviderInput::default();
        let default_key_unwrap_params = KeyUnwrapParams::default();

        let default_serialised = serde_json::to_string(&default_input).unwrap();

        let invalid_op = "invalid";
        let input_invalid_op = default_input.clone().with_op(invalid_op.into());
        let invalid_op_serialised = serde_json::to_string(&input_invalid_op).unwrap();

        let unsupported_op = OP_KEY_WRAP;
        let input_unsupported_op = default_input.clone().with_op(unsupported_op.into());
        let unsupported_op_serialised = serde_json::to_string(&input_unsupported_op).unwrap();

        let supported_op = OP_KEY_UNWRAP;

        let input_op_no_unwrap_params = default_input.clone().with_op(supported_op.into());
        let op_no_unwrap_params_serialised =
            serde_json::to_string(&input_op_no_unwrap_params).unwrap();

        let input_op_with_empty_unwrap_params = default_input
            .with_op(supported_op.into())
            .with_key_unwrap_params(default_key_unwrap_params);

        let op_with_empty_unwrap_params_serialised =
            serde_json::to_string(&input_op_with_empty_unwrap_params).unwrap();

        let mut valid_dc: Dc = Dc::default();

        valid_dc
            .parameters
            .insert("foo".into(), vec!["bar".into(), "baz".into()]);

        let valid_key_unwrap_params = KeyUnwrapParams::default()
            .with_dc(valid_dc)
            .with_annotation("annotation".into());

        // valid input
        let valid_key_provider_input = KeyProviderInput::default()
            .with_op("keyunwrap".into())
            .with_key_unwrap_params(valid_key_unwrap_params);

        let valid_serialised = serde_json::to_string(&valid_key_provider_input).unwrap();
        let tests = &[
            TestData {
                input: Vec::<u8>::new(),
                result: Err(anyhow!(serde_eof_error)),
            },
            TestData {
                input: "".as_bytes().to_vec(),
                result: Err(anyhow!(serde_eof_error)),
            },
            TestData {
                input: "foo bar".as_bytes().to_vec(),
                result: Err(anyhow!("expected ident at line 1 column 2")),
            },
            TestData {
                input: default_serialised.as_bytes().to_vec(),
                result: Err(anyhow!(ErrorInfo::MissingOp.as_ref())),
            },
            TestData {
                input: invalid_op_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}: {:?}", ErrorInfo::InvalidOp.as_ref(), invalid_op)),
            },
            TestData {
                input: unsupported_op_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}: {:?}", ErrorInfo::UnsupportedOp.as_ref(), unsupported_op)),
            },
            TestData {
                input: op_no_unwrap_params_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}", ErrorInfo::UnwrapParamsNoDc.as_ref())),
            },
            TestData {
                input: op_with_empty_unwrap_params_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}", ErrorInfo::UnwrapParamsNoDc.as_ref())),
            },
            TestData {
                input: valid_serialised.as_bytes().to_vec(),
                result: Ok(valid_key_provider_input),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let result = KeyProviderInput::try_from(d.input.clone());

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }
}
