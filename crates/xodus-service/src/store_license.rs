//! Real Store receipt issuance. No locally generated JWTs or entitlement grants.
use std::time::Duration;
use xodus::models::{live::ExchangeUserTokenOutcome, secrets::Token, soap};
use xodus::models::licensing::{LicenseTokenRequest, LicenseTokenResponse, LicenseUserIdentity};
use xodus::models::xgameruntime::xuser::{StoreLicenseTokenRequest, StoreLicenseTokenResponse};
use crate::simple_context::SimpleContext;

const FAIL: u32 = 0x80004005;
const INVALID: u32 = 0x80070057;
const DENIED: u32 = 0x80070005;

fn plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn product_id(id: &str) -> bool {
    match id.split_once('/') {
        // A SKU Store ID is a 12-character product ID and a 4-character SKU.
        // Keep the selector intact for the real licensing service to evaluate.
        Some((product, sku)) => product.len() == 12 && sku.len() == 4
            && plain_id(product) && plain_id(sku),
        None => plain_id(id),
    }
}

fn valid(req: &StoreLicenseTokenRequest) -> bool {
    plain_id(&req.parent_product_id) && !req.product_ids.is_empty() && req.product_ids.len() <= 64
        && req.product_ids.iter().all(|id| product_id(id))
        && !req.custom_developer_string.is_empty() && req.custom_developer_string.len() <= 4096
}

fn license_request(request: StoreLicenseTokenRequest, beneficiaries: Vec<LicenseUserIdentity>) -> LicenseTokenRequest {
    LicenseTokenRequest {
        parent_product_id: request.parent_product_id, enforce_sellable_by: true,
        related_product_ids: request.product_ids, custom_developer_string: request.custom_developer_string,
        beneficiaries,
    }
}

pub async fn handle(context: &SimpleContext, body: &[u8]) -> StoreLicenseTokenResponse {
    let request = std::str::from_utf8(body).ok()
        .and_then(|text| quick_xml::de::from_str::<StoreLicenseTokenRequest>(text).ok());
    let result = match request {
        Some(req) if valid(&req) => tokio::time::timeout(Duration::from_secs(90), issue(context, req))
            .await.unwrap_or(Err(FAIL)),
        _ => Err(INVALID),
    };
    match result {
        Ok(token) => StoreLicenseTokenResponse { hresult: 0, token },
        Err(hresult) => {
            tracing::warn!(hresult, "Store license token request failed");
            StoreLicenseTokenResponse { hresult, token: String::new() }
        }
    }
}

async fn issue(context: &SimpleContext, request: StoreLicenseTokenRequest) -> Result<String, u32> {
    let device = context.device_token.as_ref().ok_or(DENIED)?.clone();
    let snapshot=context.tokens().user_token_snapshot_role(xodus::tokens::AccountRole::License).map_err(|_|DENIED)?;
    let Token::Legacy(user_sts)=snapshot.token() else{return Err(DENIED)};
    let account=snapshot.user().ok_or(DENIED)?.clone();
    // Same genuine MSA audience/client used by upstream's content licensing.
    let client_id = "{d6d5a677-0872-4ab0-9442-bb792fce85c5}";
    let device_response = xodus::api::live::exchange_device_token(&context.client, device.clone(),
        client_id.into(), "www.microsoft.com".into(), Some(soap::PolicyReference::mbi_ssl()))
        .await.map_err(|_| FAIL)?;
    let device_token = device_ticket(device_response)?;
    let user_response = xodus::api::live::exchange_user_token(&context.client, user_sts,
        account.username, device, None, Some("Silent".into()), client_id.into(),
        &[("www.microsoft.com".into(), Some(soap::PolicyReference::mbi_ssl()))])
        .await.map_err(|_| FAIL)?;
    let response = match user_response {
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponseCollection(collection)) =>
            collection.security_tokens.into_iter().find(|r| user_ticket_type(&r.token_type)).ok_or(FAIL)?,
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(response)) => *response,
        _ => return Err(DENIED),
    };
    if !user_ticket_type(&response.token_type) { return Err(FAIL) }
    let Token::Compact(user_token) = Token::try_from(response).map_err(|_| FAIL)? else { return Err(FAIL) };
    let user_token = xodus::models::secrets::licensing_ticket(user_token);
    context.tokens().validate_user_token_snapshot(&snapshot).map_err(|_|DENIED)?;
    let mut response = context.client.post("https://licensing.mp.microsoft.com/v8.0/licenseToken")
        .timeout(Duration::from_secs(60)).header("from", "XboxLicenseManager")
        .header("Authorization", device_token).header("User-Agent", "XboxGameRuntime")
        .json(&license_request(request, vec![LicenseUserIdentity { identity_type: "Msa".into(),
            identity_value: user_token, local_ticket_reference: account.puid }]))
        .send().await.map_err(|_| FAIL)?;
    if !response.status().is_success() {
        return Err(if matches!(response.status().as_u16(), 401 | 403) { DENIED } else { FAIL });
    }
    if response.content_length().is_some_and(|n| n > 60000) { return Err(FAIL) }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| FAIL)? {
        if body.len() + chunk.len() > 60000 { return Err(FAIL) }
        body.extend_from_slice(&chunk);
    }
    let response: LicenseTokenResponse = serde_json::from_slice(&body).map_err(|_| FAIL)?;
    if response.license_token.is_empty() || response.license_token.len() > 48000 { return Err(FAIL) }
    context.tokens().validate_user_token_snapshot(&snapshot).map_err(|_|DENIED)?;
    Ok(response.license_token)
}

fn user_ticket_type(token_type: &str) -> bool {
    matches!(token_type, "urn:passport:compact" | "urn:passport:delegationcompact")
}

fn device_ticket(response: soap::RequestSecurityTokenResponse) -> Result<String, u32> {
    // Like content licensing, use the shared decoder for compact and
    // delegation-compact representations, then require a Compact token.
    match Token::try_from(response).map_err(|_| FAIL)? {
        Token::Compact(ticket) => Ok(ticket),
        _ => Err(FAIL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_response(kind: &str, payload: Option<&str>) -> soap::RequestSecurityTokenResponse {
        soap::RequestSecurityTokenResponse {
            token_type: kind.into(),
            applies_to: soap::AppliesTo { endpoint_reference: soap::EndpointReference { address: "synthetic.invalid".into() } },
            lifetime: soap::Timestamp { id: None, created: "2000-01-01T00:00:00Z".into(), expires: "2099-01-01T00:00:00Z".into() },
            requested_security_token: soap::RequestedSecurityToken {
                encrypted_data: None,
                binary_security_token: payload.map(|value| soap::BinarySecurityTokenRes { id: "fixture".into(), value: value.into(), value_type: None }),
            },
            requested_proof_token: None,
        }
    }

    #[test]
    fn store_device_ticket_accepts_compact_and_delegation_representations() {
        assert_eq!(device_ticket(device_response("urn:passport:compact", Some("synthetic-compact"))).unwrap(), "synthetic-compact");
        assert_eq!(device_ticket(device_response("urn:passport:delegationcompact", Some("synthetic-delegation"))).unwrap(), "d=synthetic-delegation");
        let jwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..aXY.Y2lwaGVy_dGV4dA.dGFn";
        assert_eq!(device_ticket(device_response("urn:passport:delegationcompact", Some(jwe))).unwrap(), format!("t={jwe}"));
    }

    #[test]
    fn store_device_ticket_rejects_legacy_unknown_and_missing_payloads() {
        let mut legacy = device_response("urn:passport:legacy", None);
        legacy.requested_security_token.encrypted_data = Some(soap::EncryptedData::devicesoftware("synthetic-ciphertext".into()));
        assert!(matches!(Token::try_from(legacy.clone()).unwrap(), Token::Legacy(_)));
        assert_eq!(device_ticket(legacy), Err(FAIL));
        assert_eq!(device_ticket(device_response("unsupported-type", Some("synthetic"))), Err(FAIL));
        for kind in ["urn:passport:compact", "urn:passport:delegationcompact"] {
            assert_eq!(device_ticket(device_response(kind, None)), Err(FAIL));
        }
    }

    #[test]
    fn store_license_accepts_delegation_compact_user_tickets() {
        assert!(user_ticket_type("urn:passport:compact"));
        assert!(user_ticket_type("urn:passport:delegationcompact"));
        assert!(!user_ticket_type("urn:passport:legacy"));
        assert_eq!(xodus::models::secrets::store_ticket("d=abc".into()), "t=abc");
        assert_eq!(xodus::models::secrets::store_ticket("t=abc&p=".into()), "t=abc&p=");
    }

    #[test]
    fn store_license_jwe_keeps_existing_request_and_opaque_ticket_behavior() {
        let raw = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..aXY.Y2lwaGVy_dGV4dA.dGFn";
        for (input, expected) in [(format!("d={raw}"), raw), ("d=opaque".into(), "t=opaque"),
            ("t=compact&p=proof".into(), "t=compact&p=proof")] {
            let value = license_request(request(&["9N4PT8HGCDHQ/0010"]), vec![LicenseUserIdentity {
                identity_type: "Msa".into(), identity_value: xodus::models::secrets::licensing_ticket(input),
                local_ticket_reference: "reference-unchanged".into(),
            }]);
            let value = serde_json::to_value(value).unwrap();
            assert_eq!(value["beneficiaries"][0]["identityValue"], expected);
            assert_eq!(value["beneficiaries"][0]["localTicketReference"], "reference-unchanged");
            assert_eq!(value["parentProductId"], "9N4PT8HGCDHQ");
            assert_eq!(value["relatedProductIds"], serde_json::json!(["9N4PT8HGCDHQ/0010"]));
            assert_eq!(value["enforceSellableBy"], true);
            assert_eq!(value["customDeveloperString"], "nonce<&>");
        }
    }

    fn request(ids: &[&str]) -> StoreLicenseTokenRequest {
        StoreLicenseTokenRequest { parent_product_id: "9N4PT8HGCDHQ".into(),
            product_ids: ids.iter().map(|s| s.to_string()).collect(), custom_developer_string: "nonce<&>".into() }
    }

    #[test]
    fn accepts_plain_and_sku_selectors_without_changing_them() {
        for id in ["9N4PT8HGCDHQ", "9N4PT8HGCDHQ/0010", "9n4pt8hgcdhq/00aB", "A", &"A".repeat(32)] {
            let req = request(&[id]);
            assert!(valid(&req), "rejected {id}");
            let json = serde_json::to_value(license_request(req, vec![LicenseUserIdentity {
                identity_type: "Msa".into(), identity_value: "synthetic-user".into(),
                local_ticket_reference: "synthetic-reference".into(),
            }])).unwrap();
            assert_eq!(json, serde_json::json!({
                "parentProductId": "9N4PT8HGCDHQ", "enforceSellableBy": true,
                "relatedProductIds": [id], "customDeveloperString": "nonce<&>",
                "beneficiaries": [{"identityType":"Msa", "identityValue":"synthetic-user",
                    "localTicketReference":"synthetic-reference"}],
            }));
        }
    }

    #[test]
    fn rejects_malformed_sku_selectors() {
        for id in ["", "/0010", "9N4PT8HGCDHQ/", "bad/id", "9N4PT8HGCDH/0010",
            "9N4PT8HGCDHQQ/0010", "9N4PT8HGCDHQ/001", "9N4PT8HGCDHQ/00100",
            "9N4PT8HGCDHQ//0010", "9N4PT8HGCDHQ/00/0", "9N4PT8HGCDHQ/0010/ABCDEFGHIJKL",
            "../0010", "9N4PT8HGCDHQ/00.0", "9N4PT8HGCDHQ/00-0", "9N4PT8HGCDHQ/00é",
            "9N4PT8HGCDHQ/00 0", "9N4PT8HGCDHQ/00\n0", "9N4PT8HGCDHQ/00\00",
            "9N4PT8HGCDHQ%2F0010", "9N4PT8HGCDHQ\\0010", &"A".repeat(33)] {
            assert!(!valid(&request(&[id])), "accepted {id:?}");
            assert!(!valid(&request(&["9N4PT8HGCDHQ", id])), "accepted mixed {id:?}");
        }
    }

    #[test]
    fn keeps_parent_count_and_nonce_bounds() {
        let mut req = request(&["9N4PT8HGCDHQ/0010"]);
        for parent in ["", "9N4PT8HGCDHQ/0010", "bad-id", &"A".repeat(33)] {
            req.parent_product_id = parent.into(); assert!(!valid(&req));
        }
        req.parent_product_id = "9N4PT8HGCDHQ".into();
        req.product_ids.clear(); assert!(!valid(&req));
        req.product_ids = vec!["9N4PT8HGCDHQ/0010".into(); 64]; assert!(valid(&req));
        req.product_ids.push("9N4PT8HGCDHQ".into()); assert!(!valid(&req));
        req.product_ids.pop(); req.custom_developer_string.clear(); assert!(!valid(&req));
        req.custom_developer_string = "é".repeat(2048); assert!(valid(&req));
        req.custom_developer_string.push('x'); assert!(!valid(&req));
    }

    #[test]
    fn xml_to_json_keeps_mixed_sku_ids_nonce_order_and_duplicates() {
        let xml = "<StoreLicenseTokenRequest><ParentProductId>9N4PT8HGCDHQ</ParentProductId><ProductId>9N4PT8HGCDHQ/0010</ProductId><ProductId>OTHER</ProductId><ProductId>9N4PT8HGCDHQ/0010</ProductId><CustomDeveloperString>  nonce&lt;&amp;&gt;é  </CustomDeveloperString></StoreLicenseTokenRequest>";
        let req: StoreLicenseTokenRequest = quick_xml::de::from_str(xml).unwrap();
        assert!(valid(&req));
        let json = serde_json::to_value(license_request(req, Vec::new())).unwrap();
        assert_eq!(json["relatedProductIds"], serde_json::json!(["9N4PT8HGCDHQ/0010", "OTHER", "9N4PT8HGCDHQ/0010"]));
        assert_eq!(json["customDeveloperString"], "  nonce<&>é  ");
        assert_eq!(json["parentProductId"], "9N4PT8HGCDHQ");
        assert_eq!(json["enforceSellableBy"], true);
    }
    #[test]
    fn rejects_empty_or_invalid_request() {
        let mut req = StoreLicenseTokenRequest { parent_product_id: "9N4PT8HGCDHQ".into(),
            product_ids: vec!["9N4PT8HGCDHQ".into()], custom_developer_string: "probe<&>".into() };
        assert!(valid(&req));
        req.custom_developer_string.clear(); assert!(!valid(&req));
        req.custom_developer_string = "nonce".into(); req.product_ids[0] = "bad/id".into();
        assert!(!valid(&req));
    }
    #[test]
    fn xml_preserves_exact_nonce_and_multiple_ids() {
        let req: StoreLicenseTokenRequest = quick_xml::de::from_str(
            "<StoreLicenseTokenRequest><ParentProductId>9N4PT8HGCDHQ</ParentProductId><ProductId>9N4PT8HGCDHQ</ProductId><ProductId>OTHER</ProductId><CustomDeveloperString>probe&lt;&amp;&gt;</CustomDeveloperString></StoreLicenseTokenRequest>").unwrap();
        assert_eq!(req.product_ids.len(), 2);
        assert_eq!(req.custom_developer_string, "probe<&>");
    }
}
