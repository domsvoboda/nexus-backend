//! Real Store receipt issuance. No locally generated JWTs or entitlement grants.
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use xodus::models::{live::ExchangeUserTokenOutcome, secrets::Token, soap};
use xodus::models::licensing::{LicenseTokenRequest, LicenseTokenResponse, LicenseUserIdentity};
use xodus::models::xgameruntime::xuser::{
    StoreCollectionItem, StoreCollectionMetadata, StoreLicenseTokenRequest, StoreLicenseTokenResponse,
};
use crate::simple_context::SimpleContext;

const FAIL: u32 = 0x80004005;
const INVALID: u32 = 0x80070057;
const DENIED: u32 = 0x80070005;

/// One read-only batch, bounded independently of the license-token call.
const COLLECTION_URL: &str = "https://collections.md.mp.microsoft.com/v7.0/collections/sdkQuery";
const COLLECTION_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Keep the typed adjunct comfortably inside the bridge's 16-bit reply bound
/// even when the genuine JWT is near its 48 KB ceiling.
const COLLECTION_MAX_ITEMS: usize = 128;
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(45);
const COLLECTION_BUDGET: Duration = Duration::from_secs(85);

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

/// Normalize requested selectors for the collection call. Reject exact
/// duplicates and a product-only selector mixed with an explicit SKU for the
/// same product; distinct explicit SKUs for one product stay distinct.
fn collection_products(ids: &[String]) -> Option<Vec<(String, Option<String>)>> {
    let mut out: Vec<(String, Option<String>)> = Vec::with_capacity(ids.len());
    for id in ids {
        let (product, sku) = match id.split_once('/') {
            Some((product, sku)) => (product, Some(sku)),
            None => (id.as_str(), None),
        };
        if product.len() != 12 || sku.is_some_and(|sku| sku.len() != 4) { return None; }
        if out.iter().any(|(known, known_sku)| known.as_str() == product
            && (known_sku.is_none() || sku.is_none() || known_sku.as_deref() == sku))
        {
            return None;
        }
        out.push((product.to_string(), sku.map(str::to_string)));
    }
    Some(out)
}

fn valid(req: &StoreLicenseTokenRequest) -> bool {
    plain_id(&req.parent_product_id) && !req.product_ids.is_empty() && req.product_ids.len() <= 64
        && req.product_ids.iter().all(|id| product_id(id))
        && !req.custom_developer_string.is_empty() && req.custom_developer_string.len() <= 4096
        && (!req.include_collection_data || collection_products(&req.product_ids).is_some())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceTicketKind {
    Compact,
    DelegationCompact,
}

fn device_ticket_kind(token_type: &str) -> Option<DeviceTicketKind> {
    match token_type {
        "urn:passport:compact" => Some(DeviceTicketKind::Compact),
        "urn:passport:delegationcompact" => Some(DeviceTicketKind::DelegationCompact),
        _ => None,
    }
}

// Device authorization accepts exactly the two compact token types that
// Token::try_from already parses. The plain compact value is used unchanged as
// before. Delegation compact tickets carry the d=/t= wire form that content
// licensing normalizes with licensing_ticket, so only that form is normalized
// here. No granting, no legacy tokens, no decryption, no payload rewriting.
fn device_license_ticket(response: soap::RequestSecurityTokenResponse) -> Result<String, u32> {
    let kind = match device_ticket_kind(&response.token_type) {
        Some(kind) => kind,
        None => return Err(FAIL),
    };
    let empty_payload = response.requested_security_token.binary_security_token.as_ref()
        .map_or(true, |token| token.value.is_empty());
    if empty_payload { return Err(FAIL) }
    let Token::Compact(ticket) = Token::try_from(response).map_err(|_| FAIL)? else { return Err(FAIL) };
    if ticket.is_empty() { return Err(FAIL) }
    match kind {
        DeviceTicketKind::Compact => Ok(ticket),
        DeviceTicketKind::DelegationCompact => Ok(xodus::models::secrets::licensing_ticket(ticket)),
    }
}

fn license_request(request: StoreLicenseTokenRequest, beneficiaries: Vec<LicenseUserIdentity>) -> LicenseTokenRequest {
    LicenseTokenRequest {
        parent_product_id: request.parent_product_id, enforce_sellable_by: true,
        related_product_ids: request.product_ids, custom_developer_string: request.custom_developer_string,
        beneficiaries,
    }
}

#[derive(Deserialize)]
struct CollectionResponse {
    #[serde(default)]
    items: Vec<CollectionRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionRow {
    product_id: String,
    sku_id: String,
    acquired_date: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    local_ticket_reference: Option<String>,
    status: Option<String>,
}

fn rfc3339_seconds(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text).ok().map(|value| value.timestamp())
}

/// Normalize only requested, current, active, same-account rows. Duplicates,
/// ambiguous selectors, wrong SKUs, malformed/future dates and oversize replies
/// fail closed; unrequested products are ignored, never invented.
fn normalize_collection(
    rows: Vec<CollectionRow>,
    requested: &[(String, Option<String>)],
    puid: &str,
    now: i64,
) -> Result<Vec<StoreCollectionItem>, u32> {
    if rows.len() > COLLECTION_MAX_ITEMS { return Err(FAIL); }
    let mut out: Vec<StoreCollectionItem> = Vec::new();
    for row in rows {
        if !requested.iter().any(|(product, _)| product == &row.product_id) {
            continue;
        }
        if row.product_id.len() != 12 || row.sku_id.len() != 4
            || !plain_id(&row.product_id) || !plain_id(&row.sku_id)
        {
            return Err(FAIL);
        }
        if !requested.iter().any(|(product, sku)| product == &row.product_id
            && sku.as_deref().is_none_or(|sku| sku == row.sku_id.as_str())) { return Err(FAIL); }
        if row.status.as_deref() != Some("Active") { return Err(FAIL); }
        if row.local_ticket_reference.as_deref() != Some(puid) { return Err(FAIL); }
        let acquired = row.acquired_date.as_deref().and_then(rfc3339_seconds).ok_or(FAIL)?;
        if acquired <= 0 || acquired > now { return Err(FAIL); }
        let end = row.end_date.as_deref().and_then(rfc3339_seconds).ok_or(FAIL)?;
        if end <= now { return Err(FAIL); }
        let start = match row.start_date.as_deref() {
            Some(text) => {
                let start = rfc3339_seconds(text).ok_or(FAIL)?;
                if start <= 0 || start > now { return Err(FAIL); }
                start
            }
            None => 0,
        };
        if out.iter().any(|item| item.product_id == row.product_id && item.sku_id == row.sku_id) {
            return Err(FAIL);
        }
        out.push(StoreCollectionItem {
            product_id: row.product_id,
            sku_id: row.sku_id,
            acquired_date: acquired,
            start_date: start,
            end_date: end,
        });
    }
    Ok(out)
}

async fn sdk_query(
    context: &SimpleContext,
    device_token: &str,
    user_token: &str,
    puid: &str,
    requested: &[(String, Option<String>)],
    deadline: tokio::time::Instant,
) -> Result<Vec<StoreCollectionItem>, u32> {
    let product_sku_ids: Vec<serde_json::Value> = requested.iter().map(|(product, sku)| match sku {
        Some(sku) => serde_json::json!({ "productId": product, "skuId": sku }),
        None => serde_json::json!({ "productId": product }),
    }).collect();
    let beneficiary = LicenseUserIdentity {
        identity_type: "Msa".into(),
        identity_value: user_token.into(),
        local_ticket_reference: puid.into(),
    };
    let body = serde_json::json!({
        "validityType": "Valid",
        "beneficiaries": [beneficiary],
        "productSkuIds": product_sku_ids,
    });
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() { return Err(FAIL); }
    let mut response = context.client.post(COLLECTION_URL)
        .timeout(remaining.min(COLLECTION_TIMEOUT))
        .header("Authorization", device_token)
        .header("User-Agent", "XboxGameRuntime")
        .json(&body)
        .send().await.map_err(|_| FAIL)?;
    if !response.status().is_success() { return Err(FAIL); }
    if response.content_length().is_some_and(|n| n > COLLECTION_MAX_BYTES as u64) { return Err(FAIL); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| FAIL)? {
        if bytes.len() + chunk.len() > COLLECTION_MAX_BYTES { return Err(FAIL); }
        bytes.extend_from_slice(&chunk);
    }
    let parsed: CollectionResponse = serde_json::from_slice(&bytes).map_err(|_| FAIL)?;
    normalize_collection(parsed.items, requested, puid, Utc::now().timestamp())
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
        Ok((token, collection_metadata)) => {
            let mut response = StoreLicenseTokenResponse { hresult: 0, token, collection_metadata };
            fit_bridge_frame(&mut response);
            response
        }
        Err(hresult) => {
            tracing::warn!(hresult, "Store license token request failed");
            StoreLicenseTokenResponse { hresult, token: String::new(), collection_metadata: None }
        }
    }
}

/// The existing bridge frame is UINT16. If the optional adjunct would exceed
/// it, omit the adjunct rather than truncate the genuine JWT.
fn fit_bridge_frame(response: &mut StoreLicenseTokenResponse) {
    if response.collection_metadata.is_some()
        && !quick_xml::se::to_string(response).is_ok_and(|text| text.len() <= 0xffff)
    {
        response.collection_metadata = None;
    }
}

async fn issue(context: &SimpleContext, request: StoreLicenseTokenRequest)
    -> Result<(String, Option<StoreCollectionMetadata>), u32>
{
    let deadline = tokio::time::Instant::now() + COLLECTION_BUDGET;
    let include_collection_data = request.include_collection_data;
    let requested_products = if include_collection_data {
        collection_products(&request.product_ids).ok_or(INVALID)?
    } else {
        Vec::new()
    };
    let device = context.device_token.as_ref().ok_or(DENIED)?.clone();
    let snapshot=context.tokens().user_token_snapshot_role(xodus::tokens::AccountRole::License).map_err(|_|DENIED)?;
    let Token::Legacy(user_sts)=snapshot.token() else{return Err(DENIED)};
    let account=snapshot.user().ok_or(DENIED)?.clone();
    let puid = account.puid.clone();
    // Same genuine MSA audience/client used by upstream's content licensing.
    let client_id = "{d6d5a677-0872-4ab0-9442-bb792fce85c5}";
    let device_response = xodus::api::live::exchange_device_token(&context.client, device.clone(),
        client_id.into(), "www.microsoft.com".into(), Some(soap::PolicyReference::mbi_ssl()))
        .await.map_err(|_| FAIL)?;
    let device_token = device_license_ticket(device_response)?;
    let user_response = xodus::api::live::exchange_user_token(&context.client, user_sts,
        account.username.clone(), device, None, Some("Silent".into()), client_id.into(),
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
        .header("Authorization", device_token.as_str()).header("User-Agent", "XboxGameRuntime")
        .json(&license_request(request, vec![LicenseUserIdentity { identity_type: "Msa".into(),
            identity_value: user_token.clone(), local_ticket_reference: puid.clone() }]))
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
    let collection_metadata = if include_collection_data {
        context.tokens().validate_user_token_snapshot(&snapshot).map_err(|_|DENIED)?;
        let result = sdk_query(context, &device_token, &user_token, &puid, &requested_products, deadline).await;
        context.tokens().validate_user_token_snapshot(&snapshot).map_err(|_|DENIED)?;
        match result {
            Ok(items) if !items.is_empty() => Some(StoreCollectionMetadata { items }),
            Ok(_) => None,
            Err(hresult) => {
                /* The genuine JWT stays unchanged; a failed adjunct is omitted,
                 * never replaced with fabricated dates. */
                tracing::warn!(hresult, "Store collection metadata request failed");
                None
            }
        }
    } else {
        None
    };
    Ok((response.license_token, collection_metadata))
}

fn user_ticket_type(token_type: &str) -> bool {
    matches!(token_type, "urn:passport:compact" | "urn:passport:delegationcompact")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_DEVICE_JWE: &str =
        "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..aXY.Y2lwaGVy_dGV4dA.dGFn";

    fn device_response(kind: &str, value: Option<&str>) -> soap::RequestSecurityTokenResponse {
        soap::RequestSecurityTokenResponse {
            token_type: kind.into(),
            applies_to: soap::AppliesTo { endpoint_reference: soap::EndpointReference {
                address: "synthetic.invalid".into() } },
            lifetime: soap::Timestamp { id: None, created: "2000-01-01T00:00:00Z".into(),
                expires: "2099-01-01T00:00:00Z".into() },
            requested_security_token: soap::RequestedSecurityToken { encrypted_data: None,
                binary_security_token: value.map(|value| soap::BinarySecurityTokenRes {
                    id: "synthetic".into(), value: value.into(), value_type: None }) },
            requested_proof_token: None,
        }
    }

    #[test]
    fn device_compact_tickets_are_used_unchanged() {
        for value in ["opaque-device-ticket", SYNTHETIC_DEVICE_JWE] {
            assert_eq!(device_license_ticket(device_response("urn:passport:compact", Some(value))), Ok(value.to_string()));
        }
    }

    #[test]
    fn device_delegation_tickets_use_the_licensing_wire_form() {
        assert_eq!(device_license_ticket(device_response("urn:passport:delegationcompact", Some(SYNTHETIC_DEVICE_JWE))),
            Ok(SYNTHETIC_DEVICE_JWE.to_string()));
        assert_eq!(device_license_ticket(device_response("urn:passport:delegationcompact", Some("opaque-device-ticket"))),
            Ok("t=opaque-device-ticket".to_string()));
    }

    #[test]
    fn device_unknown_legacy_missing_and_empty_payloads_fail_closed() {
        assert_eq!(device_license_ticket(device_response("urn:passport:legacy", Some(SYNTHETIC_DEVICE_JWE))), Err(FAIL));
        assert_eq!(device_license_ticket(device_response("urn:passport:unknown", Some(SYNTHETIC_DEVICE_JWE))), Err(FAIL));
        assert_eq!(device_license_ticket(device_response("urn:passport:compact", None)), Err(FAIL));
        assert_eq!(device_license_ticket(device_response("urn:passport:delegationcompact", None)), Err(FAIL));
        assert_eq!(device_license_ticket(device_response("urn:passport:compact", Some(""))), Err(FAIL));
        assert_eq!(device_license_ticket(device_response("urn:passport:delegationcompact", Some(""))), Err(FAIL));
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
            product_ids: ids.iter().map(|s| s.to_string()).collect(), custom_developer_string: "nonce<&>".into(),
            include_collection_data: false }
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
            product_ids: vec!["9N4PT8HGCDHQ".into()], custom_developer_string: "probe<&>".into(),
            include_collection_data: false };
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

    const NOW: i64 = 1_800_000_000;

    fn row(product: &str, sku: &str, acquired: &str, start: Option<&str>, end: &str,
           reference: &str, status: &str) -> CollectionRow {
        CollectionRow {
            product_id: product.into(), sku_id: sku.into(),
            acquired_date: Some(acquired.into()), start_date: start.map(str::to_string),
            end_date: Some(end.into()), local_ticket_reference: Some(reference.into()),
            status: Some(status.into()),
        }
    }

    fn good_row() -> CollectionRow {
        row("9N4PT8HGCDHQ", "0010", "2026-01-01T00:00:00Z", Some("2026-01-01T00:00:01Z"),
            "2030-01-01T00:00:00Z", "synthetic-reference", "Active")
    }

    #[test]
    fn collection_normalizes_real_shape_as_int64_utc() {
        let requested = collection_products(&["9N4PT8HGCDHQ".into()]).unwrap();
        let items = normalize_collection(vec![good_row()], &requested, "synthetic-reference", NOW).unwrap();
        assert_eq!(items, vec![StoreCollectionItem {
            product_id: "9N4PT8HGCDHQ".into(), sku_id: "0010".into(),
            acquired_date: 1767225600, start_date: 1767225601, end_date: 1893456000,
        }]);
    }

    #[test]
    fn collection_accepts_distinct_explicit_skus_for_same_product() {
        let requested = collection_products(&["9N4PT8HGCDHQ/0010".into(), "9N4PT8HGCDHQ/0017".into()]).unwrap();
        let mut second = good_row();
        second.sku_id = "0017".into();
        let items = normalize_collection(vec![good_row(), second], &requested, "synthetic-reference", NOW).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].sku_id, "0010");
        assert_eq!(items[1].sku_id, "0017");
    }

    #[test]
    fn collection_rejects_wrong_account_sku_status_and_duplicates() {
        let requested = collection_products(&["9N4PT8HGCDHQ".into()]).unwrap();
        let explicit = collection_products(&["9N4PT8HGCDHQ/0010".into()]).unwrap();
        let wrong_account = row("9N4PT8HGCDHQ", "0010", "2026-01-01T00:00:00Z", None,
            "2030-01-01T00:00:00Z", "other-reference", "Active");
        assert_eq!(normalize_collection(vec![wrong_account], &requested, "synthetic-reference", NOW), Err(FAIL));
        let wrong_sku = row("9N4PT8HGCDHQ", "0017", "2026-01-01T00:00:00Z", None,
            "2030-01-01T00:00:00Z", "synthetic-reference", "Active");
        assert_eq!(normalize_collection(vec![wrong_sku], &explicit, "synthetic-reference", NOW), Err(FAIL));
        let inactive = row("9N4PT8HGCDHQ", "0010", "2026-01-01T00:00:00Z", None,
            "2030-01-01T00:00:00Z", "synthetic-reference", "Expired");
        assert_eq!(normalize_collection(vec![inactive], &requested, "synthetic-reference", NOW), Err(FAIL));
        assert_eq!(normalize_collection(vec![good_row(), good_row()], &requested, "synthetic-reference", NOW), Err(FAIL));
    }

    #[test]
    fn collection_rejects_missing_malformed_future_and_past_dates() {
        let requested = collection_products(&["9N4PT8HGCDHQ".into()]).unwrap();
        let mut missing = good_row(); missing.acquired_date = None;
        assert_eq!(normalize_collection(vec![missing], &requested, "synthetic-reference", NOW), Err(FAIL));
        let mut malformed = good_row(); malformed.acquired_date = Some("not-a-date".into());
        assert_eq!(normalize_collection(vec![malformed], &requested, "synthetic-reference", NOW), Err(FAIL));
        let mut future = good_row(); future.acquired_date = Some("2030-01-01T00:00:00Z".into());
        assert_eq!(normalize_collection(vec![future], &requested, "synthetic-reference", NOW), Err(FAIL));
        let mut past = good_row(); past.end_date = Some("2020-01-01T00:00:00Z".into());
        assert_eq!(normalize_collection(vec![past], &requested, "synthetic-reference", NOW), Err(FAIL));
    }

    #[test]
    fn collection_ignores_unrequested_products_and_keeps_distinct_skus() {
        let requested = collection_products(&["9N4PT8HGCDHQ/0010".into(), "9N4PT8HGCDHQ/0017".into()]).unwrap();
        let other = row("9N4PT8HGCDH1", "0010", "2026-01-01T00:00:00Z", None,
            "2030-01-01T00:00:00Z", "synthetic-reference", "Active");
        let items = normalize_collection(vec![good_row(), other], &requested, "synthetic-reference", NOW).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].sku_id, "0010");
    }

    #[test]
    fn collection_flag_rejects_duplicate_or_ambiguous_selectors() {
        let mut req = request(&["9N4PT8HGCDHQ/0010", "9N4PT8HGCDHQ/0010"]);
        req.include_collection_data = true;
        assert!(!valid(&req));
        req.product_ids = vec!["9N4PT8HGCDHQ".into(), "9N4PT8HGCDHQ/0010".into()];
        assert!(!valid(&req));
        req.product_ids = vec!["9N4PT8HGCDHQ/0010".into(), "9N4PT8HGCDHQ/0017".into()];
        assert!(valid(&req));
        req.include_collection_data = false;
        req.product_ids = vec!["9N4PT8HGCDHQ/0010".into(), "9N4PT8HGCDHQ/0010".into()];
        assert!(valid(&req), "ordinary licensing keeps existing duplicate behavior");
    }

    #[test]
    fn collection_request_and_reply_are_optional_typed_adjuncts() {
        let xml = "<StoreLicenseTokenRequest><ParentProductId>9N4PT8HGCDHQ</ParentProductId><ProductId>9N4PT8HGCDHQ</ProductId><CustomDeveloperString>nonce</CustomDeveloperString><IncludeCollectionData>true</IncludeCollectionData></StoreLicenseTokenRequest>";
        let req: StoreLicenseTokenRequest = quick_xml::de::from_str(xml).unwrap();
        assert!(req.include_collection_data);
        assert!(valid(&req));
        let plain: StoreLicenseTokenRequest = quick_xml::de::from_str(
            "<StoreLicenseTokenRequest><ParentProductId>9N4PT8HGCDHQ</ParentProductId><ProductId>9N4PT8HGCDHQ</ProductId><CustomDeveloperString>nonce</CustomDeveloperString></StoreLicenseTokenRequest>").unwrap();
        assert!(!plain.include_collection_data);
        let response = StoreLicenseTokenResponse { hresult: 0, token: "synthetic".into(),
            collection_metadata: Some(StoreCollectionMetadata { items: vec![StoreCollectionItem {
                product_id: "9N4PT8HGCDHQ".into(), sku_id: "0010".into(),
                acquired_date: 1767225600, start_date: 0, end_date: 1893456000,
            }] }) };
        let text = quick_xml::se::to_string(&response).unwrap();
        assert!(text.contains("<CollectionMetadata><Item><ProductId>9N4PT8HGCDHQ</ProductId><SkuId>0010</SkuId>"));
        assert!(text.contains("<AcquiredDate>1767225600</AcquiredDate>"));
        let plain = StoreLicenseTokenResponse { hresult: 0, token: "synthetic".into(), collection_metadata: None };
        assert!(!quick_xml::se::to_string(&plain).unwrap().contains("CollectionMetadata"));
    }

    #[test]
    fn collection_adjunct_is_omitted_when_the_bridge_frame_would_overflow() {
        let mut response = StoreLicenseTokenResponse { hresult: 0, token: "x".repeat(48000),
            collection_metadata: Some(StoreCollectionMetadata { items: (0..128).map(|index| StoreCollectionItem {
                product_id: format!("{index:012}"), sku_id: "0010".into(),
                acquired_date: 1767225600, start_date: 0, end_date: 1893456000,
            }).collect() }) };
        fit_bridge_frame(&mut response);
        assert!(response.collection_metadata.is_none());
        assert_eq!(response.token.len(), 48000);
        let mut small = StoreLicenseTokenResponse { hresult: 0, token: "synthetic".into(),
            collection_metadata: Some(StoreCollectionMetadata { items: vec![StoreCollectionItem {
                product_id: "9N4PT8HGCDHQ".into(), sku_id: "0010".into(),
                acquired_date: 1767225600, start_date: 0, end_date: 1893456000,
            }] }) };
        fit_bridge_frame(&mut small);
        assert!(small.collection_metadata.is_some());
    }
}
