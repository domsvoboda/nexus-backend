use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xbox_msa_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_msa_account_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StoreLicenseTokenRequest {
    pub parent_product_id: String,
    #[serde(default, rename = "ProductId")]
    pub product_ids: Vec<String>,
    pub custom_developer_string: String,
    /// Optional adjunct. Ordinary license-token callers leave this absent/false
    /// so they never pay for a second collection request.
    #[serde(default)]
    pub include_collection_data: bool,
}

/// One normalized, first-party collection row. Dates are UTC seconds since the
/// epoch (the Store ABI is INT64), never raw service strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StoreCollectionItem {
    pub product_id: String,
    pub sku_id: String,
    pub acquired_date: i64,
    pub start_date: i64,
    pub end_date: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StoreCollectionMetadata {
    #[serde(default, rename = "Item")]
    pub items: Vec<StoreCollectionItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StoreLicenseTokenResponse {
    pub hresult: u32,
    pub token: String,
    /// Optional typed adjunct beside the unchanged genuine JWT. It is never
    /// ownership proof; the SDK applies it only after receipt verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_metadata: Option<StoreCollectionMetadata>,
}
