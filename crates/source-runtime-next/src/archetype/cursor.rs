use super::{
    ArchetypeError, ArchetypeKernel, ArchetypeRequest, ArchetypeRequestKind, ArchetypeScan,
    normalization::normalized_timestamp, request::SCAN_PAGE_LIMIT, wire::ScanResponse,
};

/// One decoded descending scan page and its provider pagination hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypePage {
    /// Scans sorted by ascending provider ID to match Go event order.
    pub scans: Vec<ArchetypeScan>,
    /// Oldest scan ID for the next `before_id` request when this page is full.
    pub next_before_id: Option<u64>,
}

impl ArchetypeKernel {
    /// Decode and order one scan response without advancing a durable checkpoint.
    pub fn decode_scans(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
    ) -> Result<ArchetypePage, ArchetypeError> {
        self.validate_request(request, ArchetypeRequestKind::Scans, None)?;
        let raw: Vec<ScanResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let page_is_full = raw.len() == SCAN_PAGE_LIMIT;
        if raw.len() > SCAN_PAGE_LIMIT {
            return Err(ArchetypeError::ResponseLimitExceeded);
        }
        let mut scans = raw
            .into_iter()
            .map(scan_from_response)
            .collect::<Result<Vec<_>, _>>()?;
        scans.sort_by_key(|scan| scan.id);
        if scans.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ArchetypeError::DuplicateRecordIdentity);
        }
        let next_before_id = page_is_full && !scans.is_empty();
        Ok(ArchetypePage {
            next_before_id: next_before_id.then(|| scans[0].id),
            scans,
        })
    }
}

pub(super) fn scan_from_response(scan: ScanResponse) -> Result<ArchetypeScan, ArchetypeError> {
    if scan.id == 0 || scan.repository_id == 0 {
        return Err(ArchetypeError::MissingRecordIdentity);
    }
    if scan.status.trim().is_empty() {
        return Err(ArchetypeError::InvalidResponse);
    }
    let occurred_at = [
        scan.completed_at.as_str(),
        scan.started_at.as_str(),
        scan.created_at.as_str(),
    ]
    .into_iter()
    .find_map(normalized_timestamp);
    let payload = serde_json::to_value(&scan).map_err(|_| ArchetypeError::InvalidResponse)?;
    Ok(ArchetypeScan {
        id: scan.id,
        repository_id: scan.repository_id,
        status: scan.status,
        occurred_at,
        payload,
    })
}
