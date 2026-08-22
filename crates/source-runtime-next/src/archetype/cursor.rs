use super::{
    ArchetypeError, ArchetypeKernel, ArchetypeRequest, ArchetypeRequestKind, ArchetypeScan,
    adapter::validate_response_size, request::SCAN_PAGE_LIMIT, types::normalized_timestamp,
    wire::ScanResponse,
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
        validate_response_size(body)?;
        let raw: Vec<ScanResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let page_is_full = raw.len() == SCAN_PAGE_LIMIT;
        if raw.len() > SCAN_PAGE_LIMIT {
            return Err(ArchetypeError::ResponseLimitExceeded);
        }
        let request_path = request.provenance();
        let mut scans = raw
            .into_iter()
            .map(|scan| scan_from_response(scan, &request_path))
            .collect::<Result<Vec<_>, _>>()?;
        scans.sort_by_key(|scan| scan.id);
        let mut deduplicated: Vec<ArchetypeScan> = Vec::with_capacity(scans.len());
        for scan in scans {
            if let Some(previous) = deduplicated.last()
                && previous.id == scan.id
            {
                if previous != &scan {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                continue;
            }
            deduplicated.push(scan);
        }
        let next_before_id = page_is_full && !deduplicated.is_empty();
        Ok(ArchetypePage {
            next_before_id: next_before_id.then(|| deduplicated[0].id),
            scans: deduplicated,
        })
    }
}

pub(super) fn scan_from_response(
    scan: ScanResponse,
    request_path: &str,
) -> Result<ArchetypeScan, ArchetypeError> {
    let selected_time = [
        scan.completed_at.as_str(),
        scan.started_at.as_str(),
        scan.created_at.as_str(),
    ]
    .into_iter()
    .find(|value| !value.trim().is_empty());
    let occurred_at = selected_time.and_then(normalized_timestamp);
    let payload = serde_json::to_value(&scan).map_err(|_| ArchetypeError::InvalidResponse)?;
    let scan = ArchetypeScan {
        id: scan.id,
        repository_id: scan.repository_id,
        status: scan.status,
        occurred_at,
        request_path: request_path.to_owned(),
        payload,
    };
    scan.validate_invariant()?;
    Ok(scan)
}
