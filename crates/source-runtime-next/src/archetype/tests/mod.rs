use super::*;

mod failure;
mod knowledge;
mod parity;
mod request;
mod scan_page;
mod vulnerability;

pub(super) const TENANT_ID: &str = "tenant-archetype";
pub(super) const OBSERVED_AT: &str = "2026-08-20T02:00:00Z";

pub(super) fn kernel(family: ArchetypeFamily) -> ArchetypeKernel {
    ArchetypeKernel::new("https://archetype.example.test", None, family, None)
        .unwrap()
        .bind_tenant(TENANT_ID)
        .unwrap()
}

pub(super) fn scan(kernel: &ArchetypeKernel) -> ArchetypeScan {
    let request = kernel.plan_scans(None).unwrap();
    kernel
        .decode_scans(
            &request,
            br#"[{"id":9,"repository_id":7,"status":"completed","completed_at":"2026-08-20T01:02:03Z"}]"#,
        )
        .unwrap()
        .scans
        .remove(0)
}
