use super::*;

mod knowledge;
mod request;
mod scan_page;
mod vulnerability;

pub(super) fn kernel(family: ArchetypeFamily) -> ArchetypeKernel {
    ArchetypeKernel::new("https://archetype.example.test", None, family, None).unwrap()
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
