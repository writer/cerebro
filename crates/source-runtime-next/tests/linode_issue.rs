#[path = "../src/linode.rs"]
mod linode;

use time::OffsetDateTime;

const PARITY_FIXTURE: &[u8] = include_bytes!("../../../sources/linode/testdata/read_issue.json");
const PROVIDER_FIXTURE: &[u8] =
    include_bytes!("../../../sources/linode/testdata/managed_issues_page.json");

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse(
        "2026-06-02T02:04:05.123456789Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

fn kernel() -> linode::LinodeKernel {
    linode::LinodeKernel::new(None, "tenant", None).unwrap()
}

#[path = "linode_issue/failure.rs"]
mod failure;
#[path = "linode_issue/parity.rs"]
mod parity;
#[path = "linode_issue/request.rs"]
mod request;
