use super::{PARITY_FIXTURE, kernel, linode, observed_at};

#[test]
fn plans_exact_request_and_declares_external_bearer_authentication() {
    let kernel = kernel();
    let first = kernel.plan(None).unwrap();
    assert_eq!(
        first.url().as_str(),
        "https://api.linode.com/v4/managed/issues?page=1&page_size=100"
    );
    assert_eq!(first.authorization_scheme(), "Bearer");
    assert_eq!(first.accept(), "application/json");
    assert!(!linode::LinodeKernel::requires_credentials());
    assert_eq!(
        kernel.plan(Some("2")).unwrap().url().as_str(),
        "https://api.linode.com/v4/managed/issues?page=2&page_size=100"
    );
}

#[test]
fn pagination_round_trips_and_rejects_invalid_cursors_and_response_pages() {
    let kernel = kernel();
    let page = kernel
        .decode(&kernel.plan(None).unwrap(), PARITY_FIXTURE, observed_at())
        .unwrap();
    let request = kernel.plan(page.next_cursor.as_deref()).unwrap();
    assert_eq!(request.url().query(), Some("page=2&page_size=100"));
    let terminal = br#"{"data":[],"page":2,"pages":2,"results":101}"#;
    assert_eq!(
        kernel
            .decode(&request, terminal, observed_at())
            .unwrap()
            .next_cursor,
        None
    );
    for cursor in [
        "0",
        "02",
        "1000001",
        "https://api.linode.com/v4/managed/issues?page=2",
        "2\n",
    ] {
        assert_eq!(
            kernel.plan(Some(cursor)).unwrap_err(),
            linode::LinodeError::InvalidCursor
        );
    }
    let wrong_page = br#"{"data":[],"page":2,"pages":2,"results":0}"#;
    assert_eq!(
        kernel
            .decode(&kernel.plan(None).unwrap(), wrong_page, observed_at())
            .unwrap_err(),
        linode::LinodeError::ResponsePageMismatch
    );
}

#[test]
fn requests_are_bound_to_the_planning_kernel() {
    let request = linode::LinodeKernel::new(Some("http://127.0.0.1:8080/v4"), "tenant", None)
        .unwrap()
        .plan(None)
        .unwrap();
    assert_eq!(
        kernel()
            .decode(&request, PARITY_FIXTURE, observed_at())
            .unwrap_err(),
        linode::LinodeError::RequestScopeMismatch
    );
}
