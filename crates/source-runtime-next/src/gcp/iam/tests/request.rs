use super::*;

#[test]
fn iam_plans_exact_go_paths_auth_and_pagination() {
    let account_request = account_kernel().plan(Some("accounts-2")).unwrap();
    assert_eq!(
        account_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10&pageToken=accounts-2"
    );
    assert_eq!(account_request.authorization_scheme(), "Bearer");
    assert_eq!(account_request.accept(), "application/json");
    assert!(!GcpIamKernel::requires_credentials());

    let key_request = key_kernel().plan(Some("keys-2")).unwrap();
    assert_eq!(
        key_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys?pageSize=10&pageToken=keys-2"
    );
}
