resource "google_service_account" "target" {
  project    = "my-project"
  account_id = "target-sa"
}

resource "google_service_account" "caller" {
  project    = "my-project"
  account_id = "caller-sa"
}

resource "google_service_account_iam_member" "caller_can_impersonate_target" {
  service_account_id = google_service_account.target.name
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = google_service_account.caller.member
}

resource "google_project_iam_member" "target_storage_viewer" {
  project = "my-project"
  role    = "roles/storage.objectViewer"
  member  = google_service_account.target.member
}
