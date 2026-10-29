variable "project_id" {
  type    = string
  default = "my-project"
}

locals {
  project_roles = ["roles/storage.objectViewer", "roles/logging.logWriter"]
}

resource "google_service_account" "app" {
  project    = var.project_id
  account_id = "app-sa"
}

resource "google_project_iam_member" "roles" {
  for_each = toset(local.project_roles)

  project = var.project_id
  role    = each.value
  member  = google_service_account.app.member
}

resource "google_organization_iam_member" "conditional" {
  org_id = "123456789"
  role   = "roles/resourcemanager.tagUser"
  member = google_service_account.app.member

  condition {
    title      = "expires_2030"
    expression = "request.time < timestamp(\"2030-01-01T00:00:00Z\")"
  }
}

resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = google_service_account.app.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:${var.project_id}.svc.id.goog[default/app]"
}
