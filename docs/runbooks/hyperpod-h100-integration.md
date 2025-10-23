# HyperPod H100 Integration Notes

## Current Cerebro Infrastructure
- **Pulumi stack (`infra/`)** runs the production Cerebro services entirely on AWS ECS Fargate.
  - `infra/aws/compute.py` provisions the API, worker, beat, and optional Flower services.
  - All tasks are CPU-backed Fargate; no GPU capacity or SageMaker resources are created today.
- Supporting infrastructure (RDS, ElastiCache, ALB, IAM, Secrets) is defined in the same Pulumi program and parameterized via `Pulumi.yaml` / `Pulumi.prod.yaml`.

## GPU Capacity Managed Outside Pulumi
- The **AI/ML team Terraform repo (`devops-terraform`)** owns GPU-capable environments.
  - Stack `stacks/st-services/unstable/aws/customers/ext-awssbd/` targets AWS account `381492279359` (`writer-nonprod`, region `us-east-1`).
  - `node_groups.tf` defines an EKS GPU node group (defaults to `g4dn.*`) that can be overridden to use larger GPUs.
  - `sagemaker.tf` includes SageMaker endpoint definitions on `ml.p5.48xlarge` (H100) but leaves them disabled until `enabled = true`.
- **Onboarding doc (“How to: Use AWS HyperPod Cluster”)** covers logging into the HyperPod (H100/H200) clusters via AWS SSO and Slurm; these clusters sit in the same `writer-nonprod` account.

## How the Pieces Fit Together
1. **Cerebro runtime** stays on Fargate via Pulumi.
2. **GPU workloads** (fine-tuning, large inference, experiments) run through the Terraform-managed HyperPod/SageMaker or EKS GPU node groups.
3. **Data paths**: Cerebro automations export transcripts and telemetry under `src/cerebro/automation/`; those datasets feed GPU jobs via Terraform/HyperPod workflows.

## Using the H100 Fleet Today
1. Log into AWS SSO → `writer-nonprod` → assume the `platform_terraform` (or relevant HyperPod) role.
2. For SageMaker endpoints: in `devops-terraform` toggle the desired model block’s `enabled` flag and run Terraform to provision `ml.p5.48xlarge` instances.
3. For EKS: adjust the GPU overrides to the desired instance size (e.g., add an H100 entry) and apply Terraform so the `gpu` node group adopts that type; workloads reference it via labels/taints.
4. For direct HyperPod jobs: follow the Slurm instructions (SSH via Session Manager or VS Code integration) and schedule work on the existing H100 queue.

## Extending Pulumi (Future Work)
- Add a Pulumi module (e.g., `infra/aws/gpu.py`) that can provision H100-backed resources in the Cerebro stack when needed (EKS node groups or managed endpoints).
- Expose configuration flags (`enableGpu`, `gpuInstanceType`, desired counts) in `Pulumi.yaml` so environments can toggle GPU infrastructure without editing code.
- Ensure IAM roles created by Pulumi include SageMaker/SSM/CloudWatch permissions if GPU services are enabled.

## Quick Reference
- AWS account: `381492279359` (`writer-nonprod`)
- Region: `us-east-1` for Terraform-managed HyperPod/SageMaker resources
- HyperPod clusters: H100 (`p5`) and H200 (`p5en`), accessed via AWS SSO + Slurm
- Related repos: `devops-terraform`, `k8s`
