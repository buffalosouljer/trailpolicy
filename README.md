# trailpolicy

Generate least-privilege IAM policies from CloudTrail activity. Designed for AWS GovCloud, where IAM Access Analyzer's policy generation feature is unavailable.

trailpolicy analyzes CloudTrail management events for specific IAM roles, maps them to IAM actions with correct resource ARNs, and produces ready-to-use IAM policy documents. It also diffs generated policies against a role's existing permissions to identify unused grants.

## How It Works

1. **Fetch** CloudTrail events for a role (via LookupEvents API or Athena)
2. **Parse** events, filtering errors and self-AssumeRole noise
3. **Map** CloudTrail event sources/names to IAM action strings (with override mappings for services like `monitoring.amazonaws.com` -> `cloudwatch`)
4. **Extract** resource ARNs from request parameters (S3 buckets, DynamoDB tables, Lambda functions, SQS queues)
5. **Build** a least-privilege policy, grouping actions by resource set, with automatic compression if the policy exceeds IAM's 10,240-character limit
6. **Output** as JSON or Terraform `aws_iam_policy_document` format

## Architecture

The project has two components:

- **Python CLI** (`cli/`) -- the core library and command-line interface
- **Terraform infrastructure** (`terraform/`) -- deploys CloudTrail, Athena, Lambda, and EventBridge for automated policy generation

Infrastructure is organized into independently deployable phases:

| Phase | Directory | Purpose |
|-------|-----------|---------|
| 0 | `phase0-bootstrap` | S3 state bucket + DynamoDB lock table |
| 1 | `phase1-foundation` | CloudTrail trail, KMS key, IAM executor role, Access Analyzer |
| 2 | `phase2-query-layer` | Athena workgroup, Glue database/table for CloudTrail queries |
| 5 | `phase5-notification-test` | Lambda + SNS for policy diff email notifications |
| 6 | `phase6-automation` | EventBridge-scheduled Lambda for batch policy generation |

Each phase is a separate Terraform root module. Phase outputs are passed as variables to subsequent phases (no remote state data sources).

## Prerequisites

- Python 3.9+
- Terraform >= 1.5.0
- AWS CLI configured with credentials for the target GovCloud account
- GNU Make

## Quick Start

### Install the CLI

```bash
cd cli
pip install -e ".[dev]"
```

### Generate a policy

```bash
# Analyze a role's CloudTrail activity for the last 30 days
trailpolicy generate --role-arn arn:aws-us-gov:iam::123456789012:role/MyRole

# Use Athena for large-scale analysis
trailpolicy generate \
  --role-arn arn:aws-us-gov:iam::123456789012:role/MyRole \
  --source athena \
  --athena-db trailpolicy_cloudtrail \
  --athena-table cloudtrail_logs \
  --athena-workgroup trailpolicy-workgroup

# Output as Terraform
trailpolicy generate \
  --role-arn arn:aws-us-gov:iam::123456789012:role/MyRole \
  -f tf -o policy.tf
```

### Compare against existing permissions

```bash
trailpolicy diff --role-arn arn:aws-us-gov:iam::123456789012:role/MyRole
```

### Validate a generated policy

```bash
trailpolicy validate --policy-file policy.json
```

## Deployment

trailpolicy deploys to 3 GovCloud organizations: `org-sbx` (sandbox), `org-fsa`, and `org-cod`. Each org gets its own Terraform state bucket in its root account.

### First-time setup (per org)

```bash
cd terraform

# 1. Bootstrap the state backend
make bootstrap ORG=org-sbx
# Copy the output values into environments/org-sbx/backend.hcl:
#   state_bucket_name  -> bucket
#   dynamodb_table_name -> dynamodb_table

# 2. Deploy Phase 1 (CloudTrail + KMS + IAM)
make apply PHASE=phase1-foundation ORG=org-sbx
# Copy Phase 1 outputs into environments/org-sbx/terraform.tfvars:
#   cloudtrail_bucket_name, cloudtrail_bucket_arn, kms_key_arn

# 3. Deploy Phase 2 (Athena query layer)
make apply PHASE=phase2-query-layer ORG=org-sbx

# 4. Build and deploy Phase 5 (notification test)
make package PHASE=phase5-notification-test
make apply PHASE=phase5-notification-test ORG=org-sbx

# 5. Build and deploy Phase 6 (automation)
make package PHASE=phase6-automation
make apply PHASE=phase6-automation ORG=org-sbx
```

### Makefile targets

All targets accept `PHASE=<phase-name>` and `ORG=<org-name>` (defaults: `phase1-foundation`, `org-sbx`).

| Target | Description |
|--------|-------------|
| `make bootstrap` | Create S3 state bucket and DynamoDB lock table |
| `make init` | Initialize Terraform backend for a phase |
| `make plan` | Preview infrastructure changes |
| `make apply` | Apply infrastructure changes |
| `make destroy` | Tear down infrastructure |
| `make package` | Build Lambda deployment zip for a phase |
| `make fmt` | Format all Terraform files |
| `make validate` | Validate all phase configurations |

### Lambda packaging

Lambda zips are built from the CLI source code. When you change CLI code, rebuild the zip before deploying:

```bash
# Build zip for a specific phase
make package PHASE=phase5-notification-test

# Or call the script directly
./scripts/build-lambda.sh phase5-notification-test
```

The script installs the `trailpolicy` package plus runtime dependencies (`boto3`, `jmespath`), strips test files and metadata, then creates `terraform/<phase>/lambda.zip`.

### Environment configuration

Each org has its own directory under `terraform/environments/`:

```
environments/
  org-sbx/
    backend.hcl        # S3 backend config (bucket, region, dynamodb_table)
    terraform.tfvars   # All phase variables for this org
  org-fsa/
    ...
  org-cod/
    ...
```

Variables required by later phases (e.g., `cloudtrail_bucket_arn` for Phase 2) are populated by copying outputs from earlier phases into the shared `terraform.tfvars`.

## CLI Reference

### `trailpolicy generate`

Generate a least-privilege IAM policy from CloudTrail activity.

```
Options:
  --role-arn TEXT          IAM role ARN to analyze (required)
  --days INTEGER          Lookback period, 1-90 (default: 30)
  --start-date TEXT       Start date YYYY-MM-DD (overrides --days)
  --end-date TEXT         End date YYYY-MM-DD (default: today)
  --region TEXT           AWS region (auto-detected if not set)
  --partition TEXT        AWS partition (auto-detected from credentials)
  --source [api|athena]   Event data source (default: api)
  --athena-db TEXT        Athena database (required if source=athena)
  --athena-table TEXT     Athena table (required if source=athena)
  --athena-workgroup TEXT Athena workgroup (required if source=athena)
  --include-advisor       Include IAM Access Advisor data (default: on)
  --no-advisor            Skip Access Advisor
  -f, --output-format     json or tf (default: json)
  -o, --output-file PATH  Write to file instead of stdout
  -v, --verbose           Enable debug logging
```

**Data sources:**
- `api` (default) -- Uses CloudTrail `LookupEvents` API. Limited to 90 days, 50 events per page, 2 TPS. Best for quick analysis of individual roles.
- `athena` -- Queries CloudTrail logs via Athena/Glue. Handles large volumes and longer time ranges. Requires Phase 2 infrastructure.

### `trailpolicy diff`

Compare a role's existing IAM policies against CloudTrail-observed activity.

```
Options:
  --role-arn TEXT          IAM role ARN to analyze (required)
  --days INTEGER          Lookback period, 1-90 (default: 60)
  --region TEXT           AWS region
  --partition TEXT        AWS partition
  -v, --verbose           Enable debug logging
```

Output categorizes every action as:
- **MATCHED** -- In the current policy and observed in CloudTrail (used permission)
- **UNUSED** -- In the current policy but not observed (candidate for removal)
- **MISSING** -- Observed in CloudTrail but not in the current policy (granted via other paths)

### `trailpolicy validate`

Validate a generated policy JSON file.

```
Options:
  --policy-file PATH      Path to JSON policy file (required)
```

Checks JSON syntax, IAM structure (Version, Statement, Effect, Action, Resource), action format (`service:Action`), and size limit (10,240 characters).

## Project Structure

```
trailpolicy/
├── cli/                              # Python CLI and core library
│   ├── pyproject.toml                # Package config (pip install -e .)
│   └── trailpolicy/
│       ├── cli.py                    # Click CLI commands
│       ├── config.py                 # Constants, partition detection
│       ├── core/
│       │   ├── action_mapper.py      # CloudTrail event -> IAM action mapping
│       │   ├── event_parser.py       # Raw event parsing and filtering
│       │   ├── cloudtrail.py         # LookupEvents API client
│       │   ├── athena.py             # Athena query backend
│       │   ├── resource_extractor.py # ARN extraction from request params
│       │   ├── policy_builder.py     # Policy assembly and compression
│       │   └── access_advisor.py     # IAM Access Advisor integration
│       ├── output/
│       │   ├── json_formatter.py     # JSON policy output
│       │   ├── terraform_formatter.py # Terraform HCL output
│       │   └── diff_reporter.py      # Policy diff computation and formatting
│       ├── data/
│       │   └── ct_iam_overrides.json # CloudTrail-to-IAM service name overrides
│       └── tests/                    # pytest test suite (108 tests)
├── terraform/
│   ├── Makefile                      # Deployment workflow automation
│   ├── environments/                 # Per-org config (org-sbx, org-fsa, org-cod)
│   ├── phase0-bootstrap/             # State backend (S3 + DynamoDB)
│   ├── phase1-foundation/            # CloudTrail + KMS + IAM + Access Analyzer
│   ├── phase2-query-layer/           # Athena + Glue catalog
│   ├── phase5-notification-test/     # Lambda + SNS diff notifications
│   ├── phase6-automation/            # EventBridge scheduled policy generation
│   └── modules/                      # Reusable Terraform child modules
│       ├── cloudtrail/
│       ├── access-analyzer/
│       ├── athena-query-layer/
│       ├── notification-test/
│       └── policy-generator-lambda/
└── scripts/
    └── build-lambda.sh               # Lambda zip packaging script
```

## Development

### Running tests

```bash
cd cli
pip install -e ".[dev]"
pytest trailpolicy/tests/ -v
```

108 tests cover the core library, output formatters, CLI commands, and input validation.

### Adding a new CloudTrail-to-IAM override

Some AWS services use CloudTrail event source names that don't map directly to IAM service prefixes. These overrides are in `cli/trailpolicy/data/ct_iam_overrides.json`:

```json
{
  "monitoring.amazonaws.com": "cloudwatch",
  "email.amazonaws.com": "ses",
  "tagging.amazonaws.com": "tag"
}
```

Add entries here when you encounter a service whose CloudTrail `eventSource` doesn't match its IAM action prefix.

### Terraform validation

```bash
cd terraform
make fmt        # Format all .tf files
make validate   # Validate all phases
```

## Known Limitations

- `iam:PassRole` is not tracked by CloudTrail and cannot be detected. The CLI warns about this -- add it manually if needed.
- IAM policies using `NotAction` cannot be precisely diffed. The diff report logs a warning when encountered.
- The CloudTrail LookupEvents API is limited to 90 days of history and 2 requests per second. Use the Athena source for larger analyses.
- Policy compression replaces groups of 6+ related actions with wildcards (e.g., `s3:Get*`) to stay under the 10,240-character IAM limit. The CLI warns when this happens.
- Resource extraction supports S3, DynamoDB, Lambda, and SQS. Other services fall back to `Resource: "*"`.

## License

Internal use only.
