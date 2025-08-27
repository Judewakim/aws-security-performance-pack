# AWS Security Performance Pack

**AWS Security Performance Pack** — a CDK (Python) project that provisions a security foundation for AWS accounts (GuardDuty, Security Hub, Config, CloudTrail, Inspector, alerting, and Conformance Packs). This repository contains a CDK app, a Conformance Packs stack, scripts, and tests. (Repository contents referenced: `app.py`, `security_performance_pack/`, `conformance-pack-uris.json`, `conformance-packs/`, `scripts/`, `requirements.txt`). ([GitHub][1])

---

## What this project does

This CDK project (Python) implements an opinionated, ready-to-deploy security baseline for an AWS account. At a high level it:

* Creates GuardDuty detectors and members (threat detection).
* Enables Security Hub (central dashboard and standards).
* Configures AWS Config with:

  * Storage of Config data in S3 bucket (snapshots & history)
  * IAM role for AWS Config
  * Configuration recorder and delivery channel
  * Deploys AWS Security & Compliance Conformance Packs
* Enables CloudTrail for audit logging.
* Enables Amazon Inspector vulnerability scanning.
* Configures alerting (SNS topics / subscriptions).
* Adds Conformance Packs (AWS-managed and/or custom) — with provision to upload pack templates to an S3 bucket for AWS Config to consume.
* Includes helper scripts and tests for local development and packaging.

> Note: file and folder names in the repo include `app.py`, `cdk.json`, `conformance-pack-uris.json`, `conformance-packs/`, `security_performance_pack/`, `scripts/`, `requirements.txt`. ([GitHub][1])

---

## Requirements

* AWS account and permissions to create IAM roles, S3 buckets, CloudFormation stacks, Config resources, Security Hub, GuardDuty, Inspector, CloudTrail, SNS, etc.
* AWS CLI v2 (recommended) configured for your AWS Identity Center (SSO) profile if you use SSO.
* Node.js and the AWS CDK CLI (v2) installed.
* Python 3.8+ and `pip`.
* A virtual environment (`.venv` recommended).

---

## Quick start

1. Clone the repo:

```bash
git clone https://github.com/Judewakim/aws-security-performance-pack.git
cd aws-security-performance-pack
```

2. Create & activate a Python virtualenv:

```bash
# Linux / macOS
python -m venv .venv
source .venv/bin/activate

# Windows (CMD)
python -m venv .venv
.venv\Scripts\activate.bat

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Authenticate with AWS (if using IAM Identity Center / SSO):

```bash
aws sso login --profile <your-profile>
# or ensure you have valid credentials for the profile you plan to use
```

5. Bootstrap the environment (one-time per account/region):

```bash
# Make sure AWS_PROFILE env var is set in the shell
set AWS_PROFILE=<your-profile>       # Windows CMD
$env:AWS_PROFILE = "<your-profile>"  # PowerShell
export AWS_PROFILE=<your-profile>    # Linux/macOS

cdk bootstrap aws://<ACCOUNT_ID>/<REGION>
```

6. Deploy:

```bash
cdk deploy SecurityPerformancePackStack --profile <your-profile>
# or
cdk deploy --all --profile <your-profile>
```

---

## Conformance packs (AWS-managed packs)

AWS-managed conformance pack templates are referenced by AWS as S3-hosted YAMLs. CloudFormation `CfnConformancePack` **requires** `template_s3_uri` to be an S3 URI (`s3://bucket/key`) — *not* an HTTPS URL. Because of this, this project includes logic to upload the conformance pack YAML files into an S3 bucket (see `conformance-packs/` and `conformance-pack-uris.json`) and then point `CfnConformancePack` at the `s3://` URIs.

If you plan to use AWS-managed conformance packs (AWS Foundational, CIS, NIST, SOC2, S3 best practices, etc.), the repository automates:

* Downloading / including pack templates under `conformance-packs/`, and
* Uploading them to the stack bucket (so `template_s3_uri` is `s3://<bucket>/<template>.yaml`) before creating the packs.

**Important caveat:** Conformance packs can be slow to create and sometimes fail deletion. See Troubleshooting below.

---

## Notable files & structure

* `app.py` — CDK app entrypoint; wires stacks together.
* `security_performance_pack/` — main stack implementation: GuardDuty, Security Hub, Config, CloudTrail, Inspector, SNS alerting, etc.
* `conformance-packs/` — local folder for conformance pack YAML files (managed or custom).
* `conformance-pack-uris.json` — bookkeeping for pack URIs used by stacks.
* `scripts/` — helper scripts (e.g., packaging, utilities).
* `requirements.txt` — Python deps for the CDK app.
* `cdk.json` — CDK app config.

---

## Troubleshooting & common pitfalls

### SSO / Identity Center tokens

If you use AWS SSO (Identity Center) you may hit `ExpiredToken` or `The security token included in the request is expired`. Typical steps that resolve this:

1. Run `aws sso login --profile <profile>` and complete browser authentication.
2. Update `.aws\credentials` with the new `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` 
3. If problems persist, clear stale SSO caches (e.g., `%USERPROFILE%\.aws\sso\cache\*.json`) and re-run `aws sso login`.

If CDK still cannot find the refreshed credentials, run `aws sts get-caller-identity --profile <profile>` to confirm CLI credentials before running `cdk`.

### CDK Python imports

If you get `ModuleNotFoundError: No module named 'aws_cdk'` when running CDK synth/deploy, ensure you installed the Python dependencies from `requirements.txt` into the active virtualenv (`.venv`).

### AWS Config recorder / delivery channel order

AWS Config is picky: both the configuration recorder and a delivery channel must be present and in the expected states. The recommended pattern:

1. Create the S3 bucket and IAM role first,
2. Create the delivery channel (points to the bucket),
3. Create the configuration recorder (points to the role).

Avoid forcing the wrong `add_dependency` direction; circular or inverted dependencies can cause `NoAvailableConfigurationRecorderException` or `NoAvailableDeliveryChannelException`.

### Conformance pack deletion failures

Conformance Packs can be slow to delete and sometimes fail (CloudFormation shows `DELETE_FAILED` with `DeleteConformancePack` errors). If you see a stuck pack (e.g., `PCIDSSPack`) during `cdk destroy --all`:

* Go to AWS Console → Config → Conformance packs and manually delete the problem pack.
* Check Config Rules (the pack creates many) and delete any leftover rules.
* Retry `cdk destroy --all`.

If you want stack destroy to always succeed without waiting for pack deletions, consider applying `RemovalPolicy.RETAIN` to conformance pack resources so deletion of the stack does not attempt to delete packs automatically.

---

## Best practices & recommendations

* Use a dedicated admin / bootstrap account to run CDK bootstrap once per account/region.
* Use `AWS_PROFILE` in the terminal rather than repeatedly using `--profile` with CDK (helps CDK find SSO creds more reliably on some platforms).
* When developing, run `cdk diff` and `cdk synth` frequently — conformance packs and Config resources can cause long-running changes.
* If you add custom conformance packs, include them under `conformance-packs/` and add entries to `conformance-pack-uris.json` as needed.

---

## Testing

The repository includes a `tests/` directory for unit/integration tests (see `tests/`). Run tests with your preferred test runner (e.g., `securitypack-tester`).

---

## How to contribute

1. Fork the repository.
2. Create a feature branch.
3. Run and test locally (see Quick start).
4. Open a PR with changes and a short description.

---

## License & contacts

* This repo is provided as-is. Add your license file if you wish to open-source.
* For questions, contact: *[LinkedIn](https://www.linkedin.com/in/jude-wakim)*

