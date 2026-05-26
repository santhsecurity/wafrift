# wafrift bench/aws-real

Real AWS WAFv2 bench: a tiny ALB-fronted Juice Shop on Fargate,
protected by `AWSManagedRulesCommonRuleSet` + SQLi + XSS rule groups.
The point: wafrift fires at the ALB DNS name, AWS WAF blocks or
allows, we record bypass rate next to the CF number.

## Status

**STUB — not deployed.** Activate when `AWS_ACCESS_KEY_ID` lands in
`C:\credentials\.env`. Until then this directory exists so the
operator knows where the AWS bench will live and what it looks like.

## What the Terraform builds

| Resource | Purpose | Cost / month |
|----------|---------|--------------|
| `aws_lb` (ALB) | Public entry point for wafrift | ~$18 |
| `aws_ecs_service` + Fargate task (Juice Shop image) | Vulnerable origin | ~$8 |
| `aws_wafv2_web_acl` | WebACL with managed rule groups | ~$5 base + $1/rule-group |
| `aws_wafv2_web_acl_association` | Binds ACL to ALB | $0 |
| `aws_cloudwatch_log_group` | WAF sample logs (per-request) | <$1 |

Roughly **$35–45 / month** if left running. Tear down after each
bench run with `terraform destroy` — typical bench session is 1–2
hours, so a single run costs cents.

## Why these managed rule groups

1. **`AWSManagedRulesCommonRuleSet`** — the OWASP-style baseline AWS
   recommends for every WebACL. Covers generic injection, LFI, RCE.
   If wafrift can't beat this, the tool has nothing to sell.
2. **`AWSManagedRulesSQLiRuleSet`** — focused SQLi detection. The
   "wafrift specialty" rule group.
3. **`AWSManagedRulesKnownBadInputsRuleSet`** — catches Log4Shell-
   style well-known exploit strings. Useful as an "obvious payload"
   reference — wafrift should pass these AT BASELINE without any
   evolution (because they're literal CVE strings, not the corpus).
4. **`AWSManagedRulesAnonymousIpList`** — *NOT* added. It would block
   the operator's own VPN/Tor and pollute results.

## Activate later

```powershell
# 1. AWS creds in env
$env:AWS_ACCESS_KEY_ID     = (Get-Content C:\credentials\.env | Select-String '^AWS_ACCESS_KEY_ID=' | ForEach-Object { ($_ -split '=', 2)[1] })
$env:AWS_SECRET_ACCESS_KEY = (Get-Content C:\credentials\.env | Select-String '^AWS_SECRET_ACCESS_KEY=' | ForEach-Object { ($_ -split '=', 2)[1] })
$env:AWS_DEFAULT_REGION    = "us-east-1"

# 2. terraform init && plan && apply
cd C:\Santh\software\wafrift\bench\aws-real\terraform
terraform init
terraform plan -out plan.tfplan
terraform apply plan.tfplan

# 3. ALB DNS name printed as output → point wafrift at it
$alb = terraform output -raw alb_dns_name
cargo run --release -p cli -- bench-waf --target "https://$alb"

# 4. ALWAYS tear down after benching
terraform destroy
```

## Footnote: Akamai

Akamai App & API Protector is SaaS-only — no self-host. Pending a
sales-channel trial account, we cite generalization from CF + AWS
results. The wafrift engine is WAF-agnostic by design.
