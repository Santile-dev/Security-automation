Question 3: Restrict AWS to eu-west-1

I understand the goal is to make sure all AWS resources are created in eu-west-1 only, which helps with data residency, cost control and keeping the attack surface small. An SCP is the right tool for this, because it applies to every account in the organisation and even account admins can't get around it.

How the SCP works:

The policy in region_restriction_scp.json denies every action when "aws:RequestedRegion" is anything outside "eu-west-1".

1. Global services are excluded through "NotAction". Services like "iam:*", "organizations:*", "route53:*", "cloudfront:*", "sts:*" and "support:*" are global and their calls go through us-east-1. Blocking them would lock people out of IAM, billing and support.
2. "acm:*" is excluded because CloudFront only accepts certificates from us-east-1.
3. I deliberately did not exclude "kms:*" or "config:*". Both are regional, so excluding them would let people create keys or Config rules in other regions.
4. "ArnNotLike" on "aws:PrincipalARN" lets "OrganizationAccountAccessRole" and a "BreakGlassAdmin" role through, so there is always a way back in if something goes wrong.

This is how I would deploy it:

1. Check what is already running outside eu-west-1, using AWS Config, Resource Explorer or Cost Explorer by region. Anything found needs to move or be accepted before the SCP goes on.
2. Create the break-glass role in every account, protect it with MFA, and alert on every use.
3. Attach the SCP to a test OU with one sandbox account first. Confirm that eu-west-1 works, that other regions are denied, and that IAM, billing and support still work.
4. Check CloudTrail for "AccessDenied" errors to catch any global service that is missing from the list.
5. Roll it out to the other OUs one at a time, non-production before production. Never attach it to the root until it has been proven.
6. Manage the SCP through Terraform or CloudFormation, so changes are reviewed and tracked.

Some other things to keep in mind:

1. SCPs do not apply to the management account, so keep workloads out of it.
2. SCPs do not affect resources that already exist in other regions. They only block new API calls.
3. Also disable unused opt-in regions in each account, as an extra layer.
4. The global services list changes as AWS adds services, so review it now and then against the AWS documentation.
5. An SCP has a 5,120 character limit. This one is about 650 characters.
