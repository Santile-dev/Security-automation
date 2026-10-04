cat > risk-review/ssm-policy-review.md <<'EOF'
Question 2.1: SSM Automation Policy Review

I understand the pipeline needs to deploy to EC2 through SSM, and using a tag to decide which servers it can touch which is a good approach. The problem is that the policy, lets the role get around that tag, and it gives a lot more access than a deployment needs. I wouldn't approve it without changes.

Below are my findings:

1. The role is allowed to "ec2:CreateTags" on "arn:aws:ec2:eu-west-1:22222222222:instance/*", so it can tag any instance. "ssm:SendCommand" is meant to run only on instances with "ssm:resourceTag/AutomationAllowed": "true", but since the role can add that tag itself, it can unlock any server it wants. This is the biggest problem.

2. Looking at the "s3:GetObject" and "s3:PutObject" are allowed on "arn:aws:s3:::*/*", which means any object in any bucket. It can read data it has no reason to see, or write it out to a bucket someone else owns.

3. The "ssm:SendCommand" is allowed with "arn:aws:ssm:eu-west-1::document/AWS-RunShellScript" and "arn:aws:ssm:eu-west-1::document/AWS-RunPowerShellScript". These let you run literally any command as root or SYSTEM. A deployment should only run the steps it's meant to.

4. The resource "arn:aws:ssm:eu-west-1:839864138277:document/customer-*" belongs to a different account. Whoever controls that account can change those documents, and the changes would run on our servers.

5. The actions "ec2:StartInstances", "ec2:StopInstances" and "ec2:RebootInstances" apply to every instance in the account, not just the tagged ones. One mistake in the pipeline could take down unrelated production servers.

6. The actions "ssm:ListCommandInvocations" and "ssm:GetCommandInvocation" on "*" let the role read the output of every command run in the account. If someone else's script prints a password, this role can see it.

7. A few ARNs are broken. "arn:aws:ec2:eu-west-1:22222222222:instance/*" has 11 digits instead of 12, "arn:aws:s3::: automated-deployment*" has a space in it, and "arn:aws:logs:eu-west-1:839864138277:log-group:/aws/ssm/deployment/*" points at a different account. 

8. The diagram mentions starting an SSM Automation, but the policy doesn't include "ssm:StartAutomationExecution" or "iam:PassRole". When someone adds "iam:PassRole" later, it's easy to make it too broad.

9. The "DenyHighRiskSSM" statement looks reassuring, but most of those actions, like "ssm:StartSession" and "ssm:PutParameter", were never allowed in the first place. It doesn't add much real protection.

10. The pipeline itself becomes a way into three AWS accounts. Anyone who can edit or trigger it can run commands on those servers.

What I would change:

1. I would remove "ec2:CreateTags", and add a "Deny" on "ec2:CreateTags" and "ec2:DeleteTags" for the "AutomationAllowed" and "Application" tag keys

2. Limit "s3:GetObject" and "s3:PutObject" to "arn:aws:s3:::automated-deployment-<ACCOUNT_ID>/*" only

3. Only allow "arn:aws:ssm:eu-west-1:<ACCOUNT_ID>:document/Automated-Deployment-Dev", not the run-anything documents

4. Use documents that each account owns, rather than pulling "customer-*" from another account

5. Add the same "aws:ResourceTag/AutomationAllowed": "true" condition to "ec2:StartInstances", "ec2:StopInstances" and "ec2:RebootInstances"

6. Fix the account IDs and ARNs, and roll the policy out per account through Terraform or CloudFormation

7. If automation is really needed, allow "ssm:StartAutomationExecution" for that one document, and "iam:PassRole" only for the execution role with "iam:PassedToService": "ssm.amazonaws.com"

8. Lock the IRSA trust down to the exact Kubernetes service account, and add "aws:SourceAccount" to the SSM trust

9. Protect the pipeline with branch protection and approvals before deploying, and keep dev and prod roles separate

10. Set up CloudTrail alerts for any "ssm:SendCommand" using "AWS-RunShellScript", and for any "ec2:CreateTags" on the automation tags

What could happen:

If it's approved as it is, a compromised pipeline, or even an honest mistake, could get root on any server, copy data out of S3, stop production servers, or run code someone else controls. Some deployments would also fail because of the broken ARNs.

With the changes above, the pipeline can only run the approved deployment on servers that are tagged for it, using its own bucket and logs, and it has no way to give itself more access.
