Question 2.2: RDS Access Policies Review

I understand the goal is to give each user their own database access level via SailPoint, Entra ID and IAM Identity Center, using short-lived IAM tokens instead of passwords, which is a good approach. The problem is that none of the three policies includes "rds-db:connect", so users can't actually log in, and they give control over the database servers themselves instead of just access to the data. I wouldn't approve them without changes.

Below are my findings:

1. None of the policies includes "rds-db:connect". That's the only permission IAM database login needs, and "rds:*" doesn't cover it. Users won't be able to log in the way the diagram shows, and teams will probably fall back to shared passwords.
2. The policies work on the wrong layer. "rds:*" controls the RDS service (creating, changing and deleting databases), not what someone can do with the data.
3. The CRUB role has "rds:*" on "*". Someone who should only edit rows could delete the database, its snapshots and its backups. On AWS permissions it's almost identical to Admin.
4. CRUB and Admin can use "rds:ModifyDBInstance" to reset the master password. That gets around IAM, SailPoint and the whole access model.
5. CRUB and Admin can use "rds:ModifyDBSnapshotAttribute" and "rds:CopyDBSnapshot" to share a snapshot with another AWS account. That's an easy way to take a full copy of the data.
6. Admin has "cloudwatch:DeleteAlarms", which could switch off monitoring, and "sns:Publish" on "*", which could send fake alerts to any topic.
7. Every policy uses "Resource": "*", so it covers every database in the account, not just the one in the use case.
8. If everyone in a group logs in as the same database user, the database can't tell who ran a query.
9. Removing someone from the Entra ID group doesn't end their current AWS session or close database connections that are already open.
10. ReadOnly is mostly harmless, since "rds:Describe*" only shows settings, but it also can't log in to run SELECT.

What I would change:

1. Give each permission set only "rds-db:connect" for its own database user, for example "arn:aws:rds-db:eu-west-1:<ACCOUNT_ID>:dbuser:<DB_RESOURCE_ID>/readonly_user"
2. Create the three database users inside the database with the right grants: SELECT for readonly_user, SELECT, INSERT, UPDATE and DELETE for crud_user, and DDL for admin_user. Never give people the master user.
3. Remove "rds:*" from the user roles. Keep server management for a separate platform or break-glass role.
4. Keep "rds:Describe*" on ReadOnly only if people need to see the instance details in the console
5. Scope every resource to the specific database instead of "*"
6. Use a database user per person, or turn on database audit logging, so every query can be traced to someone
7. Give Admin a short session and just-in-time access with approval in SailPoint
8. Run regular access reviews in SailPoint, and don't let one person hold CRUB and Admin at the same time
9. Require SSL, keep the database private, and turn on deletion protection and automated backups

What could happen:

If they're approved as they are, users can't log in with IAM authentication, so people will likely go back to shared passwords. Meanwhile CRUB and Admin users could delete the database, copy all of the data through a shared snapshot, or reset the master password and skip every control.

With the changes above, each person logs in with a short-lived token as the right database role, access is granted and removed through SailPoint, and nobody can change or copy the database servers through these roles.
