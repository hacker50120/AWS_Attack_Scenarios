## Here are some best practices to follow:

1. **Root user:** The root user in AWS is the initial account created when you sign up for AWS services. It
has full, unrestricted access to all resources and services within the AWS account. However, due to
security best practices, it's recommended to avoid using the root user for routine tasks and operations.
Root user is reserved for exceptional situations or emergencies when no other access is available. Here
are scenarios you would need root access:
Billing: Activate IAM access to the Billing and Cost Management console. Once this done, you can
delegate Billing access to IAM users.
Account Settings: Change your account settings such as account name, email address, root user
password, and root user access keys
Restore IAM user permissions. If the only IAM administrator accidentally revokes their own permissions,
you can sign in as the root user to restore those permissions.
Closing an Account: Only root user can close an AWS account
Unmanageable KMS Keys: If you accidentally remove root user from KMS Key Policy, the key becomes
unusuable and unmanageable. You can recover it by contacting AWS Support as the root user
Restore Access: If your S3, SQS, SNS or other resource-based policies (except for KMS) denies all the
principals, then only a root user can modify or delete the resource-based policy
GovCloud: Sign up for AWS GovCloud (US)

2. Centralized Access Control: IAM allows you to manage access to all your AWS services, resources, and
regions from a central location.

3. Password Policies: Enforce Password Policies and MFA to comply with your organization requirements

4. Policy Types: Policies are JSON documents that define permissions using IAM Policy Language. There
are several types of policies that you can use to control access to AWS resources.
Identity-Based Policies: These policies are attached to IAM users, groups, and roles. They define
permissions for specific identities within your AWS account and provide fine-grained control over who
can perform specific actions on which resources.
Resource-Based Policies: These policies are attached directly to AWS resources such as S3 buckets,
Lambda functions, and SQS queues. They define who has access to the associated resource and what
actions they can perform. Resource-based policies are also used to grant cross-account access and often
allow other AWS accounts or services to interact with your resources.

AWS Managed Policies: AWS provides a set of managed policies that cover common use cases and best
practices. These policies are created and managed by AWS and can be attached to IAM users, groups, or
roles in your account. They are designed to help you quickly implement security controls without having
to write custom policies from scratch.
Customer Managed Policies: These are custom policies that you create and manage in your AWS
account. They provide flexibility in defining permissions tailored to your specific requirements. You can
attach customer managed policies to IAM users, groups, or roles.
Inline Policies: Inline policies are policies that are embedded directly into an IAM user, group, role, or
resource. Unlike managed policies, inline policies are part of the identity or resource definition. They are
useful when you want to ensure that a policy is always associated with a specific identity or resource.
Session Policies: Session policies are used in the context of temporary security tokens issued by AWS
Security Token Service (STS). When an IAM role is assumed by an entity, you can apply session policies to
restrict the permissions further during that specific session.
Trust Policy: Trust policy is attached to an IAM role. It specifies the trusted entities (principals) that are
allowed to assume the role. Trust policies play a critical role in establishing trust relationships between
IAM roles and the entities that need to assume those roles. By configuring the trust policy correctly, you
can ensure that only authorized entities can temporarily take on the permissions associated with the
role.
Service Control Policy (SCP): SCPs are useful in a multi-account environment in an Organization. These
policies are particularly useful for centrally enforcing security and compliance requirements across
multiple accounts. SCPs do not grant permissions but limit permissions that identity-based policies or
resource-based policies grant to entities within an account. We will discuss more in Organization
module.

5. Policy Structure: The structure of a policy typically involves specifying the following elements:
Principal: This is the entity to which the permission applies. It can be an IAM user, another account, an
IAM role from another AWS account (cross-account), an AWS service, federated users, or even an
anonymous identity. Principal is required only for resource-based policies and IAM role trust-policies. For
identity-based policies, principal is not specified in the policy document; when you apply policies to a
user, group or role, IAM knows who the principal is.
Effect: This specifies whether the principal is allowed ("Allow") or denied ("Deny") access to specified
actions.
Action: This lists the action that the principal is allowed to perform (or denied)
Condition: This optional element allows you to specify additional conditions that must be met for the
policy to be applied. For example, you can specify IP address ranges, require the use of Multi-Factor
Authentication (MFA), require the use of Secure Transport (TLS/SSL) and so forth

6. Scalable Policy Management: In an environment with large number of resources and users, to enforce
principles of least privilege, you can manage security in two ways:

Role Based Access Control (RBAC): Here, based on a person's job-role, you customize the policy to grant
minimum permission required for performing the job function. However, the disadvantage with this
model is that when employees add new resources, you must update policies to allow access to these
resources.
Attribute Based Access Control (ABAC): In the ABAC model, permission is applied based on attributes
(also known as Tags). Here, tags are attached to the resources and the principals and ABAC policies are
designed to allow operations when the principal's tag matches the resource's tag. For example, allow an
user to start or stop EC2 instances only when the cost center's match.
With ABAC, permissions scale and requires fewer policies. ABAC is recommended for rapidly growing
environment and helps with situations where policy management is cumbersome.

7. Permissions Boundary: Permission boundaries control the maximum permissions that can be
delegated to an identity (user or role) within an AWS account. Permission boundaries do not grant
permissions; but they put a fence around maximum permissions that an identity-based policy can grant
an entity.

8. Policy evaluation logic:
By default, all requests are implicitly denied except for the root user, which has full access. An explicit
allow in an identity-based or resource-based policy overrides this default. If a permissions boundary,
Organizations SCP, or session policy is present, it might override the allow with an implicit deny.
An explicit deny in any policy overrides any allows.

9. Cross-account policy evaluation logic

Here, the resource is in one account (resource-owner) and the caller is in another account (calling-
account)

Cross-Account Access using Resource-based policy: The owner of a resource can provide access by
creating a resource-based policy. This policy involves specifying the principal in the other account, which
usually refers to the entire account, as well as IAM users or roles.
Additionally, the calling account needs to authorize its principal to access the resource. For cross-account
access to function properly, both accounts must approve the request. Specifically, the resource owner
needs to permit access to the resource, and the calling account must grant permission to its principals
for accessing the same resource; otherwise, the access is denied.
Cross-Account Access Using IAM Roles: In this scenario, the owner of the resource establishes an IAM
role with the required permissions. Within the role's trust policy, the resource owner gives permission to
the principal in the calling account to assume the role.
The calling account then needs to authorize its principals to assume the role granted by the resource
owner. The principal in the calling account can utilize the temporary credentials obtained through the
"assume role" operation to access the resource.
For this cross-account access arrangement to work, both the resource owner's account and the calling
account must approve the access request; otherwise, the access is denied.

10. Access Keys: Access keys in AWS serve as a means of authentication and authorization for accessing
AWS resources and services. They consist of two components: an access key ID and a secret access key.
The purpose of access keys is to provide CLI and programmatic access to AWS resources and services,
particularly from applications, scripts, tools, or services that interact with AWS APIs.

11. Long-lived Access Keys: Access keys assigned to users are considered long-lived because they do not
expire automatically unless you manually rotate them. While access keys can be rotated, it requires
manual intervention to change keys periodically. This can be cumbersome and prone to human error.
Fixed Permissions: The access keys gain all the privileges granted to the user. There is no way to
dynamically scope the permissions needed for a specific task
Protection: Access keys need to be securely managed to prevent unauthorized access. They should not
be embedded in code repositories or shared openly.
Not Ideal for Elastic Environments: Access keys are not well-suited for dynamically scaled environments,
as their manual rotation and long-lived nature can pose security risks.
To address the security concerns associated with long-lived access keys, you can request temporary
security credentials.

12. Temporary Security Credentials: Temporary credentials are typically valid for a predefined period,
which you can specify when requesting the credentials. After this period, the credentials expire, reducing
the potential exposure risk if the credentials were to be compromised.
Temporary credentials consist of the following components: Access Key ID, Secret Access Key, and a
Session Token
The Session Token is a unique token that accompanies the temporary credentials. It is used to
authenticate the session and establish trust.
You can generate temporary credentials using STS service – typically when you assume a role.
These credentials are automatically rotated, reducing the risk of unauthorized access due to
compromised or leaked credentials.
You can optionally require Multi-Factor Authentication (MFA) before temporary credentials are issued.
This additional authentication step helps ensure that the user attempting to assume the role is indeed
authorized to do so.

13. Here's a simplified walkthrough of how to utilize temporary credentials:
Prepare IAM Roles: Set up IAM Roles tailored for specific job functions. In the role's trust policy, allow
the entire account or users (enable MFA) or services to assume this role.
Configure IAM User: For a user, configure long-term access keys. Use an identity-based policy to restrict
their permissions exclusively to assuming specific roles.
Credentials: When the user requires access to resources, they initiate the process by assuming the
appropriate role. During this, they provide Multi-Factor Authentication (MFA) details and receive
temporary credentials.

Resource Access: With the received temporary credentials, the user gains access to the intended
resources.
Time-Limited Access: It's important to note that the temporary credentials are valid only for a set time
and expire automatically. This limited duration ensures heightened security.
Added Security Layer: If a user's long-term keys are compromised, the credentials have permission only
to assume specific roles. Attacker can use the credentials only if they know the role ARN and MFA code.
Mitigated Impact: In case the temporary credentials are compromised, the attacker's access is restricted
to the specified timeframe until the credentials naturally expire.

14. Revoking Access to Temporary Credentials: When temporary credentials are accidentally made
public, you need to revoke permissions that apply to the credentials.
You cannot delete temporary credentials. So, the only way to deny access is to update the permission
policy of the creator of temporary credentials. Creator refers to the identity that was used when calling
STS APIs to generate temporary credentials.
In case of a role, you can attach a deny all policy to the role. If a user identity was used to generate
temporary credentials, you could attach a deny all policy to the user.
You can also deny access based on time. For example, you can attach a deny all policy that applies only if
the temporary credential was issued before a specific time (using aws:TokenIssueTime variable). This
approach is beneficial as existing legitimate users of role can simply request new credentials and
continue. At the same time, the leaked credentials are no longer usable.

15. Granting Third-Party Cross-Account Access: When extending permissions using IAM Role to a third-
party account—such as a consulting firm, vendor, or partner—for role assumption in your account, it's

recommended to incorporate a condition into the trust policy. This condition should involve validating
the "ExternalId" variable. The value for this "ExternalId" is supplied by the third party in advance. By
doing so, you ensure that the assume role operation is allowed only if the provided "ExternalId" value
matches the agreed-upon value. This approach serves as a safeguard against confused deputy issues and
provides an additional layer of defense against unauthorized access attempts.

16. Granting AWS Service Access to Your Resources: When you allow AWS service access to your
resources (for example, SNS Topic publishing a message to SQS or S3 bucket notifying SQS when a new
object is added to the bucket), it's important to incorporate a condition that verifies the Source ARN and
Source Account. This precaution is taken to prevent the misuse of an AWS service by another account to
access your resources. Furthermore, implementing the Source ARN check guarantees that only
designated resources—like a specific SNS Topic or S3 bucket—are authorized for access.

17. Session Token Service (STS): STS is a service that enables you to request temporary, limited-privilege
credentials for users, EC2 instances, and other principals - typically when they assume a role. STS is a
global service and by default all requests go to https://sts.amazonaws.com (hosted in N.Virginia). To
improve resiliency, performance, and to reduce latency, you can also use the regional STS endpoints.

The temporary credentials issued by STS consists of Access Key, Secret Key, and Session Token. These
credentials can be used globally as permitted by the role permissions and applicable boundary set by
boundary permissions, SCPs and Session Policies.
Here are some of the STS actions:
AssumeRole: Principals specified the IAM Role Trust Policy can request for temporary credentials to
access resources in your account. If the trust policy requires MFA, the caller must include the MFA device
details and MFA code.
Trust policy condition for MFA:
"Condition": {"Bool": {"aws:MultiFactorAuthPresent": true}}
The session policy is optional, and you can use it to limit permissions granted to the credentials
For third party cross-account access to your resources, the caller needs to provide ExternalId (if enforced
by the trust policy)
GetSessionToken: With GetSessionToken, existing IAM users can request temporary credentials. This call
is useful when certain API actions require MFA, and you need to get new credentials that are validated
with MFA. As part of the GetSessionToken call, the user needs to submit an MFA code. Using these
temporary credentials, IAM users can then make programmatic API calls that require MFA
authentication.
AssumeRoleWithSAML: A variant of AssumeRole. Here, the caller identity is maintained in an external
SAML 2.0 compliant identity store. This API is used for generating temporary AWS credentials for users
with corporate credentials.
AssumeRoleWithWebIdentity: A variant of AssumeRole. The user is authenticated in a mobile or web
app with a web identity provider. This API is used for generating temporary AWS credentials for users
with web identity (example google, amazon, facebook and so forth)
GetFederationToken: GetFederationToken is useful when you need to implement a custom identity
broker. Here, the corporate user will interact with identity broker application on-premises. This
application will authenticate the user with corporate identity provider. The identity broker will then call
GetFederationToken API using the identity broker’s long-term credentials (accesskey and secret access
key). The temporary credentials is used by the user and on-premises applications to access AWS
resources.
This credential also allows console access. So, users with these credentials can login automatically to the
AWS web management console.
Session duration can vary from 15 minutes to 36 hours (much longer than AssumeRole’s 12 hours)
A session policy is required for this call. The temporary credentials permissions are the intersection of
requester identity-policies and session policy. If you don’t specify a session policy, the resulting
credentials do not have any permissions.

18. MFA Access with CLI and SDKs: When working with CLI and SDKs, if a specific API action require
MFA, the user can use their credentials to call STS GetSessionToken and provide MFA details. The new
credentials issued by STS is now validated with MFA and can be used for API calls that need MFA.

Here is one example: aws sts get-session-token --duration-seconds 900 --serial-
number "YourMFADeviceSerialNumber" --token-code "CodeFromMFAdevice"

19. Single Sign On with Identity Center: AWS Identity Center allows you to integrate with your existing
identity sources, such as Microsoft Active Directory and other SAML 2.0 compliant identity providers.
This enables you to leverage your existing identity provider for authentication, reducing the need to
create and manage separate sets of user credentials.

20. Application Authentication: With Amazon Cognito, you can add user sign-up and sign-in features and
control access to your web and mobile applications. Amazon Cognito provides an identity store that
scales to millions of users. It also enables users to login via social identity providers, such as Apple,
Facebook, Google, and Amazon and enterprise identity providers via SAML and OIDC. Amazon Cognito is
a standards-based identity provider.
21. IAM Access Analyzer: IAM Access Analyzer is a service provided by Amazon Web Services (AWS) that
helps you analyze resource-based access policies to determine how resources can be accessed by IAM
roles, users, and external principals. Its primary purpose is to enhance security and compliance by
identifying potential unintended access to resources within your AWS environment.
Identifying Unintended Access: IAM Access Analyzer uses automated reasoning to analyze your
resource-based policies and identify any potential access paths that might lead to unintended access. It
helps detect configurations that could result in data exposure, security vulnerabilities, or compliance
violations.
Policy Validation and Compliance: It assists in validating resource policies against best practices and
security standards. This is particularly important for maintaining compliance with regulations and
industry standards. It can report the following findings: Security Warnings, Errors, General Warnings,
along with suggestions to correct the findings. This capability is integrated into policy generation and
editing tools in AWS
Security Improvement: Access Analyzer can check the CloudTrail logs and generate policies based on the
access patterns. This allows you to identify existing policies that might be granting excessive privileges
and you can then modify the policies and tighten security.
Cross-Account and External Principal Analysis: Helps you identify the resources in your organization and
accounts, such as Amazon S3 buckets or IAM roles, shared with an external entity outside of your
organization. This helps you identify unintended access to your resources and data.
Continuous Monitoring: If you add a new policy , or change an existing policy, IAM Access Analyzer
analyzes the new or updated policy within about 30 minutes. It also analyzes all resource-based policies
periodically. Access Analyzer is a regional resource and you would need to enable in all regions
Resources Analyzed: S3 Buckets, IAM Roles, KMS Keys, Lambda functions, other resources that support
resource-based policies. In addition, it checks EBS Volume Snapshots, RDS DB and Cluster Snapshots, ECR
Repositories, EFS file systems

22. IAM Credential Reports: IAM Credential Reports provides insights into the security status and usage
of access credentials within your AWS account. The reports offer valuable information about IAM users,
status of various credentials including passwords, access keys and MFA devices.
You can use credential reports to assist in your auditing and compliance efforts such as password and
access key rotation, MFA usage, identifying inactive users and credentials.
Credential reports are formatted as comma-separated values (CSV) files and contains username, user
ARN, user creation time, password enabled (for console access), password last used, password last
changed, password next rotation, MFA active flag, access key status, access key last rotated, last used
date, and more
The credentials report are cached for four hours by IAM. A new report is generated only if there are no
previous reports for the account or if the previous report is older than four hours. You can generate and
download Credential reports from IAM Console and through CLI and APIs
aws iam generate-credential-report
aws iam get-credential-report

23. IAM Access Advisor: As an administrator, you might grant permissions to IAM resources (roles, users,
user groups, or policies) beyond what they require. IAM Access Advisor provides last accessed
information to help you identify unused permissions so that you can remove them.
You can use last accessed information to refine your policies and allow access to only the services and
actions that your IAM identities and policies use. This helps you to better adhere to the best practice of
least privilege. You can view the last accessed information for identities or policies that exist in IAM or
AWS Organizations.

# References:
```
IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
https://docs.aws.amazon.com/accounts/latest/reference/root-user-tasks.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-
account.html
https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-
perms.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html
https://aws.amazon.com/about-aws/whats-new/2019/06/now-use-iam-access-advisor-with-aws-
organizations-to-set-permission-guardrails-confidently/
```
---

## Can Create Resource-based Policy using this tool

https://awspolicygen.s3.amazonaws.com/policygen.html

### Only the IAM use test1 can access the bucket
```{
  "Id": "Policy1736772298013",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1736772294126",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::abhishek-iam",
      "Principal": {
        "AWS": [
          "arn:aws:iam::571600850800:user/test1"
        ]
      }
    }
  ]
}

```

aws s3 ls s3://abhishek-iam --profile test1 - can list all the buckets.

Setting Permissions boundary

https://docs.aws.amazon.com/images/IAM/latest/UserGuide/images/EffectivePermissions-rbp-boundary-id.png

Now, the Resource base policy is: Can perform all the actions “S3:*”
Abd boundary base policy is: Can list Only S3 buckets & objects

Now, the effective policy is that only S3 buckets can be read.

