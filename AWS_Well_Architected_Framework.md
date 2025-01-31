# AWS Well-Architected Framework Security Pillars

Aadditional attack scenarios and mitigations focused on IAM, Encryption, Logging, and Least Privilege, with examples of how to use AWS tools like GuardDuty, Security Hub, and AWS Config. These scenarios are designed to align with the AWS Well-Architected Framework security pillars.

---


### **1. IAM (Identity and Access Management)**

#### **Attack Scenarios**
1. **Privilege Escalation via `iam:PassRole`**  
   - **Attack**: An attacker with `iam:PassRole` permission assigns a high-privilege role to a compromised EC2 instance.  
   - **Impact**: Full AWS account takeover.  
   - **Mitigation**: Restrict `iam:PassRole` to specific roles; use conditions like `aws:RequestedRegion`.

2. **Over-Permissive Inline Policies**  
   - **Attack**: Inline policies with `*:*` permissions allow attackers to perform any action.  
   - **Impact**: Unrestricted AWS access.  
   - **Mitigation**: Use managed policies; audit with **IAM Access Analyzer**.

3. **Inactive Access Keys**  
   - **Attack**: Dormant access keys with high privileges are exploited.  
   - **Impact**: Unauthorized API access.  
   - **Mitigation**: Rotate keys; use temporary credentials (STS).

4. **MFA Not Enforced**  
   - **Attack**: Compromised passwords grant API/dashboard access.  
   - **Impact**: Account hijacking.  
   - **Mitigation**: Enforce MFA for all IAM users.

5. **Role Trust Policy Abuse**  
   - **Attack**: Edit role trust to allow unauthorized principals (e.g., external accounts).  
   - **Impact**: Cross-account privilege escalation.  
   - **Mitigation**: Validate trust policies; use `aws:PrincipalArn`.

6. **Service-Linked Role Backdoors**  
   - **Attack**: Over-permissive roles for services (e.g., `AWSServiceRoleForEC2`).  
   - **Impact**: Lateral movement.  
   - **Mitigation**: Restrict service-linked role permissions.

7. **Password Policy Weakness**  
   - **Attack**: Brute-force IAM user passwords.  
   - **Impact**: Console access.  
   - **Mitigation**: Enforce strong passwords; use SSO instead.

8. **AssumeRole Without External ID**  
   - **Attack**: Cross-account role assumption without validation.  
   - **Impact**: Unauthorized access.  
   - **Mitigation**: Require `sts:ExternalId` for third-party roles.

9. **Access Key Leak via GitHub**  
   - **Attack**: Developers accidentally commit keys to public repos.  
   - **Impact**: API access abuse.  
   - **Mitigation**: Use GitGuardian; rotate keys regularly.

10. **IAM Access Analyzer Ignored**  
    - **Attack**: Unused permissions/findings not remediated.  
    - **Impact**: Expanded attack surface.  
    - **Mitigation**: Enable and act on Access Analyzer reports.

---

### **2. Encryption**

#### **Attack Scenarios**
1. **Unencrypted S3 Buckets**  
   - **Attack**: Access plaintext data in public S3 buckets.  
   - **Impact**: Sensitive data exposure.  
   - **Mitigation**: Enforce SSE-S3 or SSE-KMS; use **S3 Block Public Access**.

2. **KMS Key Policy Misconfiguration**  
   - **Attack**: Modify key policies to grant unauthorized access.  
   - **Impact**: Decryption of sensitive data.  
   - **Mitigation**: Restrict `kms:PutKeyPolicy`; use conditions.

3. **Unencrypted EBS Volumes**  
   - **Attack**: Access plaintext data via stolen snapshots.  
   - **Impact**: Data theft.  
   - **Mitigation**: Enable EBS encryption by default.

4. **TLS Downgrade Attacks**  
   - **Attack**: Force TLS 1.0 for MITM attacks.  
   - **Impact**: Data interception.  
   - **Mitigation**: Enforce TLS 1.2+; use ACM certificates.

5. **Secrets in Plaintext Environment Variables**  
   - **Attack**: Log environment variables with sensitive data.  
   - **Impact**: Credential theft.  
   - **Mitigation**: Use **AWS Secrets Manager**; encrypt variables.

6. **Unencrypted RDS Snapshots**  
   - **Attack**: Copy unencrypted snapshots to attacker’s account.  
   - **Impact**: Sensitive data exposure.  
   - **Mitigation**: Enforce encryption with KMS.

7. **Data Lake Encryption Gaps**  
   - **Attack**: Access plaintext data in S3 via Athena/Glue.  
   - **Impact**: Data leakage.  
   - **Mitigation**: Enforce encryption for all data sources.

8. **KMS Key Deletion**  
   - **Attack**: Delete CMKs to disrupt operations.  
   - **Impact**: Data loss.  
   - **Mitigation**: Enable key deletion protection.

9. **Cross-Account Key Sharing**  
   - **Attack**: Share keys with untrusted accounts.  
   - **Impact**: Data decryption.  
   - **Mitigation**: Use grants with conditions.

10. **Encryption Context Bypass**  
    - **Attack**: Decrypt data without context.  
    - **Impact**: Data leakage.  
    - **Mitigation**: Enforce context in policies.

---

### **3. Logging**

#### **Attack Scenarios**
1. **CloudTrail Logging Disabled**  
   - **Attack**: Disable CloudTrail to erase activity history.  
   - **Impact**: Blind spot for malicious actions.  
   - **Mitigation**: Enable multi-region trails; use S3 object locks.

2. **Tampered Log Files**  
   - **Attack**: Delete/modify logs in S3 to hide activity.  
   - **Impact**: Forensic evasion.  
   - **Mitigation**: Enable log file validation (SHA-256).

3. **Cross-Region Logging Gaps**  
   - **Attack**: Perform malicious actions in regions without trails.  
   - **Impact**: Undetected attacks.  
   - **Mitigation**: Enable organization-wide trails.

4. **Public S3 Bucket for Logs**  
   - **Attack**: Expose logs to the internet.  
   - **Impact**: Leak of sensitive metadata.  
   - **Mitigation**: Use private buckets; enable SSE-KMS.

5. **Insider Threats via CloudTrail Access**  
   - **Attack**: Abuse IAM permissions to read/delete logs.  
   - **Impact**: Cover tracks.  
   - **Mitigation**: Restrict `cloudtrail:DeleteTrail` and `s3:DeleteObject`.

6. **Event Selector Misconfiguration**  
   - **Attack**: Exclude critical events (e.g., `DeleteBucket`).  
   - **Impact**: Missed alerts.  
   - **Mitigation**: Log all management and data events.

7. **Cost Exploitation via Excessive Logging**  
   - **Attack**: Flood logs to spike S3/CloudTrail costs.  
   - **Impact**: Financial loss.  
   - **Mitigation**: Use lifecycle policies to archive logs.

8. **CloudTrail IAM Role Abuse**  
   - **Attack**: Assume the CloudTrail service role for privilege escalation.  
   - **Impact**: Account takeover.  
   - **Mitigation**: Restrict `iam:PassRole` to CloudTrail.

9. **Malicious CloudTrail Stop/Start**  
   - **Attack**: Stop logging during an attack.  
   - **Impact**: Gap in audit trail.  
   - **Mitigation**: Monitor `StopLogging` API calls.

10. **Logging Delay Exploitation**  
    - **Attack**: Exploit delayed log delivery to evade detection.  
    - **Impact**: Delayed incident response.  
    - **Mitigation**: Stream logs to CloudWatch in real time.

---

### **4. Least Privilege**

#### **Attack Scenarios**
1. **Over-Permissive EC2 Roles**  
   - **Attack**: EC2 roles with `*:*` permissions grant attackers full AWS access.  
   - **Impact**: Account takeover.  
   - **Mitigation**: Apply least-privilege roles; use `iam:PassRole` cautiously.

2. **S3 Bucket Policy Escalation**  
   - **Attack**: Bucket policies with `s3:*` permissions allow unauthorized access.  
   - **Impact**: Data exfiltration.  
   - **Mitigation**: Use conditions (e.g., `aws:SourceIp`) in policies.

3. **Lambda Function Over-Privilege**  
   - **Attack**: Lambda roles with `dynamodb:*` permissions allow data manipulation.  
   - **Impact**: Data corruption.  
   - **Mitigation**: Restrict Lambda roles to specific actions/resources.

4. **RDS IAM Authentication Abuse**  
   - **Attack**: Over-permissive IAM roles grant database access.  
   - **Impact**: Unauthorized queries.  
   - **Mitigation**: Restrict `rds-db:connect` permissions.

5. **KMS Key Policy Over-Privilege**  
   - **Attack**: Key policies with `kms:*` permissions allow decryption of sensitive data.  
   - **Impact**: Data exposure.  
   - **Mitigation**: Use conditions (e.g., `aws:PrincipalArn`).

6. **CloudFormation Stack Policy Bypass**  
   - **Attack**: Override stack policies during updates.  
   - **Impact**: Unauthorized resource modifications.  
   - **Mitigation**: Enforce strict stack policies; use change sets.

7. **SNS Topic Policy Abuse**  
   - **Attack**: Topic policies with `sns:*` permissions allow unauthorized publishing.  
   - **Impact**: Spam/malware distribution.  
   - **Mitigation**: Restrict `sns:Publish` permissions.

8. **Step Functions Over-Privilege**  
   - **Attack**: Step Functions roles with `lambda:InvokeFunction` for all functions.  
   - **Impact**: Resource hijacking.  
   - **Mitigation**: Restrict roles to specific Lambda ARNs.

9. **Glue Job Over-Privilege**  
   - **Attack**: Glue roles with `s3:*` permissions allow data exfiltration.  
   - **Impact**: Data leakage.  
   - **Mitigation**: Restrict Glue roles to specific buckets.

10. **EKS Pod Over-Privilege**  
    - **Attack**: Pods with `s3:*` permissions allow data access.  
    - **Impact**: Data exfiltration.  
    - **Mitigation**: Use IRSA with least privilege.

---

### **AWS Tools for Mitigation**
1. **GuardDuty**: Detect unusual API activity (e.g., `DeleteTrail`, `StopLogging`).  
2. **Security Hub**: Centralize findings from GuardDuty, Config, and Inspector.  
3. **AWS Config**: Monitor resource configurations (e.g., S3 public access, IAM policies).  
4. **IAM Access Analyzer**: Identify unused permissions and external access.  
5. **CloudTrail**: Log all API calls for forensic analysis.  

---

### **AWS Well-Architected Framework Security Pillars**
1. **Identity and Access Management**: Enforce least privilege; use MFA.  
2. **Data Protection**: Encrypt data at rest/in transit; use KMS.  
3. **Infrastructure Protection**: Use security groups, NACLs, and WAF.  
4. **Detection**: Enable GuardDuty, Config, and CloudTrail.  
5. **Incident Response**: Automate responses with Lambda and SSM Automation.  

---
