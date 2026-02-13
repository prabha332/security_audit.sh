# security_audit.sh
# Designed and automated cloud &amp; Kubernetes security audit framework using Bash, AWS CLI, kubectl, and Trivy with real-time WhatsApp &amp; Email alerting.

#!/bin/bash

# =============================
# CONFIGURATION
# =============================

EMAIL="receiver@email.com"
LOGFILE="/tmp/security_audit.log"

TWILIO_SID="your_account_sid"
TWILIO_TOKEN="your_auth_token"
TWILIO_FROM="whatsapp:+XXXXXXXXXXX"
TWILIO_TO="whatsapp:+91XXXXXXXXXX"

ALERTS=""

DATE=$(date)

# =============================
# 1️⃣ Check Open Security Groups (0.0.0.0/0)
# =============================

OPEN_SG=$(aws ec2 describe-security-groups \
--query "SecurityGroups[*].IpPermissions[*].IpRanges[*].CidrIp" \
--output text | grep "0.0.0.0/0")

if [ ! -z "$OPEN_SG" ]; then
    ALERTS+="\n🚨 Open Security Groups detected (0.0.0.0/0)\n"
fi

# =============================
# 2️⃣ Check Public S3 Buckets
# =============================

for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text)
do
    PUBLIC=$(aws s3api get-bucket-acl --bucket $bucket --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']" --output text)
    if [ ! -z "$PUBLIC" ]; then
        ALERTS+="\n🚨 Public S3 Bucket: $bucket\n"
    fi
done

# =============================
# 3️⃣ Check IAM Users with Admin Access
# =============================

ADMIN_USERS=$(aws iam list-attached-user-policies \
--query "AttachedPolicies[?PolicyName=='AdministratorAccess']" \
--output text)

if [ ! -z "$ADMIN_USERS" ]; then
    ALERTS+="\n⚠️ IAM Users with AdministratorAccess detected\n"
fi

# =============================
# 4️⃣ Kubernetes: Containers Running as Root
# =============================

ROOT_CONTAINERS=$(kubectl get pods --all-namespaces -o jsonpath='{.items[*].spec.containers[*].securityContext.runAsUser}')

if echo "$ROOT_CONTAINERS" | grep -q "0"; then
    ALERTS+="\n🚨 Some containers running as root (runAsUser: 0)\n"
fi

# =============================
# 5️⃣ Missing Resource Limits
# =============================

NO_LIMITS=$(kubectl get pods --all-namespaces -o json | grep -L "limits")

if [ ! -z "$NO_LIMITS" ]; then
    ALERTS+="\n⚠️ Some containers missing resource limits\n"
fi

# =============================
# 6️⃣ Docker Image Vulnerability Scan (Trivy Required)
# =============================

IMAGE="nginx:latest"
TRIVY_RESULT=$(trivy image --severity HIGH,CRITICAL $IMAGE 2>/dev/null | grep HIGH)

if [ ! -z "$TRIVY_RESULT" ]; then
    ALERTS+="\n🚨 HIGH vulnerabilities found in image: $IMAGE\n"
fi

# =============================
# SEND ALERT
# =============================

if [ ! -z "$ALERTS" ]; then

MESSAGE="🔐 DevOps Security Audit Report - $DATE\n$ALERTS"

echo -e "$MESSAGE" > $LOGFILE

# Send Email
echo -e "$MESSAGE" | mail -s "Security Audit Alert" $EMAIL

# Send WhatsApp
curl -s -X POST https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json \
--data-urlencode "From=$TWILIO_FROM" \
--data-urlencode "To=$TWILIO_TO" \
--data-urlencode "Body=$MESSAGE" \
-u $TWILIO_SID:$TWILIO_TOKEN

else
    echo "✅ No major security issues found - $DATE"
fi
