# Prowler Scanner Lambda Container Image
# Based on AWS Lambda Python 3.12 base image with Prowler installed

FROM public.ecr.aws/lambda/python:3.12

# Install system dependencies
RUN dnf install -y \
    git \
    unzip \
    && dnf clean all

# Install AWS CLI v2 (required by Prowler)
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws

# Install Prowler with AWS provider only (much smaller image)
# This avoids installing Azure, GCP, Kubernetes SDKs that we don't need
RUN pip install --no-cache-dir "prowler[aws]"

# Copy function code and set proper permissions for Lambda runtime
COPY handler.py ${LAMBDA_TASK_ROOT}/
COPY requirements.txt ${LAMBDA_TASK_ROOT}/

# Ensure Lambda runtime user can read the files
RUN chmod 644 ${LAMBDA_TASK_ROOT}/handler.py ${LAMBDA_TASK_ROOT}/requirements.txt

# Install additional Python dependencies
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Set the CMD to the handler
CMD [ "handler.handler" ]
