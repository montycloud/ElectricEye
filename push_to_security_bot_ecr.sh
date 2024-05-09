#!/bin/bash

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <account_number> <region>"
  exit 1
fi

ACCOUNT_NUMBER="$1"
REGION="$2"
TAG_NAME="latest"
ECR_REPO_NAME="securitybot"

# Build the Docker image
DOCKER_BUILD_CMD="docker build -t securitybot ."
echo "executing: $DOCKER_BUILD_CMD"
$DOCKER_BUILD_CMD

# Login to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_NUMBER.dkr.ecr.$REGION.amazonaws.com

# Tag the Docker image with the environment
TAG_COMMAND="docker tag securitybot:latest $ACCOUNT_NUMBER.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO_NAME:$TAG_NAME"

echo "executing: $TAG_COMMAND"
$TAG_COMMAND

# Push the Docker image to ECR
DOCKER_PUSH_CMD="docker push $ACCOUNT_NUMBER.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO_NAME:$TAG_NAME"
echo "executing: $DOCKER_PUSH_CMD"
$DOCKER_PUSH_CMD

# Check the exit status of the docker push command
if [ $? -eq 0 ]; then
  echo "Docker image pushed successfully."
else
  echo "Error: Docker push command failed."
  exit 1
fi
