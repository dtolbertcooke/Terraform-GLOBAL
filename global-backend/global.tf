# Remote State Backend with S3 & DynamoDB using modules
# Github OIDC provider & roles

# state bucket
module "s3_state_bucket" {
  source      = "../modules/s3"
  bucket_name = var.state_bucket_name
  environment = "global"
}

# lambda code buckets dev
module "lambda_code_bucket_dev" {
  source      = "../modules/s3"
  bucket_name = var.lambda_code_bucket
  environment = "dev"
}

# lambda code buckets test
module "lambda_code_bucket_test" {
  source      = "../modules/s3"
  bucket_name = var.lambda_code_bucket
  environment = "test"
}

# lambda code buckets prod
module "lambda_code_bucket_prod" {
  source      = "../modules/s3"
  bucket_name = var.lambda_code_bucket
  environment = "prod"
}

# locking table
module "dynamodb_state_table" {
  source           = "../modules/dynamodb"
  state_table_name = var.state_table_name
  environment      = var.environment
}

# create github oidc provider & 3 roles for terraform in all environments (dev, test, prod)
module "github-oidc-dev" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "2.2.1"

  create_oidc_provider = true # only create provider once
  create_oidc_role     = true
  role_name            = "github-oidc-role-dev"
  github_thumbprint    = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [
    aws_iam_policy.terraform_backend_storage.arn,
    aws_iam_policy.terraform_serverless.arn,
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_iam.arn,
    aws_iam_policy.terraform_observability.arn,
    aws_iam_policy.terraform_ecr.arn
  ]
  repositories = ["dtolbertcooke/*"] # allow ALL repos under my GitHub
}
module "github-oidc-test" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "2.2.1"

  create_oidc_provider = false # ony create provider once
  create_oidc_role     = true
  role_name            = "github-oidc-role-test"
  github_thumbprint    = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [
    aws_iam_policy.terraform_backend_storage.arn,
    aws_iam_policy.terraform_serverless.arn,
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_iam.arn,
    aws_iam_policy.terraform_observability.arn,
    aws_iam_policy.terraform_ecr.arn
  ]
  repositories      = ["dtolbertcooke/*"] # allow ALL repos under my GitHub
  oidc_provider_arn = module.github-oidc-dev.oidc_provider_arn
}
module "github-oidc-prod" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "2.2.1"

  create_oidc_provider = false # only create provider once
  create_oidc_role     = true
  role_name            = "github-oidc-role-prod"
  github_thumbprint    = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [
    aws_iam_policy.terraform_backend_storage.arn,
    aws_iam_policy.terraform_serverless.arn,
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_iam.arn,
    aws_iam_policy.terraform_observability.arn,
    aws_iam_policy.terraform_ecr.arn
  ]
  repositories      = ["dtolbertcooke/*"] # allow ALL repos under my GitHub
  oidc_provider_arn = module.github-oidc-dev.oidc_provider_arn
}

# OIDC policies to be used by all (dev, test, prod) github oidc roles
# policy 1
resource "aws_iam_policy" "terraform_backend_storage" {
  name = "terraform-backend-storage"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "TerraformS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketLogging",
          "s3:GetBucketCORS",
          "s3:GetBucketAcl",
          "s3:GetAccelerateConfiguration",
          "s3:GetObjectTagging",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${module.s3_state_bucket.bucket_name}",
          "arn:aws:s3:::${module.s3_state_bucket.bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_dev.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_dev.bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_test.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_test.bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_prod.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_prod.bucket_name}/*"
        ]
      },
      {
        Sid    = "TerraformS3Create"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:PutBucketAcl"
        ]
        Resource = "*"
      },
      {
        Sid    = "TerraformDynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateTable",
          "dynamodb:DeleteTable",
          "dynamodb:DeleteItem",
          "dynamodb:TagResource",
          "dynamodb:DescribeTable",
          "dynamodb:ListTagsOfResource",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeTimeToLive"
        ]
        Resource = [
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/fruit-api-lock-table-${var.environment}",
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/fruit-api-table-*",
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/${module.dynamodb_state_table.state_table_name}"
        ]
      },
      {
        Sid      = "TerraformDynamoDBCreate"
        Effect   = "Allow"
        Action   = ["dynamodb:CreateTable"]
        Resource = "*"
      },
      {
        Sid    = "TerraformSSMAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:PutParameter",
          "ssm:DeleteParameter"
        ]
        Resource = [
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/*"
        ]
      }
    ]
  })
}

# policy 2
resource "aws_iam_policy" "terraform_serverless" {
  name = "terraform-serverless"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "LambdaCRUD"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
          "lambda:DeleteFunction",
          "lambda:GetPolicy",
          "lambda:ListVersionsByFunction",
          "lambda:AddPermission",
          "lambda:TagResource",
          "lambda:GetFunctionCodeSigningConfig"
        ]
        Resource = "*"
      },
      {
        Sid    = "APIGatewayCRUD"
        Effect = "Allow"
        Action = [
          "apigateway:GET",
          "apigateway:POST",
          "apigateway:PUT",
          "apigateway:PATCH",
        "apigateway:DELETE"]
        Resource = [
          "arn:aws:apigateway:${var.region}::/restapis",
          "arn:aws:apigateway:${var.region}::/restapis/*",
          "arn:aws:apigateway:${var.region}::/account",
          "arn:aws:apigateway:${var.region}::/tags/*"
        ]
      },
      {
        Sid    = "AutoScaling"
        Effect = "Allow"
        Action = [
          "application-autoscaling:RegisterScalableTarget",
          "application-autoscaling:PutScalingPolicy",
          "application-autoscaling:DeleteScalingPolicy",
          "application-autoscaling:DescribeScalingPolicies",
          "application-autoscaling:DescribeScalableTargets",
          "application-autoscaling:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}

# policy 3
resource "aws_iam_policy" "terraform_networking" {
  name = "terraform-networking"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "NetworkingCRUD"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:Describe*",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateNetworkAcl",
          "ec2:DeleteNetworkAcl",
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:ModifyVpcAttribute",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:DisassociateAddress",
          "ec2:CreateFlowLogs",
          "ec2:DeleteFlowLogs",
          "ec2:CreateTags",
          "ec2:ReplaceNetworkAclAssociation"
        ]
        Resource = "*"
      }
    ]
  })
}

# policy 4
resource "aws_iam_policy" "terraform_iam" {
  name = "terraform-iam"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "IAMManage"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:GetRolePolicy",
          "iam:GetPolicyVersion",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:TagRole",
          "iam:TagPolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = [
          "arn:aws:iam::${var.aws_account_id}:role/*",
          "arn:aws:iam::${var.aws_account_id}:policy/*"
        ]
      },
      {
        Sid    = "IAMPassRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::${var.aws_account_id}:role/lambda-execution-role-*",
          "arn:aws:iam::${var.aws_account_id}:role/apigw-cloudwatch-logs-role-*",
          "arn:aws:iam::${var.aws_account_id}:role/vpc-flow-log-role-*"
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = [
              "lambda.amazonaws.com",
              "apigateway.amazonaws.com",
              "vpc-flow-logs.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "AssumeOIDCRoles"
        Effect = "Allow"
        Action = ["sts:AssumeRole"]
        Resource = [
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-prod"
        ]
      }
    ]
  })
}

# policy 5
resource "aws_iam_policy" "terraform_observability" {
  name = "terraform-observability"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
          "logs:PutRetentionPolicy",
          "logs:TagResource",
          "logs:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchDashboards"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutDashboard",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards",
          "cloudwatch:DeleteDashboards"
        ]
        Resource = "*"
      }
    ]
  })
}

# policy 6
resource "aws_iam_policy" "terraform_ecr" {
  name = "terraform-ecr"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "ECRRepositoryManagement"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository",
          "ecr:DescribeRepositories",
          "ecr:DeleteRepository",
          "ecr:TagResource",
          "ecr:ListTagsForResource"
        ]
        Resource = "arn:aws:ecr:${var.region}:${var.aws_account_id}:repository/*"
      },
      {
        Sid    = "ECRImageManagement"
        Effect = "Allow"
        Action = [
          "ecr:CompleteLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:InitiateLayerUpload",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:BatchGetImage"
        ]
        Resource = "arn:aws:ecr:${var.region}:${var.aws_account_id}:repository/*"
      },
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "KMSForEKS"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:DescribeKey",
          "kms:TagResource",
          "kms:CreateAlias",
          "kms:ListAliases",
          "kms:ScheduleKeyDeletion"
        ]
        Resource = "*"
      }
    ]
  })
}