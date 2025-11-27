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
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_compute_serverless.arn,
    aws_iam_policy.terraform_containers_and_eks.arn,
    aws_iam_policy.terraform_iam_and_observability.arn
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
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_compute_serverless.arn,
    aws_iam_policy.terraform_containers_and_eks.arn,
    aws_iam_policy.terraform_iam_and_observability.arn
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
    aws_iam_policy.terraform_networking.arn,
    aws_iam_policy.terraform_compute_serverless.arn,
    aws_iam_policy.terraform_containers_and_eks.arn,
    aws_iam_policy.terraform_iam_and_observability.arn
  ]
  repositories      = ["dtolbertcooke/*"] # allow ALL repos under my GitHub
  oidc_provider_arn = module.github-oidc-dev.oidc_provider_arn
}




# OIDC policies to be used by all (dev, test, prod) github oidc roles
# 1 - backend storage policy
resource "aws_iam_policy" "terraform_backend_storage" {
  name = "terraform-backend-storage"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # State + code buckets (backend + lambda)
      {
        Sid    = "TerraformS3StateAndCode"
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
        Sid    = "TerraformS3CreateBuckets"
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

      # DynamoDB state + app tables
      {
        Sid    = "TerraformDynamoDBStateAndApp"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
          "dynamodb:ListTagsOfResource",
          "dynamodb:TagResource",
          "dynamodb:UpdateTable",
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
        Sid      = "TerraformDynamoDBCreateTables"
        Effect   = "Allow"
        Action   = ["dynamodb:CreateTable"]
        Resource = "*"
      },

      # SSM for backend config
      {
        Sid    = "TerraformSSMBackendConfig"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:PutParameter",
          "ssm:DeleteParameter"
        ]
        Resource = "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/*"
      }
    ]
  })
}

# 2 - networking policy
resource "aws_iam_policy" "terraform_networking" {
  name = "terraform-networking"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "TerraformVPCNetworking"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:ModifyVpcAttribute",

          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:DescribeSubnets",

          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:DescribeInternetGateways",

          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:DescribeNatGateways",

          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:DescribeRouteTables",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",

          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",

          "ec2:CreateNetworkAcl",
          "ec2:DeleteNetworkAcl",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:ReplaceNetworkAclAssociation",

          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:DisassociateAddress",
          "ec2:DescribeAddresses",
          "ec2:DescribeAddressesAttribute",

          "ec2:DescribeRegions",
          "ec2:DescribeNetworkInterfaces",

          "ec2:CreateTags",
          "ec2:DeleteFlowLogs",
          "ec2:CreateFlowLogs",
          "ec2:DescribeFlowLogs"
        ]
        Resource = "*"
      }
    ]
  })
}

# 3 - serverless policy
resource "aws_iam_policy" "terraform_compute_serverless" {
  name = "terraform-compute-serverless"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Lambda functions for serverless API
      {
        Sid    = "LambdaCRUD"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
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

      # API Gateway for REST API
      {
        Sid    = "APIGatewayCRUD"
        Effect = "Allow"
        Action = [
          "apigateway:GET",
          "apigateway:POST",
          "apigateway:PUT",
          "apigateway:PATCH",
          "apigateway:DELETE"
        ]
        Resource = [
          "arn:aws:apigateway:${var.region}::/restapis",
          "arn:aws:apigateway:${var.region}::/restapis/*",
          "arn:aws:apigateway:${var.region}::/account",
          "arn:aws:apigateway:${var.region}::/tags/*"
        ]
      },

      # Application Auto Scaling (Lambda / ECS / etc)
      {
        Sid    = "ApplicationAutoScaling"
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

# 4 - containerization policy
resource "aws_iam_policy" "terraform_containers_and_eks" {
  name = "terraform-containers-and-eks"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # ECR repo + images + auth
      {
        Sid    = "ECRRepositoryAndImages"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository",
          "ecr:DescribeRepositories",
          "ecr:DeleteRepository",
          "ecr:TagResource",
          "ecr:ListTagsForResource",
          "ecr:CompleteLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:InitiateLayerUpload",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
          "ecr:GetRegistryScanningConfiguration"
        ]
        Resource = "arn:aws:ecr:${var.region}:${var.aws_account_id}:repository/*"
      },
      {
        Sid      = "ECRAuthWildcard"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },

      # EKS cluster / nodegroups / addons / access entry
      {
        Sid    = "EKSClusterManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateCluster",
          "eks:DescribeCluster",
          "eks:DeleteCluster",
          "eks:UpdateClusterConfig",
          "eks:UpdateClusterVersion",
          "eks:ListClusters",
          "eks:TagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "EKSNodegroupManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateNodegroup",
          "eks:DescribeNodegroup",
          "eks:UpdateNodegroupConfig",
          "eks:UpdateNodegroupVersion",
          "eks:DeleteNodegroup"
        ]
        Resource = "*"
      },
      {
        Sid    = "EKSAddonManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateAddon",
          "eks:DescribeAddon",
          "eks:UpdateAddon",
          "eks:DeleteAddon"
        ]
        Resource = "*"
      },
      {
        Sid    = "EKSAccessEntryManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateAccessEntry",
          "eks:DeleteAccessEntry",
          "eks:DescribeAccessEntry",
          "eks:AssociateAccessPolicy",
          "eks:DisassociateAccessPolicy",
          "eks:ListAssociatedAccessPolicies"
        ]
        Resource = "*"
      },

      # EC2 describe for EKS networking (if you ever tighten ec2:Describe* above)
      {
        Sid    = "EC2DescribeForEKS"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeRouteTables",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },

      # KMS for EKS cluster encryption
      {
        Sid    = "KMSForEKS"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:DescribeKey",
          "kms:TagResource",
          "kms:CreateAlias",
          "kms:DeleteAlias",
          "kms:ListAliases",
          "kms:ScheduleKeyDeletion",
          "kms:CreateGrant",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:PutKeyPolicy",
          "kms:EnableKeyRotation",
          "kms:ListResourceTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# 5 - IAM & Obesrvability policy
resource "aws_iam_policy" "terraform_iam_and_observability" {
  name = "terraform-iam-and-observability"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # IAM role/policy CRUD for Terraform-managed roles/policies
      {
        Sid    = "IAMManageTerraformRolesAndPolicies"
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

      # PassRole to services Terraform wires up
      {
        Sid      = "IAMPassRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${var.aws_account_id}:role/*"
        Condition = {
          StringLike = {
            "iam:PassedToService" = [
              "lambda.amazonaws.com",
              "apigateway.amazonaws.com",
              "vpc-flow-logs.amazonaws.com",
              "eks.amazonaws.com",
              "ec2.amazonaws.com"
            ]
          }
        }
      },

      # OIDC provider for GitHub
      {
        Sid    = "OIDCProviderManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider"
        ]
        Resource = "arn:aws:iam::${var.aws_account_id}:oidc-provider/*"
      },

      # Service-linked roles (EKS, etc)
      {
        Sid    = "IAMServiceLinkedRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole",
          "iam:GetRole",
          "iam:ListInstanceProfilesForRole",
          "iam:ListRoleTags",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "arn:aws:iam::${var.aws_account_id}:role/*"
      },

      # STS + account info (Terraform provider & modules often use these)
      {
        Sid    = "AccountIntrospection"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "iam:ListAccountAliases",
          "iam:ListUsers",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:GetAccessKeyLastUsed",
          "iam:GetLoginProfile",
          "iam:ListAccessKeys",
          "iam:ListAttachedUserPolicies",
          "iam:ListSigningCertificates",
          "tag:GetResources"
        ]
        Resource = "*"
      },

      # Allow assuming your own GitHub OIDC roles (if you use this pattern)
      {
        Sid    = "AssumeOIDCRoles"
        Effect = "Allow"
        Action = ["sts:AssumeRole"]
        Resource = [
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-prod"
        ]
      },

      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:DescribeMetricFilters",
          "logs:PutLogEvents",
          "logs:PutRetentionPolicy",
          "logs:TagResource",
          "logs:ListTagsForResource"
        ]
        Resource = "*"
      },

      # CloudWatch dashboards
      {
        Sid    = "CloudWatchDashboards"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutDashboard",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:DescribeAlarms"
        ]
        Resource = "*"
      },

      # CloudTrail (used by Access Analyzer / policy generation)
      {
        Sid    = "CloudTrailList"
        Effect = "Allow"
        Action = [
          "cloudtrail:ListTrails"
        ]
        Resource = "*"
      }
    ]
  })
}

