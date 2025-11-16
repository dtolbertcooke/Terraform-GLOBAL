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

  create_oidc_provider      = true # only create provider once
  create_oidc_role          = true
  role_name                 = "github-oidc-role-dev"
  github_thumbprint         = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [aws_iam_policy.github_actions_policy.arn] # attach oidc policy created above
  repositories              = ["dtolbertcooke/*"]                        # allow ALL repos under my GitHub
}
module "github-oidc-test" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "2.2.1"

  create_oidc_provider      = false # ony create provider once
  create_oidc_role          = true
  role_name                 = "github-oidc-role-test"
  github_thumbprint         = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [aws_iam_policy.github_actions_policy.arn] # attach oidc policy created above
  repositories              = ["dtolbertcooke/*"]                        # allow ALL repos under my GitHub
  oidc_provider_arn         = module.github-oidc-dev.oidc_provider_arn
}
module "github-oidc-prod" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "2.2.1"

  create_oidc_provider      = false # only create provider once
  create_oidc_role          = true
  role_name                 = "github-oidc-role-prod"
  github_thumbprint         = "6938fd4d98bab03faadb97b34396831e3780aea1"
  oidc_role_attach_policies = [aws_iam_policy.github_actions_policy.arn] # attach oidc policy created above
  repositories              = ["dtolbertcooke/*"]                        # allow ALL repos under my GitHub
  oidc_provider_arn         = module.github-oidc-dev.oidc_provider_arn
}

# OIDC policy to be used by all (dev, test, prod) github oidc roles
resource "aws_iam_policy" "github_actions_policy" {
  name = "github-oidc-role-terraform-policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        Sid      = "AllowCreateLambdaFunctions"
        Effect   = "Allow"
        Action   = "lambda:CreateFunction"
        Resource = "*"
      },
      {
        Sid    = "AllowRegisterScalableTarget"
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
      },
      {
        Sid      = "AllowPassLambdaExecutionRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${var.aws_account_id}:role/lambda-execution-role-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "lambda.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowPassRoles"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          "arn:aws:iam::${var.aws_account_id}:role/apigw-cloudwatch-logs-role-global-infra",
          "arn:aws:iam::${var.aws_account_id}:role/apigw-cloudwatch-logs-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/apigw-cloudwatch-logs-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/apigw-cloudwatch-logs-role-prod",
          "arn:aws:iam::${var.aws_account_id}:role/lambda-execution-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/lambda-execution-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/lambda-execution-role-prod"
        ]
      },
      {
        Sid    = "AllowLambdaFunctions"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
          "lambda:DeleteFunction",
          "lambda:GetPolicy",
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig",
          "lambda:AddPermission",
          "lambda:TagResource"
        ]
        Resource = [
          "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:fruit-api-GET*",
          "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:fruit-api-PUT*",
          "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:fruit-api-PATCH*",
          "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:fruit-api-DELETE*"
        ]
      },
      {
        Sid      = "AllowCreateDynamoDBTable"
        Effect   = "Allow"
        Action   = ["dynamodb:CreateTable"]
        Resource = "*"
        Condition = {
          StringLike = {
            "dynamodb:TableName" = [
              "fruit-api-lock-table-*",
              "fruit-api-table-*"
            ]
          }
        }
      },
      {
        "Sid" : "TerraformS3BucketAccess",
        "Effect" : "Allow",
        "Action" : [
          "s3:DeleteObject",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetReplicationConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketWebsite",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketLogging",
          "s3:GetBucketCORS",
          "s3:GetBucketAcl",
          "s3:GetAccelerateConfiguration",
          "s3:GetObjectTagging",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        "Resource" : [
          "arn:aws:s3:::${module.s3_state_bucket.state_bucket_name}",
          "arn:aws:s3:::${module.s3_state_bucket.state_bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_dev.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_dev.bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_test.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_test.bucket_name}/*",
          "arn:aws:s3:::${module.lambda_code_bucket_prod.bucket_name}",
          "arn:aws:s3:::${module.lambda_code_bucket_prod.bucket_name}/*"
        ]
      },
      {
        Sid    = "AllowCreateS3Buckets"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:GetBucketLocation",
          "s3:HeadBucket",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:PutBucketAcl"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowPDynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateTable",
          "dynamodb:DeleteTable",
          "dynamodb:DeleteItem",
          "dynamodb:TagResource",
          "dynamodb:DescribeTable",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:ListTagsOfResource"
        ]
        Resource = [
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/fruit-api-lock-table-${var.environment}",
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/fruit-api-table-*",
          "arn:aws:dynamodb:${var.region}:${var.aws_account_id}:table/${module.dynamodb_state_table.state_table_name}"
        ]
      },
      {
        "Sid" : "TerraformNetworkingAccess",
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:DescribeVpcs",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:DescribeSubnets",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:DescribeNatGateways",
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
          "ec2:DescribeSecurityGroups",
          "ec2:CreateNetworkAcl",
          "ec2:DeleteNetworkAcl",
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:ModifyVpcAttribute",
          "ec2:AllocateAddress",
          "ec2:DescribeAddresses",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeVpcClassicLinkDnsSupport",
          "ec2:DescribeVpcClassicLink",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeSecurityGroupRules",
          "ec2:ReplaceNetworkAclAssociation",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DisassociateAddress",
          "ec2:ReleaseAddress",
          "ec2:DescribeAddressesAttribute",
          "ec2:CreateFlowLogs",
          "ec2:DeleteFlowLogs",
          "ec2:DescribeFlowLogs"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "TerraformIAMAccess",
        "Effect" : "Allow",
        "Action" : [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetRole",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:PassRole"
        ],
        "Resource" : [
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-prod"
        ]
      },
      {
        "Sid" : "TerraformAssumeRole",
        "Effect" : "Allow",
        "Action" : ["sts:AssumeRole"],
        "Resource" : [
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-dev",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-test",
          "arn:aws:iam::${var.aws_account_id}:role/github-oidc-role-prod"
        ]
      },
      {
        Sid    = "AllowSSMParameters"
        Effect = "Allow"
        Action = ["ssm:GetParameters", "ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"]
        Resource = [
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/state-bucket",
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/state-table",
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/region",
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/app-table-dev",
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/app-table-test",
          "arn:aws:ssm:${var.region}:${var.aws_account_id}:parameter/tf/global-backend/app-table-prod"
        ]
      },
      {
        "Sid" : "LogsCloudWatchGlobal",
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:ListTagsLogGroup",
          "logs:ListTagsForResource",
          "logs:PutLogEvents",
          "logs:PutRetentionPolicy",
          "logs:TagResource"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "CloudWatchRoleManagement",
        "Effect" : "Allow",
        "Action" : [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:PassRole",
          "iam:TagRole",
          "iam:ListInstanceProfilesForRole"
        ],
        "Resource" : "arn:aws:iam::${var.aws_account_id}:role/*"
      },
      {
        "Sid" : "AllowPolicyManagement",
        "Effect" : "Allow",
        "Action" : [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:TagPolicy"
        ],
        "Resource" : "arn:aws:iam::${var.aws_account_id}:policy/*"
      },
      {
        Sid    = "CRUDAPIGateway"
        Effect = "Allow"
        Action = [
          "apigateway:PUT",
          "apigateway:POST",
          "apigateway:GET",
          "apigateway:PATCH",
          "apigateway:DELETE",
          "apigateway:TagResource"
        ]
        Resource = [
          "arn:aws:apigateway:${var.region}::/restapis",
          "arn:aws:apigateway:${var.region}::/restapis/*",
          "arn:aws:apigateway:${var.region}::/tags/*",
          "arn:aws:apigateway:${var.region}::/account"
        ]
      },
      {
        "Sid" : "CloudWatchDashboardAccess",
        "Effect" : "Allow",
        "Action" : [
          "cloudwatch:PutDashboard",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards",
          "cloudwatch:DeleteDashboards"
        ],
        "Resource" : [
          "arn:aws:cloudwatch::${var.aws_account_id}:dashboard/serverless-api-dev-dashboard",
          "arn:aws:cloudwatch::${var.aws_account_id}:dashboard/serverless-api-test-dashboard",
          "arn:aws:cloudwatch::${var.aws_account_id}:dashboard/serverless-api-prod-dashboard"
        ]
      }
    ]
    }
  )
}

