# powershell-apigee-metrics

## Functionality
Gets Apigee metrics from API and outputs to console

## Code
Written for Powershell Core 6+

## Requirements

### Modules
Requires AWSPowerShell

### Assumptions
This script is currently expecting to run on an AWS EC2 Instance
This script assumes the secrets are set up and the instance has the relevant rights through IAM with (x-account) roles.
This script assumes there is egress internet available


### Settings

#### Apigee login credentials saved in AWS Secretmanager
* Key-Value pairs expected:
    * user - the username of Apigee user
    * secret - the password of the user

#### Variables in Powershel
| Variable | Purpose | Optional/Required
| --- | --- | ---
| apiVariables | What metric API's are called with what settings | Required
| awsSMAccountId | AWS AccountID where the Secretmanager secret lives | (Optional if in same account)
| awsTakexAccountRoleARN | ARN of the x-account role it needs to assume to execute it's job. | (Optional if in same account)
| awsTakeRoleSessionName | SessionName passed to Use-STSRole | (Optional if in same account)
| awsSecretID | Name of the Secret Manager Secret | Required
| awsSecretRegion | Region of Secret Manager Secret | Required