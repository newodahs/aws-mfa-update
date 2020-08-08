# aws-mfa-update

Simple application written in golang that makes setting pulling and setting MFA credentials from STS for use in the AWS-CLI easier.

When run, aws-mfa-update will do the following:
1. Read in `~/<user>/.aws/config` to find the MFA serial to use for the STS request
2. Take a provided One Time Password (OTP) and format an STS command
3. Execute the STS command via the AWS-CLI
4. Populate the temporary credentials for future use with the CLI in `~/<user>/.aws/credentials`

To build: `go build` in the project directory

# Command Overivew
```
aws-mfa-update <options>

-baseProfile=<profileName> - Name of the profile in the config file to find the mfa_serial entry to use
                            -> Assumes 'default' if not provided
                            -> Will recurse on source_profile if mfa_serial is not found up to 6 times
                            
-authProfile=<profileName> - Name of the profile to store the temporary authentication credentials to
                            -> If not provided a profile named 'mfa' is assumed as the target
                            -> Does NOT allow storing/overwriting 'default' profile
                            -> DANGER: WILL OVERWRITE CREDIENTIALS IN PROVIDED PROFILE!
                            
-otp=<oneTimePasswd> - Six-digit OTP from authenticator application to use in this call
                       -> If not provided, aws-mfa-update will prompt the user for it
                       
-homedir=<homeDirectory> - Directory to use to find the config and credentials file
                           -> Expands to: <homeDirectory>/.aws/[config|credentials]
```

# Design goals and Assumptions
The design and goal of aws-mfa-update is to provide a quick and safe method of populating temporary credentials from and for the AWS-CLI without implementing the full session management requirements of the AWS-SDK and make it so that the use of MFA with the AWS-CLI is a bit easier to manage and use for a typical end user and facilitate automation to re-up the temporary credentials (WIP).

## Usecase 1
Consider a config file that looks as such:
```
[default]
mfa_serial = arn:aws:iam::SOMEACCTNUM:mfa/userName
region = us-east-1
output = json

[profile mfa]
region = us-east-1
source_profile = default
```

And a credentials file that looks as such:
```
[default]
aws_access_key_id = SOMEACCESSKEY
aws_secret_access_key = SOMESECRETKEY

[mfa]
aws_access_key_id = TEMPACCESSKEY
aws_secret_access_key = TEMPSECRETKEY
aws_session_token = TEMPTOKEN

```

In the above use case, the user would run: `./aws-mfa-update -otp=123456` and leverage the defaults (mentioned above) so that:
1. The default `mfa_serial` from the config and the supplied OTP (123456) is passed to the AWS-CLI STS call
   * Using the above file examples, the command passed to the CLI would be: `aws sts get-session-token --serial-number arn:aws:iam::SOMEACCTNUM:mfa/userName --token-code 123456`
2. The JSON result from the AWS-CLI is captured and parsed
3. The parsed results are written to the credentials file, under the `mfa` profile (section)
4. The user would then issue commands to the CLI as the `mfa` profile with the temporary credentials that were obtained
   * Example (assuming IAM access): `aws --profile mfa iam list-groups`

## Usecase 2
Consider a config file that looks as such:
```
[default]
mfa_serial = arn:aws:iam::SOMEACCTNUM:mfa/userName
region = us-east-1
output = json

[profile mfa]
mfa_serial = arn:aws:iam::SOMEACCTNUM:mfa/userNameMFA
region = us-east-1
output = json

[profile prod]
region = us-east-1
source_profile = mfa
```

And a credentials file that looks as such:
```
[default]
aws_access_key_id = SOMEACCESSKEY
aws_secret_access_key = SOMESECRETKEY

[mfa]
aws_access_key_id = ANOTHERACCESSKEY
aws_secret_access_key = ANOTHERSECRETKEY

[prod]
aws_access_key_id = TEMPACCESSKEY
aws_secret_access_key = TEMPSECRETKEY
aws_session_token = TEMPTOKEN

```
In the above use case, the user would run: `./aws-mfa-update -baseProfile=prod -authProfile=prod -otp=987654`:
1. The `aws-mfa-update` app will first look for the `mfa_serial` in the `prod` profile, it will not be found
   * Instead, it will find the `source_profile` set to `mfa`, thus causing the command to look for the `mfa_serial` in the `mfa` profile, which it will find
2. The `mfa_serial` from the `mfa` profile and the supplied OTP (987654) is passed to the AWS-CLI STS call
   * Using the above file examples, the command passed to the CLI would be: `aws sts get-session-token --serial-number mfa_serial = arn:aws:iam::SOMEACCTNUM:mfa/userNameMFA --token-code 987654`
3. The JSON result from the AWS-CLI is captured and parsed
4. The parsed results are written to the credentials file, under the supplied `authProfile`, aka the `prod` profile (section)
5. The user would then issue commands to the CLI as the `prod` profile with the temporary credentials that were obtained
   * Example (assuming IAM access): `aws --profile prod iam list-groups`

## Config File Assumptions
* Assumes that there is at least one valid `mfa_serial` entry for use with the STS call
* Assumes `json` as the output for the profiles in use

## Credentials File Assumptions
* Assumes that the default section is to be protected
* Assumes that the user-specified (target) profile for temporary credentials can have the following keys overwritten at will:
  * `aws_access_key_id`
  * `aws_secret_access_key`
  * `aws_session_token`
* Does **NOT** assume the profile section exists in the credentials file -- creates if needed.
