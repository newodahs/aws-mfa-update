package main

import (
         "strings"
         "bufio"
         "fmt"
         "flag"
         "os"
         "os/user"
         "os/exec"
         "log"
         "errors"
         "regexp"
         "encoding/json"  //we call the aws CLI directly and parse the returned JSON
         "gopkg.in/ini.v1" //we read from the config and write to the credentials files directly
       )

type mfaCreds struct {
   AccessKeyId string
   SecretAccessKey string
   SessionToken string
   Expiration string
}

type awsSTSResponse struct {
   Credentials mfaCreds
}

func main() {

   //parameters
   var basePro string
   var authPro string
   var otp string
   var userDir string

   flag.StringVar(&basePro, "baseProfile", "default", "Profile to use to get MFA Serial for auth")
   flag.StringVar(&authPro, "authProfile", "mfa", "Profile to write auth to; disallows overwriting default credentials\nDANGER: WILL OVERWRITE CREDIENTIALS IN PROVIDED PROFILE!")
   flag.StringVar(&otp, "otp", "", "OTP for use; will prompt if not provided")
   flag.StringVar(&userDir, "homedir", "", "Home directory for the user; will try to figure it out if not provided")

   flag.Parse()

   //check for invalid authProfile
   if strings.EqualFold(authPro, "default") == true {
      log.Fatalln("This application does not allow the overwriting of the default application credentials!\n\nUse a specific auth profile instead as best-practice.")
   }

   if len(userDir) <= 0 {
      //build our user config dir
      user, err := user.Current()
      if err != nil { log.Fatalln("Failed to find the local user", err) }

      userDir = user.HomeDir
   }

   //load in our config to get auth with... if no profile specified, use default
   if strings.EqualFold(basePro, "default") != true {
      basePro = fmt.Sprintf("profile %s", basePro)
   }
   mfaSerial, err := loadProfileMFASerial(fmt.Sprintf("%s/.aws/config", userDir), basePro)
   if err != nil { log.Fatalln("Failed to get the MFA Serial\n", err) }

   //prompt for input...
   if isValidOTP(otp) != true {
      log.Println("Supplied OTP doesn't look right... Prompting the user...")
      inOTP, err := getOTPCode()
      if err != nil { log.Fatalln("Failed to get a reasonable OTP from the user", err) }
      otp = inOTP
   }

   //build the command
   //awsCmdArgs := fmt.Sprintf("sts get-session-token --serial-number %s --token-code %s", mfaSerial, otp)
   //run the STS request and parse the response
   awsCmd := exec.Command("aws", "sts", "get-session-token", "--serial-number", mfaSerial, "--token-code", otp)
   awsOut, err := awsCmd.CombinedOutput()
   if err != nil {
      log.Fatalln("Unable to run aws sts command\n", err)
   }

   //pull in the JSON response...
   var resp awsSTSResponse
   err = json.Unmarshal([]byte(awsOut), &resp)
   if err != nil { log.Fatalln("Failed to parse JSON response\n", err) }

   //push required response data into the environment
   err = writeMFACreds(fmt.Sprintf("%s/.aws/credentials", userDir), authPro, resp.Credentials)
   if err != nil {
      log.Fatalln("Unable to set the MFA credentials\n", err)
   }

   log.Println(fmt.Sprintf("MFA Credentials set for profile [%s] using profile [%s].\n** Credentials expire at: %s", authPro, basePro, resp.Credentials.Expiration))
}

const _maxLPListLen int = 6
func loadProfileMFASerial(filename string, profile string) (string, error) {

   config, err := ini.Load(filename)
   if err != nil {
      return "", errors.New(fmt.Sprintf("Unable to open file: %s", filename))
   }

   var lProfile [_maxLPListLen]string
   return findMFASerial(config, profile, lProfile[0:4], 0)
}

/*
 * Broke this function out from loadProfileMFASerial and added functionality to try
 * and find the mfa_serial via source_profile entries; in doing this, I chose to
 * make this a recursive function and load the ini file once outside of the actual
 * search logic - protects against circular references via a depth-limited array
 * which also disallows more than 6 references
*/
func findMFASerial(config *ini.File, profile string, lastProList []string, curIt int) (string, error) {

   //look for early exit to see if we've exceeded the maximum number of references
   if (curIt >= _maxLPListLen) {
      return "", errors.New(fmt.Sprintf("Exceeded profile referencing (max of six references allowed...). Last checked profile: %s", lastProList[4]))
   }

   //find the section
   iniProfile, err := config.GetSection(profile)
   if err != nil {
      return "", errors.New(fmt.Sprintf("Unable to find profile: %s", profile))
   }

   //find the key-value
   //if the section has an mfa_serial key, use that, if not look for a
   //source_profile key to point us to where to find the mfa_serial...
   if iniProfile.HasKey("mfa_serial") == true {
      //found the mfa_serial!
      serial, err := iniProfile.GetKey("mfa_serial")
      if err != nil {
         panic(fmt.Sprintf("Unable to get mfa_serial for profile: %s", profile))
      }
      return serial.String(), nil
   } else if iniProfile.HasKey("source_profile") == true {
      //found a referenced profile to check for mfa_serial
      sProfile, err := iniProfile.GetKey("source_profile")
      if err != nil {
         panic(fmt.Sprintf("Unable to get source_profile for profile: %s", profile))
      }

      //translate the key to a formatted string
      sProStr := sProfile.String()
      if strings.EqualFold(sProStr, "default") != true {
         sProStr = fmt.Sprintf("profile %s", sProStr)
      }

      if len(sProStr) > 0 {
         //check over the slice and look for circular references (have we seen it before)
         for i := 0; i < _maxLPListLen; i++ {
            if len(lastProList[i]) <= 0 {
               break  //early out
            }

            if lastProList[i] == sProStr {
               //circular reference detected...
               return "", errors.New(fmt.Sprintf("Circluar reference of profiles detected (%s)", profile))
            }
         }

         //add the current profile to the list and try the next one......
         lastProList = append(lastProList, profile)
         return findMFASerial(config, sProStr, lastProList, curIt + 1)
      } else {
         return "", errors.New(fmt.Sprintf("Blank source_profile specification found in: %s", profile))
      }
   }

   return "", errors.New(fmt.Sprintf("Unable to find either mfa_serial or source_profile for profile %s", profile))
}

func writeMFACreds(filename string, profile string, creds mfaCreds) (error) {

   config, err := ini.Load(filename)
   if err != nil {
      return errors.New(fmt.Sprintf("Unable to open file: %s", filename))
   }

   //see if the section exists
   iniProfile, err := config.GetSection(profile)
   if err != nil {
      //section doesn't exist, create it
      newSection, err := config.NewSection(profile)
      if (err != nil) {
         return errors.New(fmt.Sprintf("Failed to setup section for profile: %s", profile))
      }
      iniProfile = newSection
   }

   //set the key-value pairs
   if iniProfile.HasKey("aws_access_key_id") == true {
      //set the existing key to the new value
      aki, _ := iniProfile.GetKey("aws_access_key_id")
      aki.SetValue(creds.AccessKeyId)
   } else {
      //create the key and set it
      iniProfile.NewKey("aws_access_key_id", creds.AccessKeyId)
   }

   //set the key-value pairs
   if iniProfile.HasKey("aws_secret_access_key") == true {
      //set the existing key to the new value
      aki, _ := iniProfile.GetKey("aws_secret_access_key")
      aki.SetValue(creds.SecretAccessKey)
   } else {
      //create the key and set it
      iniProfile.NewKey("aws_secret_access_key", creds.SecretAccessKey)
   }

   //set the key-value pairs
   if iniProfile.HasKey("aws_session_token") == true {
      //set the existing key to the new value
      aki, _ := iniProfile.GetKey("aws_session_token")
      aki.SetValue(creds.SessionToken)
   } else {
      //create the key and set it
      iniProfile.NewKey("aws_session_token", creds.SessionToken)
   }

   err = config.SaveTo(filename)
   if err != nil {
      return errors.New("Failed to save new MFA values to credentials file.")
   }

   return nil
}

const _maxRetries int = 5
func getOTPCode() (string, error) {

   reader := bufio.NewReader(os.Stdin)

   var otp string
   //let them try to enter an OTP up to 5 times...
   var i int
   for i = 0; i < _maxRetries; i++ {
      fmt.Print("Enter OTP: ")
      input, err := reader.ReadString('\n')
      if err != nil { return "", errors.New("Failed to read the users input OTP") }

      //cleanup the input
      otp = strings.Replace(input, "\n", "", -1)
      if isValidOTP(otp) != true {
         log.Println("OTP doesn't look right (should be a six-digit code), try again...")
         continue
      }

      break  //assume any input >= 6 is good; no idea what the future of OTP looks like...
   }
   if i >= _maxRetries {
      return "", errors.New("User retried OTP too many times")
   }

   return otp, nil
}

func isValidOTP(otp string) bool {
   //validate the OTP; AWS defines this as a 6-digit code, validatable via Regex
   rxOTP := regexp.MustCompile(`^\d{6}$`)
   return rxOTP.Match([]byte(otp))
}
