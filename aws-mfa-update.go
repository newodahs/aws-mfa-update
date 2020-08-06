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
   mfaSerial, err := loadProfileMFASerial(fmt.Sprintf("%s/.aws/config", userDir), basePro)
   if err != nil { log.Fatalln("Failed to get the MFA Serial\n", err) }

   //prompt for input...
   if isValidOTP(otp) != true {
      log.Println("Supplied OTP doesn't look right... Prompting the user...\n")
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

   log.Println(fmt.Sprintf("MFA Credentials set for profile [%s] using profile [%s].\n** Credentials expire at: %s\n", authPro, basePro, resp.Credentials.Expiration))
}

func loadProfileMFASerial(filename string, profile string) (string, error) {

   config, err := ini.Load(filename)
   if err != nil {
      return "", errors.New(fmt.Sprintf("Unable to open file: %s", filename))
   }

   //find the section
   iniProfile, err := config.GetSection(profile)
   if err != nil {
      return "", errors.New(fmt.Sprintf("Unable to find profile: %s", profile))
   }

   //find the key-value
   serial, err := iniProfile.GetKey("mfa_serial")
   if err != nil {
      return "", errors.New(fmt.Sprintf("Unable to get mfa_serial for profile: %s", profile))
   }

   return serial.String(), nil
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
         log.Println("OTP doesn't look right (should be a six-digit code), try again...\n")
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
