package appviewx

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopaltirupur/appviewx-signer/appviewx/api"
	"github.com/gopaltirupur/appviewx-signer/appviewx/certs"
	appviewxcommon "github.com/gopaltirupur/appviewx-signer/appviewx/common"
	"github.com/gopaltirupur/appviewx-signer/common"

	"go.uber.org/zap"
)

var appviewxEnv *appviewxcommon.AppViewXEnv

var defaultRetryTimes int = 5
var defaultRetryWaitTimeInSeconds int = 2

var retryTimes int
var retryWaitTimeInSeconds int
var sessionMutex sync.Mutex

var caSettingNameWiseRootAndIntermediateCert map[string]string

func init() {

	//TODO: - TO REMOVE
	// setEnvironmentVariables()

	caSettingNameWiseRootAndIntermediateCert = map[string]string{}
	var err error
	appviewxEnv, err = getAppViewXEnv()
	if err != nil {
		log.Fatalf("Error in getting environment variables : %+v", err)
	}

	retryTimes = getEnvWithDefault("APPVIEWX_RETRY_COUNT", defaultRetryTimes)
	retryWaitTimeInSeconds = getEnvWithDefault("APPVIEWX_RETRY_TIME_IN_SECONDS", defaultRetryWaitTimeInSeconds)

}

func setEnvironmentVariables() {

	os.Setenv("LOG_LEVEL", "DEBUG")
	os.Setenv("APPVIEWX_ENV_HOST", "192.168.95.157")
	os.Setenv("APPVIEWX_ENV_PORT", "31443")
	os.Setenv("APPVIEWX_ENV_IS_HTTPS", "true")
	os.Setenv("APPVIEWX_ENV_USER_NAME", "admin")
	os.Setenv("APPVIEWX_ENV_PASSWORD", "AppViewX@123")
	os.Setenv("APPVIEWX_ENV_CERTIFICATE_AUTHORITY", "Ejbca")
	os.Setenv("APPVIEWX_ENV_CA_SETTING_NAME", "Ejbca")
	os.Setenv("APPVIEWX_ENV_CERTIFICATE_GROUP_NAME", "Default")
	os.Setenv("APPVIEWX_ENV_CATEGORY", "server")
	os.Setenv("APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS", `{"issuerCommonName":"NEW SUB CA","certificateProfileName":"HOURS PROFILE","endEntityProfileName":"APPVIEWX PROFILE","userName":"test"}`)
	os.Setenv("APPVIEWX_THROUGHPUT", "20")

}

func getEnvWithDefault(envVarName string, defaultValue int) int {
	if os.Getenv(envVarName) == "" {
		log.Printf("Environment Variable : %s is not set proceeding with default value : %d ", envVarName, defaultValue)
		return defaultValue
	}
	value, err := strconv.Atoi(os.Getenv(envVarName))
	if err != nil {
		log.Printf("Error in parsing %s : %+v : Setting defaul value : %d\n", envVarName, err, defaultValue)
		return defaultValue
	}
	log.Printf("%s is set with value : %d ", envVarName, value)
	return value

}

//TODO: - to Remove channel c once UUID issue is fixed
func MakeCallToAppViewXAndGetCertificate(ctx context.Context, csr *x509.CertificateRequest, serverOpts *common.ServerOpts) (cert []byte, err error) {

	log.Printf("Creating Certificate in AppViewX")
	resourceID, certificateContentFromAppViewX, statusCode, err := api.CreateCertificate(ctx, appviewxEnv, appviewxEnv.SessionID, getCSRContent(ctx, csr))
	if statusCode == 407 {
		log.Printf("SessionID invalid, Generating new SessionID")
		sessionMutex.Lock()
		if appviewxEnv.SessionLastGenerationTime.Add(time.Minute).Before(time.Now()) {
			log.Printf("Old Session : Generating New")
			sessionID, err := api.LoginAndGetSessionID(ctx, appviewxEnv)
			if err != nil || len(sessionID) <= 0 {
				log.Printf("Session ID : " + sessionID)
				log.Printf("Error in getting the sessionID : ", zap.Error(err))
				return nil, err
			}
			// log.Printf("sessionID : " + sessionID)
			log.Printf("Login Successful AppViewX")
			appviewxEnv.SessionID = sessionID
			appviewxEnv.SessionLastGenerationTime = time.Now()
		}
		sessionMutex.Unlock()
		resourceID, certificateContentFromAppViewX, statusCode, err = api.CreateCertificate(ctx, appviewxEnv, appviewxEnv.SessionID, getCSRContent(ctx, csr))
	}
	if err != nil {
		log.Printf("Error in Creating the Certificate : ", zap.Error(err))
		return
	}
	log.Printf("resourceID : " + resourceID)
	log.Printf("Finished Creating Certificate in AppViewX")

	log.Printf("Downloading the Certificate from AppViewX")
	certificateContents := ""

	//TODO:
	if rootAndIntermediateCert, ok := caSettingNameWiseRootAndIntermediateCert[appviewxEnv.CaSettingName]; ok && certificateContentFromAppViewX != "" {
		// if _, ok := caSettingNameWiseRootAndIntermediateCert[appviewxEnv.CaSettingName]; ok && certificateContentFromAppViewX != "" {
		log.Printf(fmt.Sprintf("Certificate received in certificate/create "))
		//TODO: handle if parent certificate is already available and certificateContent is available
		certChainCertificateBytes, err := base64.StdEncoding.DecodeString(certificateContentFromAppViewX)
		if err != nil {
			log.Println("Error in decoding the certChainCertificateBytes")
			return nil, err
		}
		//TODO:
		certificateContents = string(certChainCertificateBytes) + rootAndIntermediateCert
		// certificateContents = string(certChainCertificateBytes)
	} else {
		log.Printf(fmt.Sprintf("Certificate not received in certificate/create "))
		for i := retryTimes; certificateContents == "" && i > 0; i-- {
			log.Printf("downloadCertificate : RetryTimes : " + fmt.Sprintf("%d", i))
			time.Sleep(time.Second * time.Duration(retryWaitTimeInSeconds))
			certificateContents, err = api.DownloadCertificate(ctx, appviewxEnv, appviewxEnv.SessionID, resourceID, i)
		}
		log.Printf("certificateContents : " + certificateContents)

		if certificateContents == "" {
			return nil, errors.New("certificateContents is empty ")
		}

		//Setting RootAndIntermediate certs as cache
		//TODO:
		setRootAndIntermediateCertsInMap(ctx, caSettingNameWiseRootAndIntermediateCert, certificateContents)
		// certificateContents = setRootAndIntermediateCertsInMap(ctx, caSettingNameWiseRootAndIntermediateCert, certificateContents)

		log.Printf("Finished Downloading the Certificate from AppViewX")

		log.Printf("Getting GetCertChainCertificate")

		log.Printf("Finished Getting First Certificate")

		//TODO: - load cache with parent certificate
	}
	log.Printf("certificateContents : \n" + strings.Trim(certificateContents, "\n"))

	// cert = certificateX509.Raw

	//TODO: - TO CHECK certificate response to istiod 300920201308
	cert = []byte(certificateContents)

	log.Printf("Finished Decoding the Certificate")

	return
}

func setRootAndIntermediateCertsInMap(ctx context.Context, caSettingNameWiseRootAndIntermediateCert map[string]string, certificateContents string) string {
	log.Printf("Setting caSettingNameWiseRootAndIntermediateCert with Root and Intermediate certs")
	index := strings.Index(certificateContents, "-----END CERTIFICATE-----")
	index += len("-----END CERTIFICATE-----")
	output := certificateContents[:index]

	rootAndIntermediateCerts := certificateContents[index:]
	rootAndIntermediateCerts = strings.Trim(rootAndIntermediateCerts, "\n")
	caSettingNameWiseRootAndIntermediateCert[appviewxEnv.CaSettingName] = rootAndIntermediateCerts

	return output
}

func getAppViewXEnv() (appviewxEnv *appviewxcommon.AppViewXEnv, err error) {
	log.Printf("Executing getAppViewXEnv")
	log.Printf(certs.CurrentCA)
	switch certs.CurrentCA {
	case certs.AppViewXCA:
		return getAppViewXEnvWithAppViewXCA()
	case certs.MicrosoftCA:
		return getAppViewXEnvWithVendorSpecificDetails()
	case certs.EJBCA:
		return getAppViewXEnvWithVendorSpecificDetails()
	}
	return
}

func getAppViewXEnvCommon() (appviewxEnv *appviewxcommon.AppViewXEnv, err error) {
	log.Printf("executing getAppViewXEnvCommon")
	appviewxEnv = &appviewxcommon.AppViewXEnv{}

	isHTTPS := os.Getenv("APPVIEWX_ENV_IS_HTTPS")
	if isHTTPS == "" {
		appviewxEnv.AppViewXIsHTTPS = true
	} else {
		appviewxIsHTTPS, err := strconv.ParseBool(os.Getenv("APPVIEWX_ENV_IS_HTTPS"))
		if err != nil {
			return appviewxEnv, err
		}
		appviewxEnv.AppViewXIsHTTPS = appviewxIsHTTPS
	}

	appviewxEnv.AppViewXHost = os.Getenv("APPVIEWX_ENV_HOST")
	if appviewxEnv.AppViewXHost == "" {
		return appviewxEnv, fmt.Errorf("APPVIEWX_ENV_HOST is not set")
	}

	appviewxPort, err := strconv.Atoi(os.Getenv("APPVIEWX_ENV_PORT"))
	if err != nil {
		return
	}
	appviewxEnv.AppViewXPort = appviewxPort

	appviewxEnv.AppViewXUserName = os.Getenv("APPVIEWX_ENV_USER_NAME")
	if appviewxEnv.AppViewXUserName == "" {
		return appviewxEnv, fmt.Errorf("APPVIEWX_ENV_USER_NAME is not set")
	}

	appviewxEnv.AppViewXPassword = os.Getenv("APPVIEWX_ENV_PASSWORD")
	if appviewxEnv.AppViewXPassword == "" {
		return appviewxEnv, fmt.Errorf("APPVIEWX_ENV_PASSWORD is not set")
	}

	appviewxEnv.CertificateAuthority = os.Getenv("APPVIEWX_ENV_CERTIFICATE_AUTHORITY")
	appviewxEnv.CaSettingName = os.Getenv("APPVIEWX_ENV_CA_SETTING_NAME")

	if os.Getenv("APPVIEWX_ENV_VALIDITY_IN_DAYS") != "" {
		validityInDays, errlocal := strconv.Atoi(os.Getenv("APPVIEWX_ENV_VALIDITY_IN_DAYS"))
		if errlocal != nil {
			err = errlocal
			return
		}
		appviewxEnv.ValidityInDays = validityInDays
	}

	appviewxEnv.CertificateGroupName = os.Getenv("APPVIEWX_ENV_CERTIFICATE_GROUP_NAME")
	appviewxEnv.Category = os.Getenv("APPVIEWX_ENV_CATEGORY")

	//TODO: - TO REMOVE
	appviewxEnvBytes, err := json.Marshal(appviewxEnv)
	if err != nil {
		log.Println("Error in Marshalling - ignore")
		return
	}
	r, err := regexp.Compile("appviewxPassword[^,]+")
	if err != nil {
		log.Println("Error in compiling appviewxEnvBytes - ignore")
		return
	}
	appviewxEnvBytes = r.ReplaceAll(appviewxEnvBytes, []byte(""))

	log.Printf("appviewxEnvBytes : %s\n", string(appviewxEnvBytes))

	return
}

func getAppViewXEnvWithAppViewXCA() (appviewxEnv *appviewxcommon.AppViewXEnv, err error) {
	return getAppViewXEnvCommon()
}

func getAppViewXEnvWithVendorSpecificDetails() (appviewxEnv *appviewxcommon.AppViewXEnv, err error) {
	log.Printf("executing getAppViewXEnvWithVendorSpecificDetails")
	appviewxEnv, err = getAppViewXEnvCommon()
	if err != nil {
		return
	}

	appviewxEnv.Name = os.Getenv("APPVIEWX_ENV_NAME")

	vendorSpecificDetails := map[string]interface{}{}
	vendorSpecificDetailsString := os.Getenv("APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS")

	err = json.Unmarshal([]byte(vendorSpecificDetailsString), &vendorSpecificDetails)
	if err != nil {
		return
	}

	appviewxEnv.VendorSpecificDetails = vendorSpecificDetails

	return
}

func getCSRContent(ctx context.Context, csr *x509.CertificateRequest) (output string) {
	// csr.Subject.CommonName = "apviewxtest.com"

	output = api.CSRBytesToPEMString(ctx, csr.Raw)
	log.Printf("CSR : \n" + output)
	return
}

