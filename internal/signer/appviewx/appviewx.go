package appviewx

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopaltirupur/appviewx-signer/internal/signer/common"
	"go.uber.org/zap"

	"github.com/go-logr/logr"
)

type ApViewXSigner struct {
	Log logr.Logger
}

var appviewxEnv *AppViewXEnv

var defaultRetryTimes int = 5
var defaultRetryWaitTimeInSeconds int = 2

var retryTimes int
var retryWaitTimeInSeconds int
var sessionMutex sync.Mutex

var caSettingNameWiseRootAndIntermediateCert map[string]string

func init() {

	caSettingNameWiseRootAndIntermediateCert = map[string]string{}
	var err error
	appviewxEnv, err = getAppViewXEnv()
	if err != nil {
		log.Fatalf("Error in getting environment variables : %+v", err)
	}

	retryTimes = getEnvWithDefault("APPVIEWX_RETRY_COUNT", defaultRetryTimes)
	retryWaitTimeInSeconds = getEnvWithDefault("APPVIEWX_RETRY_TIME_IN_SECONDS", defaultRetryWaitTimeInSeconds)

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

//MakeCallToAppViewXAndGetCertificate calls appviewx and handles sync or async mode of certificate enrollment
func (signer *ApViewXSigner) MakeCallToAppViewXAndGetCertificate(ctx context.Context, csr *string, serverOpts *common.ServerOpts,
	isSync bool, externalRequestID string, isDownload bool) (cert []byte, resourceID *string, err error) {
	log := signer.Log.WithName("getCertificate").WithValues("certificatesigningrequest", ctx.Value("name"))

	log.V(1).Info("Creating Certificate in AppViewX")
	resourceID, certificateContentFromAppViewX, statusCode, err := signer.CreateCertificate(ctx, appviewxEnv, appviewxEnv.SessionID, csr, isSync, externalRequestID, isDownload)
	if statusCode == 407 {
		log.V(1).Info("SessionID invalid, Generating new SessionID")
		sessionMutex.Lock()
		if appviewxEnv.SessionLastGenerationTime.Add(time.Minute).Before(time.Now()) {
			log.V(1).Info("Old Session : Generating New")
			sessionID, err := signer.LoginAndGetSessionID(ctx, appviewxEnv)
			if err != nil || len(sessionID) <= 0 {
				log.V(1).Info(fmt.Sprintf("Session ID : %d", len(sessionID)))
				log.V(1).Info("Error in getting the sessionID : %v", zap.Error(err))
				return nil, nil, err
			}
			log.V(1).Info("sessionID length : ", "length", len(sessionID))
			log.V(1).Info("Login Successful AppViewX")
			appviewxEnv.SessionID = sessionID
			appviewxEnv.SessionLastGenerationTime = time.Now()
		}
		sessionMutex.Unlock()
		resourceID, certificateContentFromAppViewX, statusCode, err = signer.CreateCertificate(ctx, appviewxEnv, appviewxEnv.SessionID, csr, isSync, externalRequestID, isDownload)
	}

	if statusCode == 429 {
		return nil, nil, fmt.Errorf("Status Code : %d", statusCode)
	}

	if !isSync {
		return
	}

	if err != nil {
		return
	}

	if certificateContentFromAppViewX == nil {
		log.V(1).Info("certificateContentFromAppViewX length is 0")
		return nil, nil, nil
	}

	if resourceID != nil {
		log.V(1).Info("resourceID : " + *resourceID)
	}

	cert, err = base64.StdEncoding.DecodeString(*certificateContentFromAppViewX)
	if err != nil {
		return nil, nil, err
	}

	// log.V(1).Info("certificateContentFromAppViewX : \n" + *certificateContentFromAppViewX)

	log.V(1).Info("Finished Decoding the Certificate")

	return
}

//TODO: - Not used
func setRootAndIntermediateCertsInMap(ctx context.Context, caSettingNameWiseRootAndIntermediateCert map[string]string, certificateContents string) string {
	index := strings.Index(certificateContents, "-----END CERTIFICATE-----")
	index += len("-----END CERTIFICATE-----")
	output := certificateContents[:index]

	rootAndIntermediateCerts := certificateContents[index:]
	rootAndIntermediateCerts = strings.Trim(rootAndIntermediateCerts, "\n")
	caSettingNameWiseRootAndIntermediateCert[appviewxEnv.CaSettingName] = rootAndIntermediateCerts

	return output
}

func getAppViewXEnv() (appviewxEnv *AppViewXEnv, err error) {
	log.Printf("Executing getAppViewXEnv")
	log.Printf(CurrentCA)
	switch CurrentCA {
	case AppViewXCA:
		return getAppViewXEnvWithAppViewXCA()
	case MicrosoftCA:
		return getAppViewXEnvWithVendorSpecificDetails()
	case EJBCA:
		return getAppViewXEnvWithVendorSpecificDetails()
	}
	return
}

func getAppViewXEnvCommon() (appviewxEnv *AppViewXEnv, err error) {
	log.Printf("executing getAppViewXEnvCommon")
	appviewxEnv = &AppViewXEnv{}

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

func getAppViewXEnvWithAppViewXCA() (appviewxEnv *AppViewXEnv, err error) {
	return getAppViewXEnvCommon()
}

func getAppViewXEnvWithVendorSpecificDetails() (appviewxEnv *AppViewXEnv, err error) {
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

func (signer *ApViewXSigner) getCSRContent(ctx context.Context, csr *x509.CertificateRequest) (output string) {
	log := signer.Log.WithName("getCSRContent").WithValues("certificatesigningrequest", ctx.Value("name"))
	if csr != nil {
		output = CSRBytesToPEMString(ctx, csr.Raw)
		log.V(2).Info("CSR : \n" + output)
	}
	return
}
