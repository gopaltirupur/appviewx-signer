package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gopaltirupur/appviewx-signer/appviewx/common"

	"go.uber.org/zap"
)

var appviewxSyncCertificateTTLInSec string
var defaultAppViewXSyncCertificateTTLInSec = "60"

func init() {
	appviewxSyncCertificateTTLInSec = os.Getenv("APPVIEWX_SYNC_CERTIFICATE_TTL")
	if appviewxSyncCertificateTTLInSec == "" {
		appviewxSyncCertificateTTLInSec = defaultAppViewXSyncCertificateTTLInSec
		log.Printf("APPVIEWX_SYNC_CERTIFICATE_TTL is set with default value %s", appviewxSyncCertificateTTLInSec)
	} else {
		log.Printf("APPVIEWX_SYNC_CERTIFICATE_TTL is set with value %s", appviewxSyncCertificateTTLInSec)
	}
}

func CSRBytesToPEMString(ctx context.Context, input []byte) (output string) {
	buf := bytes.NewBuffer([]byte{})
	pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: input})
	return string(buf.Bytes())
}

func GetFirstCertificate(ctx context.Context, certificateContents string) (certificate string) {
	fileContentsString := string(certificateContents)
	fileContentsArr := strings.Split(fileContentsString, "-----END CERTIFICATE-----")

	for _, cert := range fileContentsArr {
		cert := strings.Trim(cert, "\n")
		cert += "\n-----END CERTIFICATE-----"
		return cert
	}
	return
}

func DownloadCertificate(ctx context.Context, appviewxEnv *common.AppViewXEnv, sessionID, resourceID string, retryTimes int) (certificateContents string, err error) {
	log.Printf(" -------------------------------------- Starting downloadCertificate -------------------------------------- ")

	queryParam := getCommonQueryParamMap()
	queryParam["resourceId"] = resourceID
	queryParam["isChainRequired"] = "true"

	url, err := common.GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "certificate/download/content", queryParam)
	if err != nil {
		log.Printf("downloadCertificate - Error in generating url : ", zap.Error(err))
	}

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["sessionId"] = sessionID

	responseContents, err := common.MakeGetCallAndReturnResponse(ctx, url, additionalRequestHeaders)
	if err != nil {
		log.Printf("Error inmaking the download certificate : ", zap.Error(err))
		return "", err
	}

	log.Printf("Response in Download Certificate : " + string(responseContents))

	downloadCertificateResponse := common.DownloadCertificateResponse{}
	json.Unmarshal(responseContents, &downloadCertificateResponse)

	certificateContents = downloadCertificateResponse.Response.CertificateContents
	log.Printf("Length of certificateContents : " + fmt.Sprintf("%d", len(certificateContents)))
	log.Printf(" -------------------------------------- Finished downloadCertificate -------------------------------------- ")
	return
}

func CreateCertificate(ctx context.Context, appviewxEnv *common.AppViewXEnv, sessionID, csrContent string) (resourceID, certificateContents string, statusCode int, err error) {
	log.Printf(" -------------------------------------- Starting createCertificate -------------------------------------- ")
	requestPayload := getPayloadForCreateCertificate(ctx, appviewxEnv, csrContent)

	queryParamMap := getCommonQueryParamMap()
	queryParamMap["isSync"] = "true"
	queryParamMap["ttl"] = appviewxSyncCertificateTTLInSec

	url, err := common.GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "certificate/create", queryParamMap)
	if err != nil {
		log.Printf("createCertificate - Error in generating url for session ID : ", zap.Error(err))
		return "", "", 0, err
	}

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["sessionId"] = sessionID

	responseContents, statusCode, err := common.MakePostCallAndReturnResponse(ctx, url, requestPayload, additionalRequestHeaders)
	if err != nil {
		log.Printf("Error in making Create Certificate : ", zap.Error(err))
		return "", "", 0, err
	}

	log.Printf("Response in Create Certificate : " + string(responseContents))

	certificateResponse := common.CreateCertificateResponse{}
	json.Unmarshal(responseContents, &certificateResponse)

	resourceID = certificateResponse.Response.ResourceID
	certificateContents = certificateResponse.Response.CertificateContent

	log.Printf(" -------------------------------------- Finished createCertificate -------------------------------------- ")

	return
}

func getPayloadForCreateCertificate(ctx context.Context, appviewxEnv *common.AppViewXEnv, csrContent string) (output common.CreateCertificatePayload) {
	output = common.CreateCertificatePayload{}

	caConnectorInfo := common.CaConnectorInfo{}
	caConnectorInfo.CertificateAuthority = appviewxEnv.CertificateAuthority
	caConnectorInfo.CaSettingName = appviewxEnv.CaSettingName
	caConnectorInfo.Name = appviewxEnv.Name
	caConnectorInfo.GenericFields = map[string]string{}
	caConnectorInfo.CertificateProfileName = "Server"

	if appviewxEnv.VendorSpecificDetails == nil {
		caConnectorInfo.VendorSpecificDetails = map[string]string{}
	} else {
		caConnectorInfo.VendorSpecificDetails = appviewxEnv.VendorSpecificDetails
	}

	caConnectorInfo.CustomAttributes = map[string]string{}
	caConnectorInfo.CertAttributes = map[string]string{}
	caConnectorInfo.ValidityInDays = appviewxEnv.ValidityInDays
	output.CaConnectorInfo = caConnectorInfo

	certificateGroup := common.CertificateGroup{}
	certificateGroup.Name = appviewxEnv.CertificateGroupName
	output.CertificateGroup = certificateGroup

	uploadCSRDetails := common.UploadCSRDetails{}
	uploadCSRDetails.CSRContent = csrContent
	uploadCSRDetails.Category = appviewxEnv.Category
	output.UploadCSRDetails = uploadCSRDetails

	certificateFormat := common.CertificateFormat{}
	certificateFormat.Format = "PEM"
	output.CertificateFormat = certificateFormat

	return
}

func getCommonQueryParamMap() (output map[string]string) {
	queryParam := map[string]string{}
	queryParam["gwkey"] = "f000ca01"
	queryParam["gwsource"] = "external"
	return queryParam
}

func LoginAndGetSessionID(ctx context.Context, appviewxEnv *common.AppViewXEnv) (output string, err error) {

	log.Printf(" -------------------------------------- Starting loginAndGetSessionID -------------------------------------- ")

	requestPayload := common.SessionPayload{}

	url, err := common.GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "acctmgmt-perform-login", getCommonQueryParamMap())
	if err != nil {
		log.Printf("loginAndGetSessionID - Error in generating url for session ID :", zap.Error(err))
		return "", err
	}

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["username"] = appviewxEnv.AppViewXUserName
	additionalRequestHeaders["password"] = appviewxEnv.AppViewXPassword

	responseContents, _, err := common.MakePostCallAndReturnResponse(ctx, url, requestPayload, additionalRequestHeaders)
	if err != nil {
		log.Printf("Error in making login Call : ", zap.Error(err))
		return "", err
	}

	log.Printf("Response in Login : " + string(responseContents))

	sessionResponse := common.SessionResponse{}
	json.Unmarshal(responseContents, &sessionResponse)

	v, _ := json.Marshal(sessionResponse)
	log.Printf(string(v))
	output = sessionResponse.Response.SessionId

	log.Printf(" -------------------------------------- Finished loginAndGetSessionID -------------------------------------- ")

	return
}
