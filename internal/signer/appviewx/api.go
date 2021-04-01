package appviewx

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
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

func (signer *ApViewXSigner) DownloadCertificate(ctx context.Context, appviewxEnv *AppViewXEnv, sessionID, resourceID string, retryTimes int) (certificateContents string, err error) {
	log := signer.Log.WithName("download-certificate").WithValues("certificatesigningrequest", ctx.Value("name"))
	log.V(1).Info(" -------------------------------------- Starting downloadCertificate -------------------------------------- ")

	queryParam := getCommonQueryParamMap()
	queryParam["resourceId"] = resourceID
	queryParam["isChainRequired"] = "true"

	url, err := GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "certificate/download/content", queryParam)
	if err != nil {
		log.Error(err, "downloadCertificate - Error in generating url : ")
		return "", err
	}

	log.V(1).Info("Constructed URL : " + url)

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["sessionId"] = sessionID

	responseContents, err := signer.MakeGetCallAndReturnResponse(ctx, url, additionalRequestHeaders)
	if err != nil {
		log.Error(err, "Error inmaking the download certificate : ")
		return "", err
	}

	log.V(1).Info("Response in Download Certificate : " + string(responseContents))

	downloadCertificateResponse := DownloadCertificateResponse{}
	json.Unmarshal(responseContents, &downloadCertificateResponse)

	certificateContents = downloadCertificateResponse.Response.CertificateContents
	log.V(1).Info("Length of certificateContents : " + fmt.Sprintf("%d", len(certificateContents)))
	log.V(1).Info(" -------------------------------------- Finished downloadCertificate -------------------------------------- ")
	return
}

func (signer *ApViewXSigner) CreateCertificate(ctx context.Context, appviewxEnv *AppViewXEnv, sessionID string, csrContent *string, isSync bool,
	externalRequestID string, isDownload bool) (resourceID, certificateContents *string, statusCode int, err error) {

	log := signer.Log.WithName("create-certificate").WithValues("certificatesigningrequest", ctx.Value("name"))
	log.V(1).Info(" -------------------------------------- Starting createCertificate -------------------------------------- ")
	requestPayload := getPayloadForCreateCertificate(ctx, appviewxEnv, csrContent, externalRequestID, isDownload)

	queryParamMap := getCommonQueryParamMap()
	if isSync {
		queryParamMap["isSync"] = "true"
	} else {
		queryParamMap["isSync"] = "false"
	}
	queryParamMap["ttl"] = appviewxSyncCertificateTTLInSec

	url, err := GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "certificate/create", queryParamMap)
	if err != nil {
		log.V(1).Info("createCertificate - Error in generating url for session ID : ", zap.Error(err))
		return nil, nil, 0, err
	}

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["sessionId"] = sessionID

	responseContents, statusCode, err := signer.MakePostCallAndReturnResponse(ctx, url, requestPayload, additionalRequestHeaders)
	if err != nil {
		log.V(1).Info("Error in making Create Certificate : ", zap.Error(err))
		return nil, nil, 0, err
	}

	log.V(1).Info(fmt.Sprintf("Response in Create Certificate ExternalRequestID : %s : Response : %s", externalRequestID, (responseContents)))

	certificateResponse := &CreateCertificateResponse{}
	json.Unmarshal(responseContents, certificateResponse)

	if certificateResponse.Response != nil {
		resourceID = certificateResponse.Response.ResourceID
		certificateContents = certificateResponse.Response.CertificateContent
	}

	log.V(1).Info(" -------------------------------------- Finished createCertificate -------------------------------------- ")
	if certificateContents != nil {
		log.V(1).Info(fmt.Sprintf("Length of certificateContents : %d", len(*certificateContents)))
	}

	return
}

func getPayloadForCreateCertificate(ctx context.Context, appviewxEnv *AppViewXEnv, csrContent *string, externalRequestID string, isDownload bool) (output *CreateCertificatePayload) {
	output = &CreateCertificatePayload{}
	output.WorkFlowType = "CERT"

	if isDownload {
		output.UniqueCertificate = true
	}

	caConnectorInfo := CaConnectorInfo{}
	caConnectorInfo.CertificateAuthority = appviewxEnv.CertificateAuthority
	caConnectorInfo.CaSettingName = appviewxEnv.CaSettingName
	caConnectorInfo.Name = appviewxEnv.Name
	caConnectorInfo.GenericFields = map[string]string{"externalRequestId": externalRequestID}
	caConnectorInfo.CertificateProfileName = "Server"
	caConnectorInfo.CsrParameters = map[string]string{}
	caConnectorInfo.VendorSpecificDetails = getCAConnectorInfoVendorSpecificDetails(appviewxEnv.VendorSpecificDetails)

	caConnectorInfo.CustomAttributes = map[string]string{}
	caConnectorInfo.CertAttributes = map[string]string{}
	caConnectorInfo.ValidityInDays = appviewxEnv.ValidityInDays
	output.CaConnectorInfo = caConnectorInfo

	certificateGroup := CertificateGroup{}
	certificateGroup.Name = appviewxEnv.CertificateGroupName
	output.CertificateGroup = certificateGroup

	uploadCSRDetails := UploadCSRDetails{}

	if !isDownload {
		uploadCSRDetails.CSRContent = csrContent
	}
	uploadCSRDetails.Category = appviewxEnv.Category
	output.UploadCSRDetails = uploadCSRDetails

	certificateFormat := CertificateFormat{}
	certificateFormat.Format = "PEM"
	output.CertificateFormat = &certificateFormat

	return
}

func getCAConnectorInfoVendorSpecificDetails(vendorSpecificDetails map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	if len(vendorSpecificDetails) != 0 {
		for k, v := range vendorSpecificDetails {
			output[k] = v
		}
	}
	output["userName"] = uuid.New().String()
	return output
}

func getCommonQueryParamMap() (output map[string]string) {
	queryParam := map[string]string{}
	queryParam["gwkey"] = "f000ca01"
	queryParam["gwsource"] = "external"
	return queryParam
}

func (signer *ApViewXSigner) LoginAndGetSessionID(ctx context.Context, appviewxEnv *AppViewXEnv) (output string, err error) {

	log := signer.Log.WithName("login").WithValues("certificatesigningrequest", ctx.Value("name"))

	log.V(1).Info(" -------------------------------------- Starting loginAndGetSessionID -------------------------------------- ")
	requestPayload := SessionPayload{}

	url, err := GenerateURL(ctx, appviewxEnv.AppViewXIsHTTPS, appviewxEnv.AppViewXHost, appviewxEnv.AppViewXPort, "acctmgmt-perform-login", getCommonQueryParamMap())
	if err != nil {
		log.Error(err, "loginAndGetSessionID - Error in generating url for session ID :")
		return "", err
	}

	additionalRequestHeaders := map[string]string{}
	additionalRequestHeaders["username"] = appviewxEnv.AppViewXUserName
	additionalRequestHeaders["password"] = appviewxEnv.AppViewXPassword

	responseContents, _, err := signer.MakePostCallAndReturnResponse(ctx, url, requestPayload, additionalRequestHeaders)
	if err != nil {
		log.Error(err, "Error in making login Call : ")
		return "", err
	}

	log.V(1).Info("Response in Login : " + string(responseContents))

	sessionResponse := SessionResponse{}
	json.Unmarshal(responseContents, &sessionResponse)

	// v, _ := json.Marshal(sessionResponse)
	// log.V(1).Info(string(v))
	output = sessionResponse.Response.SessionId

	log.V(1).Info(" -------------------------------------- Finished loginAndGetSessionID -------------------------------------- ")

	return
}
