package appviewx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type SessionPayload struct{}

type AppViewXEnv struct {
	AppViewXIsHTTPS           bool                   `json:"appviewxIsHTTPS"`
	AppViewXHost              string                 `json:"appviewxHost"`
	AppViewXPort              int                    `json:"appviewxPort"`
	AppViewXUserName          string                 `json:"appviewxUserName"`
	AppViewXPassword          string                 `json:"appviewxPassword"`
	CertificateAuthority      string                 `json:"certificateAuthority"`
	CaSettingName             string                 `json:"caSettingName"`
	Name                      string                 `json:"name,omitempty"`
	ValidityInDays            int                    `json:"validityInDays"`
	CertificateGroupName      string                 `json:"certificateGroupName"`
	Category                  string                 `json:"category"`
	VendorSpecificDetails     map[string]interface{} `json:"vendorSpecificDetails"`
	SessionID                 string
	SessionLastGenerationTime time.Time
}

type SessionResponse struct {
	Response      SessionResponseInternal `json:"response"`
	Message       interface{}             `json:"message"`
	AppStatusCode interface{}             `json:"appStatusCode"`
	Tags          interface{}             `json:"tags"`
	Headers       interface{}             `json:"headers"`
}

type SessionResponseInternal struct {
	Status                     string      `json:"status"`
	AppStatusCode              interface{} `json:"appStatusCode"`
	StatusDescription          interface{} `json:"statusDescription"`
	SessionId                  string      `json:"sessionId"`
	AvailableLoginAttemptCount string      `json:"availableLoginAttemptCount"`
}

type CreateCertificatePayload struct {
	WorkFlowType      string             `json:"workflowType"`
	UniqueCertificate bool               `json:"uniqueCertificate"`
	CaConnectorInfo   CaConnectorInfo    `json:"caConnectorInfo"`
	CertificateGroup  CertificateGroup   `json:"certificateGroup"`
	UploadCSRDetails  UploadCSRDetails   `json:"uploadCsrDetails"`
	CertificateFormat *CertificateFormat `json:"certificateFormat"`
}

type CertificateFormat struct {
	Format   string `json:"format"`
	Password string `json:"password"`
}

type UploadCSRDetails struct {
	CSRContent *string `json:"csrContent"`
	Category   string  `json:"category"`
}

type CertificateGroup struct {
	Name string `json:"name"`
}

type CaConnectorInfo struct {
	CertificateAuthority   string                 `json:"certificateAuthority"`
	CaSettingName          string                 `json:"caSettingName"`
	Name                   string                 `json:"name,omitempty"`
	GenericFields          interface{}            `json:"genericFields"`
	VendorSpecificDetails  map[string]interface{} `json:"vendorSpecificDetails"`
	CustomAttributes       interface{}            `json:"customAttributes"`
	CertAttributes         interface{}            `json:"certAttributes"`
	ValidityInDays         int                    `json:"validityInDays"`
	CertificateProfileName string                 `json:"certificateProfileName"`
	CsrParameters          interface{}            `json:"csrParameters"`
}

type CreateCertificateResponse struct {
	Response      *CreateCertificateResponseInternal `json:"response"`
	Message       string                             `json:"message"`
	AppStatusCode interface{}                        `json:"appStatusCode"`
	Tags          interface{}                        `json:"tags"`
	Headers       interface{}                        `json:"headers"`
}

type CreateCertificateResponseInternal struct {
	ResourceID         *string `json:"resourceId"`
	RequestId          *string `json:"requestId"`
	CertificateContent *string `json:"certificateContent"`
}

type DownloadCertificateResponse struct {
	Response      DownloadCertificateResponseInternal `json:"response"`
	Message       string                              `json:"message"`
	AppStatusCode interface{}                         `json:"appStatusCode"`
	Tags          interface{}                         `json:"tags"`
	Headers       interface{}                         `json:"headers"`
}

type DownloadCertificateResponseInternal struct {
	CertificateContents string `json:"certificateContents"`
	PrivateKeyContent   string `json:"privateKeyContent"`
	CommonName          string `json:"commonName"`
	SerialNumber        string `json:"serialNumber"`
	Format              string `json:"format"`
	Success             bool   `json:"success"`
}

func GenerateURL(ctx context.Context, isHTTPS bool, appviewxHost string, appviewxPort int, subPath string, queryParam map[string]string) (string, error) {
	buffer := bytes.Buffer{}
	if isHTTPS {
		buffer.WriteString("https://")
	} else {
		buffer.WriteString("http://")
	}

	if len(appviewxHost) > 0 {
		buffer.WriteString(appviewxHost)
	} else {
		return "", errors.New("Error in appviewxHost : " + appviewxHost)
	}

	if appviewxPort > 0 {
		buffer.WriteString((":" + fmt.Sprintf("%d", appviewxPort)))
	} else {
		return "", errors.New("Error in appviewxPort : " + fmt.Sprintf("%d", appviewxPort))
	}

	buffer.WriteString("/avxapi/")

	buffer.WriteString(subPath)

	isItFirstTime := true
	for key, value := range queryParam {
		if isItFirstTime {
			isItFirstTime = false
			buffer.WriteString("?")
		} else {
			buffer.WriteString("&")
		}
		buffer.WriteString((key + "=" + value))
	}
	return buffer.String(), nil
}

func (signer *ApViewXSigner) MakePostCallAndReturnResponse(ctx context.Context, url string, payload interface{}, additionalRequestHeaders map[string]string) (output []byte, statusCode int, err error) {

	log := signer.Log.WithName("make-call-post").WithValues("certificatesigningrequest", ctx.Value("name"))

	log.V(1).Info("url : " + url)
	requestPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Error(err, "loginAndGetSessionID - Error in Marshalling the request Payload ")
		return nil, 0, err
	}
	log.V(1).Info("Payload : " + string(requestPayloadBytes))

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestPayloadBytes))
	if err != nil {
		log.Error(err, "Error in creating Post request ")
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Error(err, "Error in making http request : ")
		return nil, 0, err
	}
	defer response.Body.Close()
	statusCode = response.StatusCode

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Error(err, "Error in reading the response : ")
		return nil, 0, err
	}
	output = body
	return
}

func (signer *ApViewXSigner) MakeGetCallAndReturnResponse(ctx context.Context, url string, additionalRequestHeaders map[string]string) (output []byte, err error) {

	log := signer.Log.WithName("make-call-get").WithValues("certificatesigningrequest", ctx.Value("name"))

	log.V(1).Info("url : " + url)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err, "Error in creating Post request ")
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Error(err, "Error in making http request : ")
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Error(err, "Error in reading the response : ")
		return nil, err
	}
	output = body
	return
}
