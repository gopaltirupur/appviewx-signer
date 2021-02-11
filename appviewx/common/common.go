package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
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
	CaConnectorInfo   CaConnectorInfo   `json:"caConnectorInfo"`
	CertificateGroup  CertificateGroup  `json:"certificateGroup"`
	UploadCSRDetails  UploadCSRDetails  `json:"uploadCsrDetails"`
	CertificateFormat CertificateFormat `json:"certificateFormat"`
}

type CertificateFormat struct {
	Format   string `json:"format"`
	Password string `json:"password"`
}

type UploadCSRDetails struct {
	CSRContent string `json:"csrContent"`
	Category   string `json:"category"`
}

type CertificateGroup struct {
	Name string `json:"name"`
}

type CaConnectorInfo struct {
	CertificateAuthority   string      `json:"certificateAuthority"`
	CaSettingName          string      `json:"caSettingName"`
	Name                   string      `json:"name,omitempty"`
	GenericFields          interface{} `json:"genericFields"`
	VendorSpecificDetails  interface{} `json:"vendorSpecificDetails"`
	CustomAttributes       interface{} `json:"customAttributes"`
	CertAttributes         interface{} `json:"certAttributes"`
	ValidityInDays         int         `json:"validityInDays"`
	CertificateProfileName string      `json:"certificateProfileName"`
}

type CreateCertificateResponse struct {
	Response      CreateCertificateResponseInternal `json:"response"`
	Message       string                            `json:"message"`
	AppStatusCode interface{}                       `json:"appStatusCode"`
	Tags          interface{}                       `json:"tags"`
	Headers       interface{}                       `json:"headers"`
}

type CreateCertificateResponseInternal struct {
	ResourceID         string `json:"resourceId"`
	RequestId          string `json:"requestId"`
	CertificateContent string `json:"certificateContent"`
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
	success             bool   `json:"success"`
}

func GenerateURL(ctx context.Context, isHTTPS bool, appviewxHost string, appviewxPort int, subPath string, queryParam map[string]string) (output string, err error) {
	if isHTTPS {
		output += "https://"
	} else {
		output += "http://"
	}

	if len(appviewxHost) > 0 {
		output += appviewxHost
	} else {
		return "", errors.New("Error in appviewxHost : " + appviewxHost)
	}

	if appviewxPort > 0 {
		output += (":" + fmt.Sprintf("%d", appviewxPort))
	} else {
		return "", errors.New("Error in appviewxPort : " + fmt.Sprintf("%d", appviewxPort))
	}

	output += "/avxapi/"

	output += subPath

	isItFirstTime := true
	for key, value := range queryParam {
		if isItFirstTime {
			isItFirstTime = false
			output += "?"
		} else {
			output += "&"
		}
		output += (key + "=" + value)
	}
	log.Printf("Constructed URL : " + output)
	return
}

func MakePostCallAndReturnResponse(ctx context.Context, url string, payload interface{}, additionalRequestHeaders map[string]string) (output []byte, statusCode int, err error) {
	log.Printf("url : " + url)
	requestPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("loginAndGetSessionID - Error in Marshalling the request Payload ", zap.Error(err))
		return nil, 0, err
	}
	log.Printf("Payload : " + string(requestPayloadBytes))

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestPayloadBytes))
	if err != nil {
		log.Printf("Error in creating Post request ", zap.Error(err))
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Printf("Error in making http request : ", zap.Error(err))
		return nil, 0, err
	}
	defer response.Body.Close()
	statusCode = response.StatusCode

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Printf("Error in reading the response : ", zap.Error(err))
		return nil, 0, err
	}
	output = body
	return
}

func MakeGetCallAndReturnResponse(ctx context.Context, url string, additionalRequestHeaders map[string]string) (output []byte, err error) {
	log.Printf("url : " + url)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error in creating Post request ", zap.Error(err))
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	for key, value := range additionalRequestHeaders {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		log.Printf("Error in making http request : ", zap.Error(err))
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil || len(body) <= 0 {
		log.Printf("Error in reading the response : ", zap.Error(err))
		return nil, err
	}
	output = body
	return
}

func GetCertChainCertificate(ctx context.Context, certificateContents string) (certificate string) {
	fileContentsString := string(certificateContents)
	fileContentsArr := strings.Split(fileContentsString, "-----END CERTIFICATE-----")

	certificate = (strings.Trim(fileContentsArr[0], "\n"))
	certificate += "\n-----END CERTIFICATE-----"

	log.Printf("GetCertChainCertificate : " + string(certificate))

	// for _, cert := range fileContentsArr[:len(fileContentsArr)-2] {
	// 	certificate += ("\n\n" + strings.Trim(cert, "\n"))
	// 	certificate += "\n-----END CERTIFICATE-----"
	// 	// return cert
	// }
	return
}

func GetRandomString(ctx context.Context) (output string) {
	characterSet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	length := 10
	b := make([]byte, length)
	for i := range b {
		b[i] = characterSet[seededRand.Intn(len(characterSet))]
	}
	return string(b)
}

func AddNewLine(certBytes []byte) (output []byte) {
	output = []byte(string(certBytes) + "\n")
	return
}
