package common

import (
	"encoding/json"
)

const (
	APPVIEWX_ENV_IS_HTTPS                = "APPVIEWX_ENV_IS_HTTPS"
	APPVIEWX_ENV_HOST                    = "APPVIEWX_ENV_HOST"
	APPVIEWX_ENV_PORT                    = "APPVIEWX_ENV_PORT"
	APPVIEWX_ENV_USER_NAME               = "APPVIEWX_ENV_USER_NAME"
	APPVIEWX_ENV_PASSWORD                = "APPVIEWX_ENV_PASSWORD"
	APPVIEWX_ENV_CERTIFICATE_AUTHORITY   = "APPVIEWX_ENV_CERTIFICATE_AUTHORITY"
	APPVIEWX_ENV_CA_SETTING_NAME         = "APPVIEWX_ENV_CA_SETTING_NAME"
	APPVIEWX_ENV_NAME                    = "APPVIEWX_ENV_CA_NAME"
	APPVIEWX_ENV_VALIDITY_IN_DAYS        = "APPVIEWX_ENV_VALIDITY_IN_DAYS"
	APPVIEWX_ENV_CERTIFICATE_GROUP_NAME  = "APPVIEWX_ENV_CERTIFICATE_GROUP_NAME"
	APPVIEWX_ENV_CATEGORY                = "APPVIEWX_ENV_CATEGORY"
	APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS = "APPVIEWX_ENV_VENDOR_SPECIFIC_DETAILS"
)

//ServerOpts to capture the server flags and start the server
type ServerOpts struct {
	GrpcHostName     string
	GrpcPort         string
	Protocol         string
	AppViewXHostName string
	AppViewXPort     string
	AppViewXIsHTTPS  bool
	CAName           string
	CASettingName    string
}

func (serverOpts ServerOpts) String() string {
	outputMarshalled, _ := json.Marshal(serverOpts)
	return string(outputMarshalled)
}
