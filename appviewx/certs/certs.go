package certs

import (
	"os"

	"github.com/gopaltirupur/appviewx-signer/common"
)

var IsAppViewXRoutingRequired = true

const (
	AppViewXCA  = "AppViewX"
	MicrosoftCA = "Microsoft Enterprise"
	EJBCA       = "Ejbca"
)

var CurrentCA = os.Getenv(common.APPVIEWX_ENV_CERTIFICATE_AUTHORITY)

func GetRootCert() (output []byte) {
	if IsAppViewXRoutingRequired {

		switch CurrentCA {
		case AppViewXCA:
			output = getAppViewXRootCert()
		case MicrosoftCA:
			output = getMicrosoftRootCert()
		}

	} else {
		output = getExampleRootCert()
	}

	return
}

func GetInterMediateCert() (output []byte) {
	if IsAppViewXRoutingRequired {

		switch CurrentCA {
		case AppViewXCA:
			output = getAppViewXInterMediateCert()
		case MicrosoftCA:
			output = getMicrosoftInterMediateCert()
		}

	} else {
		output = getExampleInterMediateCert()
	}

	return
}

func GetInterMediateKey() (output []byte) {
	// if IsAppViewXCA {
	// output = getAppViewXInterMediateKey()
	// } else {
	output = getExampleInterMediateKey()
	// }

	return
}
