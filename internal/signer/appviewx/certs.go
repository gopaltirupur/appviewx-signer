package appviewx

import (
	"os"

	"github.com/gopaltirupur/appviewx-signer/internal/signer/common"
)

const (
	AppViewXCA  = "AppViewX"
	MicrosoftCA = "Microsoft Enterprise"
	EJBCA       = "Ejbca"
)

var CurrentCA = os.Getenv(common.APPVIEWX_ENV_CERTIFICATE_AUTHORITY)
