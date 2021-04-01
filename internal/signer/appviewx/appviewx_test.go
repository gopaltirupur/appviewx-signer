package appviewx

import (
	"os"
	"testing"
)

func TestMainAppViewX(t *testing.T) {
	os.Setenv("APPVIEWX_ENV_CERTIFICATE_AUTHORITY", "AppViewX")
	CurrentCA = os.Getenv("APPVIEWX_ENV_CERTIFICATE_AUTHORITY")

	os.Setenv("LOG_LEVEL", "DEBUG")
	os.Setenv("APPVIEWX_ENV_HOST", "192.168.95.157")
	os.Setenv("APPVIEWX_ENV_PORT", "31443")
	os.Setenv("APPVIEWX_ENV_IS_HTTPS", "true")
	os.Setenv("APPVIEWX_ENV_USER_NAME", "admin")
	os.Setenv("APPVIEWX_ENV_PASSWORD", "AppViewX@123")
	os.Setenv("APPVIEWX_ENV_CERTIFICATE_AUTHORITY", "AppViewX")
	os.Setenv("APPVIEWX_ENV_CA_SETTING_NAME", "AppViewX CA")
	os.Setenv("APPVIEWX_ENV_VALIDITY_IN_DAYS", "365")
	os.Setenv("APPVIEWX_ENV_CERTIFICATE_GROUP_NAME", "Default")
	os.Setenv("APPVIEWX_ENV_CATEGORY", "server")
}

func TestGetAppViewXEnvCommon(t *testing.T) {
	TestMainAppViewX(t)
	appviewxEnv, err := getAppViewXEnv()
	if appviewxEnv == nil {
		t.Errorf("Error in getting appviewx environment config  %+v", err)
		return
	}
	if appviewxEnv.AppViewXIsHTTPS != true {
		t.Errorf("Error in setting ishttps value")
	}
	if err != nil {
		t.Errorf(err.Error())
	}

	os.Setenv("APPVIEWX_ENV_IS_HTTPS", "")
	appviewxEnv, err = getAppViewXEnv()
	if err != nil {
		t.Errorf("Getting error when https is not set")
	}
	if appviewxEnv.AppViewXIsHTTPS != true {
		t.Errorf("Default isHttps Value is not set")
	}

	os.Setenv("APPVIEWX_ENV_IS_HTTPS", "truee")
	_, err = getAppViewXEnv()
	if err == nil {
		t.Errorf("https not set no error")
	}

}

func TestValidateWrongEnvVariables(t *testing.T) {
	type EnvTest struct {
		envName  string
		newValue string
	}

	testCases := []EnvTest{
		EnvTest{"APPVIEWX_ENV_VALIDITY_IN_DAYS", "65a"},
		EnvTest{"APPVIEWX_ENV_HOST", ""},
		EnvTest{"APPVIEWX_ENV_IS_HTTPS", "truee"},
	}

	for _, currentTestCase := range testCases {
		t.Run(currentTestCase.envName, func(t *testing.T) {
			TestMainAppViewX(t)
			envVariable := os.Getenv(currentTestCase.envName)
			os.Setenv(currentTestCase.envName, currentTestCase.newValue)
			_, err := getAppViewXEnv()
			if err == nil {
				t.Errorf("invalid days set and no error")
			}
			os.Setenv("APPVIEWX_ENV_VALIDITY_IN_DAYS", envVariable)
		})
	}

}

func TestInit(t *testing.T) {
	_, err := getAppViewXEnv()
	if err == nil {
		t.Errorf("No environment variable and no error received")
	}

}
