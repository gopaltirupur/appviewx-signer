package util

import "os"

func GetHostNameAndPortFromEnvironment() (hostName, port string) {
	hostName = os.Getenv("SVC_HOST_NAME")
	if len(hostName) <= 0 {
		hostName = "0.0.0.0"
	}

	port = os.Getenv("SVC_PORT")
	if len(port) <= 0 {
		port = "50051"
	}
	return hostName, port
}
