module github.com/gopaltirupur/appviewx-signer

go 1.15

// Pin k8s.io/* dependencies to kubernetes-1.17.0 to match controller-runtime v0.5.0
replace (
	k8s.io/api => k8s.io/api v0.18.0-beta.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.3
	k8s.io/apiserver => k8s.io/apiserver v0.18.0-beta.2
	k8s.io/client-go => k8s.io/client-go v0.17.3
)

require (
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/go-logr/logr v0.1.0
	github.com/google/uuid v1.1.1
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/zap v1.10.0
	k8s.io/api v0.18.0-beta.2
	k8s.io/apimachinery v0.18.0-beta.2
	k8s.io/apiserver v0.17.2
	k8s.io/client-go v0.18.0-beta.2
	sigs.k8s.io/controller-runtime v0.5.0
)
