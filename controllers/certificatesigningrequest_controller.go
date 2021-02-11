/*
Copyright 2020 The cert-manager authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	nativelog "log"
	"strings"

	"github.com/go-logr/logr"
	capi "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gopaltirupur/appviewx-signer/appviewx"
	capihelper "github.com/gopaltirupur/appviewx-signer/internal/api"
	"github.com/gopaltirupur/appviewx-signer/internal/kubernetes/signer"
)

// CertificateSigningRequestSigningReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestSigningReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	SignerName    string
	Signer        *signer.Signer
	EventRecorder record.EventRecorder
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *CertificateSigningRequestSigningReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificatesigningrequest", req.NamespacedName)
	var csr capi.CertificateSigningRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, fmt.Errorf("error %q getting CSR", err)
	}
	log.V(1).Info(fmt.Sprintf("csr.DeletionGracePeriodSeconds : %d", csr.DeletionGracePeriodSeconds))
	switch {
	// case csr.DeletionGracePeriodSeconds == nil || *csr.DeletionGracePeriodSeconds == 0:
	// 	log.V(1).Info(fmt.Sprintf("********************* csr.DeletionGracePeriodSeconds : %d", csr.DeletionGracePeriodSeconds))
	// 	var newGracePeriod int64 = 60
	// 	patch := client.MergeFrom(csr.DeepCopy())
	// 	csr.DeletionGracePeriodSeconds = &newGracePeriod
	// 	r.Client.Status().Patch(ctx, &csr, patch)
	// 	log.V(1).Info(fmt.Sprintf("********************* csr.DeletionGracePeriodSeconds : %d", *csr.DeletionGracePeriodSeconds))
	case !csr.DeletionTimestamp.IsZero():
		log.V(1).Info("CSR has been deleted. Ignoring.")
	case csr.Spec.SignerName == nil:
		log.V(1).Info("CSR does not have a signer name. Ignoring.")
	case *csr.Spec.SignerName != r.SignerName:
		log.V(1).Info("CSR signer name does not match. Ignoring.", "signer-name", csr.Spec.SignerName)
	case csr.Status.Certificate != nil:
		log.V(1).Info("CSR has already been signed. Ignoring.")
	case !capihelper.IsCertificateRequestApproved(&csr):
		log.V(1).Info("CSR is not approved, Ignoring.")
	default:
		log.V(1).Info("Signing")
		// /////////////////////////////////////////////////////////////////////////////
		// if csr.DeletionGracePeriodSeconds != nil {
		// 	log.V(1).Info(fmt.Sprintf("********************* v csr.DeletionGracePeriodSeconds : %d", *csr.DeletionGracePeriodSeconds))
		// } else {
		// 	log.V(1).Info(fmt.Sprintf("********************* p csr.DeletionGracePeriodSeconds : %d", csr.DeletionGracePeriodSeconds))
		// }
		// var newGracePeriod int64 = 60
		// patch := client.MergeFrom(csr.DeepCopy())
		// csr.DeletionGracePeriodSeconds = &newGracePeriod
		// r.Client.Status().Patch(ctx, &csr, patch)
		// log.V(1).Info(fmt.Sprintf("********************* csr.DeletionGracePeriodSeconds : %d", *csr.DeletionGracePeriodSeconds))
		/////////////////////////////////////////////////////////////////////////////
		x509cr, err := capihelper.ParseCSR(csr.Spec.Request)
		if err != nil {
			log.Error(err, "unable to parse csr")
			r.EventRecorder.Event(&csr, v1.EventTypeWarning, "SigningFailed", "Unable to parse the CSR request")
			return ctrl.Result{}, nil
		}
		// cert, err := r.Signer.Sign(x509cr, csr.Spec.Usages)
		cert, err := appviewx.MakeCallToAppViewXAndGetCertificate(ctx, x509cr, nil)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error auto signing csr: %v", err)
		}
		// //TODO: - TO REMOVE
		// cert := getHardCodedCertificate()
		// nativelog.Println(x509cr)
		// /////////////////////////

		//TODO: - TO CHECK
		// cert = []byte(convertSliceStringToString(getCertificateCertChain(ctx,r,string(cert))))

		nativelog.Printf("******************* certPem : " + string(cert))
		patch := client.MergeFrom(csr.DeepCopy())
		csr.Status.Certificate = cert
		if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("error patching CSR: %v", err)
		}
		r.EventRecorder.Event(&csr, v1.EventTypeNormal, "Signed", "The CSR has been signed")
	}
	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestSigningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).
		Complete(r)
}

func getHardCodedCertificate() []byte {

	return []byte(`
-----BEGIN CERTIFICATE-----
MIIDjDCCAnSgAwIBAgIUPWKB7m/fYqvlsSzA8mvLK/qmnUswDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKTkVXIFNVQiBDQTAeFw0yMTAyMDIwMjEzMjZaFw0yMTAy
MDIwMzEzMjZaMAsxCTAHBgNVBAoTADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANVZA2T6hFVfvuwvIszKPCeJvZJZ1tGpoO3xGvvEC6/fwsyN9PRGgZo+
tpB58e8KSqj3DWDVQnAQQ5XwQItTIf1VAcQz5e+dhI49BmJjTvc5fndeRpSNhD5K
QIEr4hvuLjwfrM4hR1C4df0VCgI2xXBtMDXEuHn7VXbX+Fubbjt2NL0VXNs58twI
DhQ4/zbqjFghUW276nHHcftN7AUSEwwxDSvrtWiL51jG1Ar8qnbrIon5NYwLO/G9
5VTAUAkqod53f6Aik/pQmdnDWSJt36e3UGxCb835jaJ2ebW3udh4wKDpEO7m4h5U
h3fo74dIW8GUFmjr43zeOijtZ8pKBlUCAwEAAaOB3TCB2jAMBgNVHRMBAf8EAjAA
MB8GA1UdIwQYMBaAFBIqE1aJ+S7ZJ/J8GiQv4CjOmYnkMFsGA1UdEQEB/wRRME+G
TXNwaWZmZTovL2NsdXN0ZXIubG9jYWwvbnMvaXN0aW8tc3lzdGVtL3NhL2lzdGlv
LWVncmVzc2dhdGV3YXktc2VydmljZS1hY2NvdW50MB0GA1UdJQQWMBQGCCsGAQUF
BwMCBggrBgEFBQcDATAdBgNVHQ4EFgQU4Q7rEgUySSOWVLkCw/GltNAtOnAwDgYD
VR0PAQH/BAQDAgXgMA0GCSqGSIb3DQEBCwUAA4IBAQBVE5WtrRD2Vk/xtp8YkyOR
mZ1rN92yZqIGyvGTDWSFre5VfuWxCAEbJ+nulwudKp1whu8QIvUQUOcSNcH1YqTO
A1DJl5fNDqmmlTZzLsMGNai/zup/4E/0cChRWsO9Py46II+PKZD35mvrpcgLAfuu
poU7Rp1wFmBOYcfhEhaB/1iMYpposIHBoxKMrsBnDdhJfWW4V2sdZ3Vy5/jPDo/Q
MTLGVjxdkO64+NP1RjO5SyNT423lNaZrmiQpN14iO4GdoqGPodNBkQdbjiZmRLJ4
Fy3GZbR9OqqWbT8+moKut0zaH31s7pQkOaSNJsXdswd8k0ickDfuD6occZpD7Sq/
-----END CERTIFICATE-----`)

}

func getCertificateCertChain(ctx context.Context, r *CertificateSigningRequestSigningReconciler,certificateResponse string) (output []string) {
	log := r.Log.WithValues("getCertificateCertChain")

	log.V(1).Info("Executing getCertificateCertChain")
	output = []string{}
	certificateResponseSplit := strings.Split(certificateResponse, "-----END CERTIFICATE-----")
	log.V(1).Info(fmt.Sprintf("certificateResponseSplit - length : %d", len(certificateResponseSplit)))

	// for i, currentcertificate := range certificateResponseSplit {
	// 	log.Printf("**** i = : %d : length : %d ", i, len(currentcertificate))
	// 	currentcertificate = strings.Trim(currentcertificate, " ")
	// 	currentcertificate = strings.Trim(currentcertificate, "\n")
	// 	currentcertificate = strings.Trim(currentcertificate, " ")
	// 	if len(currentcertificate) > 0 {
	// 		currentcertificate = currentcertificate + "\n-----END CERTIFICATE-----"
	// 		output = append(output, currentcertificate)
	// 	}
	// }

	length := len(certificateResponseSplit)
	// for i := length - 1; i >= 0; i-- {
	for i := 0; i < length; i++ {

		currentcertificate := strings.Trim(certificateResponseSplit[i], " ")
		currentcertificate = strings.Trim(currentcertificate, "\n")
		currentcertificate = strings.Trim(currentcertificate, " ")

		log.V(1).Info(fmt.Sprintf("i = : %d : length : %d ", i, len(currentcertificate)))
		if len(currentcertificate) > 0 {
			currentcertificate = currentcertificate + "\n-----END CERTIFICATE-----\n"
			output = append(output, currentcertificate)
		}
	}

	log.V(1).Info(fmt.Sprintf("output Length : %d", len(output)))
	return
}

func convertSliceStringToString(input []string)string{
	output := ""
	for _,currentcertificate := range input{
		output = (currentcertificate+"\n")
	}
	return output
}