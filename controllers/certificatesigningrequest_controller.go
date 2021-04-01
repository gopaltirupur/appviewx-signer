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
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	capi "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	capihelper "github.com/gopaltirupur/appviewx-signer/internal/api"
	"github.com/gopaltirupur/appviewx-signer/internal/kubernetes/signer"
	"github.com/gopaltirupur/appviewx-signer/internal/signer/appviewx"
)

var appviewxMode string
var concurrentReconciles = 5

func init() {
	appviewxMode = os.Getenv("APPVIEWX_MODE")
	if os.Getenv("CONCURRENT_RECONCILE") != "" {
		var err error
		concurrentReconciles, err = strconv.Atoi(os.Getenv("CONCURRENT_RECONCILE"))
		if err != nil {
			log.Fatalf("Error in parsing the CONCURRENT_RECONCILE")
		}
	}
	log.Printf("CONCURRENT_RECONCILE is set to : %d\n", concurrentReconciles)
}

const (
	retryInSeconds      = 1
	EXTERNAL_REQUEST_ID = "certificates.k8s.io/externalRequestId"
)

// CertificateSigningRequestSigningReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestSigningReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	SignerName    string
	Signer        *signer.Signer
	EventRecorder record.EventRecorder
	ApViewXSigner *appviewx.ApViewXSigner
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *CertificateSigningRequestSigningReconciler) Reconcile(req ctrl.Request) (result ctrl.Result, err error) {

	ctx := context.WithValue(context.Background(), "name", req.NamespacedName)
	log := r.Log.WithValues("certificatesigningrequest", req.NamespacedName)

	defer func() {
		r := recover()
		if r != nil {
			err = errors.New("recovery error at Reconcile")
			log.V(1).Info(fmt.Sprintf("Error - recovered from a panic : %+v", r))
		}
	}()

	var csr capi.CertificateSigningRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, fmt.Errorf("error %q getting CSR", err)
	}
	log.V(1).Info(fmt.Sprintf("csr.DeletionGracePeriodSeconds : %d", csr.DeletionGracePeriodSeconds))
	switch {
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

		if appviewxMode == "SYNC" {
			log.V(1).Info("Signing - Sync")

			//TODO: make configurable
			//Don't consider csr if it is old
			// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 6).Add(time.Millisecond * 500)) {
			// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not proceeding with enrollment")
			// }

			externalRequestID := uuid.New().String()
			csrContents := string(csr.Spec.Request)
			cert, _, err := r.ApViewXSigner.MakeCallToAppViewXAndGetCertificate(ctx, &csrContents, nil, true, externalRequestID, false)
			if err != nil {
				log.V(1).Info("Error in MakeCallToAppViewXAndGetCertificate ", "err", err, "externalRequestID", externalRequestID)
				return ctrl.Result{Requeue: true}, fmt.Errorf("error in getting certificate : %v", err)
			}
			if cert == nil {
				log.V(1).Info("Error in MakeCallToAppViewXAndGetCertificate - cert byte array is nil", "externalRequestID", externalRequestID)
				return ctrl.Result{Requeue: true}, fmt.Errorf("cert byte array is nil")
			}

			//Don't go for patch if already late
			// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 9).Add(time.Millisecond * 500)) {
			// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not patching")
			// }

			patch := client.MergeFrom(csr.DeepCopy())
			csr.Status.Certificate = cert
			if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
				return ctrl.Result{}, fmt.Errorf("error patching CSR: %v", err)
			}
			log.V(1).Info("Signing - Sync - Success", "externalRequestID", externalRequestID)
			r.EventRecorder.Event(&csr, v1.EventTypeNormal, "Signed", "The CSR has been signed")

		} else if appviewxMode == "ASYNC" {

			switch {
			case csr.Annotations[EXTERNAL_REQUEST_ID] == "":
				log.V(1).Info("Signing - Async")

				//TODO: make configurable
				//Don't consider csr if it is old
				// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 6).Add(time.Millisecond * 500)) {
				// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not proceeding with enrollment")
				// }

				externalRequestID := uuid.New().String()
				csrContents := string(csr.Spec.Request)
				_, _, err = r.ApViewXSigner.MakeCallToAppViewXAndGetCertificate(ctx, &csrContents, nil, false, externalRequestID, false)
				if err != nil {
					log.V(1).Info("Error in MakeCallToAppViewXAndGetCertificate - Call 1 ", "err", err, "externalRequestID", externalRequestID)
					return ctrl.Result{Requeue: true}, fmt.Errorf("Error in async certificate")
				}

				//Don't go for patch if already late
				// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 9).Add(time.Millisecond * 500)) {
				// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not patching")
				// }

				patch := client.MergeFrom(csr.DeepCopy())

				metav1.SetMetaDataAnnotation(&csr.ObjectMeta, EXTERNAL_REQUEST_ID, externalRequestID)

				if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
					return ctrl.Result{}, fmt.Errorf("Error in patching CSR with the externalRequestID : %v", err)
				}
				log.V(1).Info("Signing - Async - Success", "externalRequestID", externalRequestID)

			default:

				externalRequestID := csr.Annotations[EXTERNAL_REQUEST_ID]
				log.V(1).Info(fmt.Sprintf("Picking up with externalResourceID %s", externalRequestID))

				//TODO: make configurable
				//Don't consider csr if it is old
				// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 8).Add(time.Millisecond * 500)) {
				// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not proceeding with enrollment")
				// }

				cert, _, err := r.ApViewXSigner.MakeCallToAppViewXAndGetCertificate(ctx, nil, nil, true, externalRequestID, true)
				if err != nil {
					log.V(1).Info("Error in MakeCallToAppViewXAndGetCertificate - Call 2", "err", err, "externalRequestID", externalRequestID)
					return ctrl.Result{Requeue: false}, fmt.Errorf("error in getting certificate : %v", err)
				}
				if len(cert) == 0 {
					log.V(1).Info(fmt.Sprintf("Certificate not generated : will retry again : %v", err), "externalRequestID", externalRequestID)
					return ctrl.Result{RequeueAfter: time.Second * retryInSeconds}, fmt.Errorf("Certificate not generated ")
				}

				//Don't go for patch if already late
				// if time.Now().After(csr.CreationTimestamp.Time.Add(time.Second * 9).Add(time.Millisecond * 500)) {
				// 	log.V(1).Info("Time out not patching the certificate", "externalRequestID", externalRequestID)
				// 	return ctrl.Result{Requeue: false}, fmt.Errorf("timeout not patching")
				// }
				log.V(1).Info("patching the certificate", "externalRequestID", externalRequestID)

				patch := client.MergeFrom(csr.DeepCopy())
				delete(csr.Annotations, EXTERNAL_REQUEST_ID)
				csr.Status.Certificate = cert
				if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
					return ctrl.Result{}, fmt.Errorf("Error in patching the CSR with the certificate : %v", err)
				}
				log.V(1).Info("Picking up with externalResourceID - Success", "externalRequestID", externalRequestID)
				r.EventRecorder.Event(&csr, v1.EventTypeNormal, "Signed", "The CSR has been signed")
			}
		} else {
			panic("APPVIEWX_MODE should be SYNC or ASYNC")
		}
	}
	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestSigningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrentReconciles}).
		Complete(r)
}
