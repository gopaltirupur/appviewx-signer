-   Configure the destined Certificate Authority on AppViewX.

-   Disable **ApprovalRequired**  in the  policy to support Auto enrollment.

### Configure Certificate Authority.

-   Access the AppViewX application.

-   Navigate to the Menu → CERT+

-   Navigate to  **Certificate Authority** under **Administration**

-   Click on the CA that needs to be configured

> *Example:*
>
> ![](media/image1.png){width="6.5in" height="3.0694444444444446in"}

### 

### Disable the Policy Approval Required

-   Click the menu button.

-   Select *CERT+ &gt; Groups & Policies &gt; CA Policy*.

-   On the CA Policy list view page, select the respective policy.

-   On the policy details page, **disable the Certificate Requests Need
    > Approval**.

**Note:** *Make sure the respective Certificate group is associated with
the respective policy under “Groups & Policies → Groups”*

![](media/image2.png){width="6.5in" height="3.0694444444444446in"}

-   Click Update Policy.

-   To know about certificate groups, refer to Create a Certificate Group.

AppViewX-Istio K8s Operator Configuration
=========================================

Installation Steps
------------------

-   Download appviewx-signer from 

-   Update AppViewX Instance credentials and host details on the .env file.

-   Install K8s external-signer following the steps from the Readme file.

-   Download the external-signer certificate to the kubernetes cluster from AppViewX with   the steps mentioned under category External CA  download in the Readme file.

-   Create a Kubernetes secret from the certificate downloaded from the previous step.

-   Switch to the working directory where the certificate is downloaded and unzip the file.

-   Concatenate the Root CA and the Intermediate CA to base64 format using the command

    > cat /dir/RootCA.crt /dir/IntermediateCA.crt | base64

-   Copy the base64 content and insert in an external-ca-cert.yaml file as below.

  ------------------------------------------

      apiVersion: v1
    
      kind: Secret
    
      metadata:
    
      name: external-ca-cert
    
      namespace: istio-system
    
      data:
    
      root-cert.pem: "\#base64 content here\#”

  ------------------------------------------
  ------------------------------------------

-   Create the secret with the command 

    > “kubectl create namespace  istio-system ; kubectl apply -f external-ca-cert.yaml”.

Install Istio and enable external signer\
-----------------------------------------

The below steps are executed to install Istio on the kubernetes cluster
and enable External CA integration to sign certificates for workloads.

-   Download getIstio
    > curl -sLhttps://tetrate.bintray.com/getistio/download.sh | bash

-   Fetch Istio binary 
    > getistio fetch

-   Enable external signer in istio configuration using the istio.yaml file like below.

  ---------------------------------------------------------------------------------------------------
 

     apiVersion: install.istio.io/v1alpha1
    
      kind: IstioOperator
    
      spec:
    
      components:
    
      base:
    
      k8s:
    
      overlays:
    
      \# Amend ClusterRole to add permission for istiod to approve certificate signing by custom signer
    
      - kind: ClusterRole
    
      name: istiod-istio-system
    
      patches:
    
      - path: rules\[-1\]
    
      value: |
    
      apiGroups:
    
      - certificates.k8s.io
    
      resourceNames:
    
      \# Name of k8s external Signer in this example
    
      - appviewx.com/foo       \# Signer Name to be modified
    
      resources:
    
      - signers
    
      verbs:
    
      - approve
    
      - sign
    
      pilot:
    
      k8s:
    
      env:
    
      \# Indicate to Istiod that we use an external signer
    
      - name: EXTERNAL\_CA \# Enabling External CA
    
      value: ISTIOD\_RA\_KUBERNETES\_API
    
      \# Indicate to Istiod the external k8s Signer Name
    
      - name: K8S\_SIGNER
    
      value: appviewx.com/foo      \# Signer Name to be modified
    
      overlays:
    
      - kind: Deployment
    
      name: istiod
    
      patches:
    
      - path: spec.template.spec.containers\[0\].volumeMounts\[-1\]
    
      value: |
    
      \# Mount external CA certificate into Istiod
    
      name: external-ca-cert
    
      mountPath: /etc/external-ca-cert
    
      readOnly: true
    
      - path: spec.template.spec.volumes\[-1\]
    
      value: |
    
      name: external-ca-cert
    
      secret:
    
      secretName: external-ca-cert
    
      optional: true

  ---------------------------------------------------------------------------------------------------
  ---------------------------------------------------------------------------------------------------

-   Install istio using getIstio

    > getistio istioctl install --set profile=demo -f ./istio.yaml --set
 values.global.imagePullPolicy=IfNotPresent

Test Environment Setup 
-----------------------

To validate and verify the mtls certificates issued by a custom
Certificate Authority, Users can install a sample application using the
below script and verify the custom certificate signed.\
\
*Note : The script is a separate downloadable from the AppViewX Git.*

Run the shell script with the below command

> sh
> ./004\_master\_node\_test\_and\_validate\_with\_sample\_application.sh

To verify the certificates on the AppViewX CLM. Log into the AppViewX
instance, navigate to Menu → Cert+ and verify the certificates in the
inventory.

Supported Operations
--------------------

The AppViewX-Istio Server supports two operations as shown in the below
table.

  **Operation**   **Operation Type**
  --------------- ------------------------
  Enrollment      Certificate enrollment
