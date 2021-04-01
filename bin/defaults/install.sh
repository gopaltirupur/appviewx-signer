DOCKER_IMAGE=appviewx-istio/appviewx-signer/controller:1.0

echo "Ensure the following before proceeding with the installation"
echo "  appviewx.env is updated with required AppViewX Environment details"
echo "  Update 'external-ca-secret.yaml' with root-cert.pem ( base64 encoded content of root + intermediate certificates in same order )"
echo "  ensure availability of namespace istio-system      'kubectl create namespace istio-system'"
echo "  ensure availability of namespace signer-ca-system  'kubectl create namespace signer-ca-system'"

echo "If above files updated and Continue deleting namespace 'signer-ca-system' ( y / n ) ? "
read CHOICE

if [ "$CHOICE" = "y" ]
then

echo "creating secret"
kubectl create secret generic appviewx-credentials -n signer-ca-system --from-env-file=$(pwd)"/appviewx.env";

echo "loading signer image"
docker load < ./appviewx-signer.tar

echo "installing the signer"
cd ./config/e2e;kustomize edit set image controller=${DOCKER_IMAGE};	
cd ../..

echo $(pwd)
echo "kustomize build"
kustomize build config/e2e | kubectl apply -f -;

echo "signer installed successfully"

echo "creating the external-ca-secret"
echo $(pwd)
kubectl apply -f ./external-ca-secret.yaml

echo "installing the istio"

istioctl install --set profile=demo -f ./istio.yaml --set values.global.imagePullPolicy=IfNotPresent;

echo "installed istio successfully"

else
    echo "exiting"
fi
