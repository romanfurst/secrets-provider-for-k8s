package secrets

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	admission "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"

	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/conjur"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	secretsConfigProvider "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	k8sSecretsStorage "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/k8s_secrets_storage"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/pushtofile"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/utils"
	v1 "k8s.io/api/core/v1"
)

const (
	secretProviderGracePeriod = time.Duration(10 * time.Millisecond)
)

// CommonProviderConfig provides config that is common to all providers
type CommonProviderConfig struct {
	StoreType       string
	SanitizeEnabled bool
}

// ProviderConfig provides the configuration necessary to create a secrets
// Provider.
type ProviderConfig struct {
	CommonProviderConfig
	k8sSecretsStorage.K8sProviderConfig
	pushtofile.P2FProviderConfig
}

// ProviderFunc describes a function type responsible for providing secrets to
// an unspecified target. It returns either an error, or a flag that indicates
// whether any target secret files or Kubernetes Secrets have been updated.
type ProviderFunc func(secrets ...string) (updated bool, err error)

// DeleterFunc delete secret contetnt from provider memory when k8s secret is undeployed
type DeleterFunc func(secrets []string)

type MutateFunc func(v1.Secret) (secret v1.Secret, err error)

// RepeatableProviderFunc describes a function type that is capable of looping
// indefinitely while providing secrets to unspecified targets.
type RepeatableProviderFunc func() error

// ProviderFactory defines a function type for creating a ProviderFunc given a
// RetrieveSecretsFunc and ProviderConfig.
type ProviderFactory func(traceContent context.Context, secretsRetrieverFunc conjur.RetrieveSecretsFunc, providerConfig ProviderConfig) (ProviderFunc, DeleterFunc, []error)

type WebhookServer struct {
	server     *http.Server
	mutateFunc MutateFunc
}

// Webhook Server parameters
type ServerParams struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

// todo: pryc
type WatchSecretFunc func(provider ProviderFunc)

// NewProviderForType returns a ProviderFunc responsible for providing secrets in a given mode.
func NewProviderForType(
	traceContext context.Context,
	secretsRetrieverFunc conjur.RetrieveSecretsFunc,
	providerConfig ProviderConfig,
) (ProviderFunc, DeleterFunc, []error) {
	switch providerConfig.StoreType {
	case config.K8s:
		provider := k8sSecretsStorage.NewProvider(
			traceContext,
			secretsRetrieverFunc,
			providerConfig.CommonProviderConfig.SanitizeEnabled,
			providerConfig.K8sProviderConfig,
		)
		whsvr := initWebhookServer(provider.Mutate)
		mux := http.NewServeMux()
		mux.HandleFunc("/webhook", whsvr.serve)
		whsvr.server.Handler = mux
		go func() {
			log.Debug("Starting admission webhook server...")
			err := whsvr.server.ListenAndServeTLS("", "")
			//todo eroor handling asynchronni metody
			if err != nil {
				log.RecordedError(err.Error())
			}
		}()
		return provider.Provide, provider.Delete, nil
	case config.File:
		provider, err := pushtofile.NewProvider(
			secretsRetrieverFunc,
			providerConfig.CommonProviderConfig.SanitizeEnabled,
			providerConfig.P2FProviderConfig,
		)
		if err != nil {
			return nil, nil, err
		}
		provider.SetTraceContext(traceContext)
		return provider.Provide, nil, nil
	default:
		return nil, nil, []error{fmt.Errorf(
			messages.CSPFK054E,
			providerConfig.StoreType,
		)}
	}
}

// RetryableSecretProvider returns a new ProviderFunc, which wraps the provided ProviderFunc
// in a limitedBackOff-restricted Retry call.
func RetryableSecretProvider(
	retryInterval time.Duration,
	retryCountLimit int,
	provideSecrets ProviderFunc,
) ProviderFunc {
	limitedBackOff := utils.NewLimitedBackOff(
		retryInterval,
		retryCountLimit,
	)

	return func(secrets ...string) (bool, error) {
		var updated bool
		var retErr error

		err := backoff.Retry(func() error {
			if limitedBackOff.RetryCount() > 0 {
				log.Info(fmt.Sprintf(messages.CSPFK010I, limitedBackOff.RetryCount(), limitedBackOff.RetryLimit))
			}
			updated, retErr = provideSecrets(secrets...)
			return retErr
		}, limitedBackOff)

		if err != nil {
			log.Error(messages.CSPFK038E, err)
		}
		return updated, err
	}
}

// ProviderRefreshConfig specifies the secret refresh configuration
// for a repeatable secret provider.
type ProviderRefreshConfig struct {
	Mode                  string
	SecretRefreshInterval time.Duration
	ProviderQuit          chan struct{}
}

// RunSecretsProvider takes a retryable ProviderFunc, and runs it in one of three modes:
//   - Run once and return (for init or application container modes)
//   - Run once and sleep forever (for sidecar mode without periodic refresh)
//   - Run periodically (for sidecar mode with periodic refresh)
func RunSecretsProvider(
	config ProviderRefreshConfig,
	provideSecrets ProviderFunc,
	status StatusUpdater,
	providerConfig *secretsConfigProvider.Config,
	deleteSecrets DeleterFunc,
) error {

	var periodicQuit = make(chan struct{})
	var periodicError = make(chan error)
	var ticker *time.Ticker
	var err error

	if err = status.CopyScripts(); err != nil {
		return err
	}
	if _, err = provideSecrets(providerConfig.RequiredK8sSecrets...); err != nil && (config.Mode != "sidecar" && config.Mode != "application") {
		return err
	}
	if err == nil {
		err = status.SetSecretsProvided()
		if err != nil && (config.Mode != "sidecar" && config.Mode != "application") {
			return err
		}
	}
	switch {
	case config.Mode != "sidecar" && config.Mode != "application":
		// Run once and return if not in sidecar mode
		return nil
	case config.Mode == "application":
		log.Info("Refresh interval %s", config.SecretRefreshInterval)
		// Run periodically if in sidecar mode with periodic refresh
		ticker = time.NewTicker(config.SecretRefreshInterval)
		config := periodicConfig{
			ticker:        ticker,
			periodicQuit:  periodicQuit,
			periodicError: periodicError,
		}
		/*watcher := k8sClient.K8sSecretWatcher{
			PodNamespace: providerConfig.PodNamespace,
			AddFunc:      watchAddFunc(provideSecrets, status),
			UpdateFunc:   watchUpdateFunc(provideSecrets, status),
			DeleteFunc:   watchDeleteFunc(deleteSecrets),
		}*/
		go periodicSecretProvider(provideSecrets, config, status /*watcher.Watch,*/, providerConfig.RequiredK8sSecrets...)
	default:
		// Run once and sleep forever if in sidecar mode without
		// periodic refresh (fall through)
	}

	// Wait here for a signal to quit providing secrets or an error
	// from the periodicSecretProvider() function
	select {
	case <-config.ProviderQuit:
		break
	case err = <-periodicError:
		break
	}

	// Allow the periodicSecretProvider goroutine to gracefully shut down
	if config.SecretRefreshInterval > 0 {
		// Kill the ticker
		ticker.Stop()
		periodicQuit <- struct{}{}
		// Let the go routine exit
		time.Sleep(secretProviderGracePeriod)
	}
	return err
}

type periodicConfig struct {
	ticker        *time.Ticker
	periodicQuit  <-chan struct{}
	periodicError chan<- error
}

func periodicSecretProvider(
	provideSecrets ProviderFunc,
	config periodicConfig,
	status StatusUpdater,
	//watch k8sClient.WatchK8sSecretFunc,
	requiredK8sSecrets ...string,
) {
	if requiredK8sSecrets == nil || len(requiredK8sSecrets) < 1 {
		//watch()
	}
	for {
		select {
		case <-config.periodicQuit:
			return
		case <-config.ticker.C:
			log.Info("Run provideSecrets()")
			updated, err := provideSecrets(requiredK8sSecrets...)
			if err == nil && updated {
				log.Info("secret updated")
				err = status.SetSecretsUpdated()
			}
			/*if err != nil {
				config.periodicError <- err
			}*/
		}
	}
}

func watchAddFunc(provideSecrets ProviderFunc, status StatusUpdater) func(obj interface{}) {
	return func(obj interface{}) {
		secretObj, ok := obj.(*v1.Secret)
		if ok {
			log.Info("New k8s secret %s created", secretObj.Name)
			updated, err := provideSecrets(secretObj.Name)
			if err == nil && updated {
				log.Info("Newly created Secret %s successfully provided", secretObj.Name)
				err = status.SetSecretsUpdated()
			}
		}
	}
}

func watchUpdateFunc(provideSecrets ProviderFunc, status StatusUpdater) func(oldObj, newObj interface{}) {
	return func(oldObj, newObj interface{}) {
		if oldObj == newObj {
			return
		}
		oldSecretObj, ok := newObj.(*v1.Secret)
		if !ok {
			return
		}
		log.Info("Secret %s updated", oldSecretObj.Name)
		newSecretObj, ok := newObj.(*v1.Secret)
		if ok {
			updated, err := provideSecrets(newSecretObj.Name)
			if err == nil && updated {
				log.Info("secret updated")
				err = status.SetSecretsUpdated()
			}
		}
	}
}

func watchDeleteFunc(deleter DeleterFunc) func(obj interface{}) {
	return func(obj interface{}) {
		secretObj, ok := obj.(*v1.Secret)
		if ok {
			log.Info("Secret %s deleted", secretObj.Name)
			deleter([]string{secretObj.Name})
		}
	}
}

func initWebhookServer(mutateFunc MutateFunc) WebhookServer {

	pair, err := tls.LoadX509KeyPair("/etc/webhook/certs/cert.pem", "/etc/webhook/certs/key.pem")
	if err != nil {
		log.Error("Failed to load key pair: %v", err)
	}

	return WebhookServer{
		server: &http.Server{
			Addr:      fmt.Sprintf(":%v", 5000),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
		mutateFunc: mutateFunc,
	}
}

func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	body, err := requestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var admissionResponse *admission.AdmissionResponse
	ar := admission.AdmissionReview{}
	if _, _, err := serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer().Decode(body, nil, &ar); err != nil {
		log.Error("Can't decode body: %v", err)
		admissionResponse = &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = &admission.AdmissionResponse{
			UID:     ar.Request.UID,
			Allowed: true,
		}
	}

	//v1.Secret
	var secret v1.Secret
	//smazat z cache
	if ar.Request.Operation == admission.Delete {
		//todo handle delete event
		goto response
	}
	if err := json.Unmarshal(ar.Request.Object.Raw, &secret); err != nil {
		log.Error(err.Error())
		admissionResponse = errorAdmissionResponse(err.Error())
		goto response
	}

	_, err = whsvr.mutateFunc(secret)
	if err != nil {
		log.Error(err.Error())
		admissionResponse = errorAdmissionResponse(err.Error())
	}

response:

	admissionReview := admission.AdmissionReview{}
	admissionReview.TypeMeta.Kind = "AdmissionReview"
	admissionReview.TypeMeta.APIVersion = "admission.k8s.io/v1"
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}
	writeResponse(w, admissionReview)

}
func requestBody(r *http.Request) ([]byte, error) {
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			if len(data) == 0 {
				return nil, fmt.Errorf("empty body")
			}
			return data, nil
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("request without body")
}

func writeResponse(w http.ResponseWriter, admissionReview admission.AdmissionReview) {
	if resp, err := json.Marshal(admissionReview); err != nil {
		log.Error("Can't encode response to JSON: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	} else {
		if _, err := w.Write(resp); err != nil {
			log.Error("Can't write response: %v", err)
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		}
	}
}

func errorAdmissionResponse(msg string) *admission.AdmissionResponse {
	return &admission.AdmissionResponse{
		Result: &metav1.Status{
			Message: msg,
		},
	}

}
