package k8ssecretsstorage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"go.opentelemetry.io/otel"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"

	"github.com/cyberark/conjur-opentelemetry-tracer/pkg/trace"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/conjur"
	k8sClient "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/k8s"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/pushtofile"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/utils"
)

// Secrets that have been retrieved from Conjur may need to be updated in
// more than one Kubernetes Secrets, and each Kubernetes Secret may refer to
// the application secret with a different name. The updateDestination struct
// represents one destination to which a retrieved Conjur secret value needs
// to be written when Kubernetes Secrets are updated.
type updateDestination struct {
	k8sSecretName string
	secretName    string
	contentType   string
	authn         string
}

type k8sSecretsState struct {

	// Maps a Conjur variable ID (policy path) to all the updateDestination
	// targets which will need to be updated with the corresponding Conjur
	// secret value after it has been retrieved.
	updateDestinations map[string][]updateDestination
}

type k8sAccessDeps struct {
	retrieveSecret k8sClient.RetrieveK8sSecretFunc
	updateSecret   k8sClient.UpdateK8sSecretFunc
	listSecret     k8sClient.RetrieveK8sSecretListFunc
}

type conjurAccessDeps struct {
	retrieveSecrets conjur.RetrieveSecretsFunc
}

type logFunc func(message string, args ...interface{})
type logFuncWithErr func(message string, args ...interface{}) error
type logDeps struct {
	recordedError logFuncWithErr
	logError      logFunc
	warn          logFunc
	info          logFunc
	debug         logFunc
}

type k8sProviderDeps struct {
	k8s    k8sAccessDeps
	conjur conjurAccessDeps
	log    logDeps
}

type k8sSecretWrapper struct {
	fullName   string
	nammespace string
	authn      string
}

// K8sProvider is the secret provider to be used for K8s Secrets mode. It
// makes secrets available to applications by:
//   - Retrieving a list of required K8s Secrets
//   - Retrieving all Conjur secrets that are referenced (via variable ID,
//     a.k.a. policy path) by those K8s Secrets.
//   - Updating the K8s Secrets by replacing each Conjur variable ID
//     with the corresponding secret value that was retrieved from Conjur.
type K8sProvider struct {
	k8s                k8sAccessDeps
	conjur             conjurAccessDeps
	log                logDeps
	podNamespace       string
	requiredK8sSecrets []string
	secretsState       k8sSecretsState
	traceContext       context.Context
	sanitizeEnabled    bool
	//prevSecretsChecksums maps a k8s secret name to a sha256 checksum of the
	// corresponding secret content. This is used to detect changes in
	// secret content.
	prevSecretsChecksums map[string]utils.Checksum
	// Maps a K8s Secret name to the original K8s Secret API object fetched
	// from K8s.
	originalK8sSecrets map[string]*v1.Secret
	//Map where key is authn name and value is  map of SecretGroups list where key is full k8sSecret name inf 'ns/name' format and value is list of its secret groups
	secretsGroups map[string]map[string][]*pushtofile.SecretGroup
}

// K8sProviderConfig provides config specific to Kubernetes Secrets provider
type K8sProviderConfig struct {
	PodNamespace       string
	RequiredK8sSecrets []string
}

type ConjurVariable struct {
	ID    string
	authn string
}

var lock sync.Mutex
var updateSecretLock sync.Mutex
var retrieveSecretLock sync.Mutex

// NewProvider creates a new secret provider for K8s Secrets mode.
func NewProvider(
	traceContext context.Context,
	retrieveConjurSecrets conjur.RetrieveSecretsFunc,
	sanitizeEnabled bool,
	config K8sProviderConfig,
) K8sProvider {
	return newProvider(
		k8sProviderDeps{
			k8s: k8sAccessDeps{
				k8sClient.RetrieveK8sSecret,
				k8sClient.UpdateK8sSecret,
				k8sClient.RetrieveK8sSecretList,
			},
			conjur: conjurAccessDeps{
				retrieveConjurSecrets,
			},
			log: logDeps{
				log.RecordedError,
				log.Error,
				log.Warn,
				log.Info,
				log.Debug,
			},
		},
		sanitizeEnabled,
		config,
		traceContext)
}

// newProvider creates a new secret provider for K8s Secrets mode
// using dependencies provided for retrieving and updating Kubernetes
// Secrets objects.
func newProvider(
	providerDeps k8sProviderDeps,
	sanitizeEnabled bool,
	config K8sProviderConfig,
	traceContext context.Context,
) K8sProvider {
	return K8sProvider{
		k8s:                providerDeps.k8s,
		conjur:             providerDeps.conjur,
		log:                providerDeps.log,
		podNamespace:       config.PodNamespace,
		requiredK8sSecrets: config.RequiredK8sSecrets,
		sanitizeEnabled:    sanitizeEnabled,
		secretsState: k8sSecretsState{
			updateDestinations: map[string][]updateDestination{},
		},
		traceContext:         traceContext,
		prevSecretsChecksums: map[string]utils.Checksum{},
		originalK8sSecrets:   map[string]*v1.Secret{},
		secretsGroups:        map[string]map[string][]*pushtofile.SecretGroup{},
	}
}

// Provide implements a ProviderFunc to retrieve and push secrets to K8s secrets.
// If secrets names is passed as parameter, it override configured secrets to provide
func (p K8sProvider) Provide(secrets ...string) (bool, error) {
	lock.Lock()
	defer lock.Unlock()

	// Use the global TracerProvider
	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))
	// Retrieve required K8s Secrets and parse their Data fields.
	if err := p.retrieveRequiredK8sSecrets(tr, secrets...); err != nil {
		return false, p.log.recordedError(messages.CSPFK021E)
	}
	// Retrieve Conjur secrets for all K8s Secrets.
	var updated bool
	retrievedConjurSecrets, err, variableErrors := p.retrieveConjurSecrets(tr)
	if err != nil {
		// Delete K8s secrets for Conjur variables that no longer exist or the user no longer has permissions to.
		// In the future we'll delete only the secrets that are revoked, but for now we delete all secrets in
		// the group because we don't have a way to determine which secrets are revoked.
		if (strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404")) && p.sanitizeEnabled {
			updated = true
			rmErr := p.removeDeletedSecrets(tr)
			if rmErr != nil {
				p.log.recordedError(messages.CSPFK063E)
				// Don't return here - continue processing
			}
		}

		//cleanup
		p.originalK8sSecrets = map[string]*v1.Secret{}
		p.secretsGroups = map[string]map[string][]*pushtofile.SecretGroup{}

		return updated, p.log.recordedError(messages.CSPFK034E, err.Error())
	}

	// Update all K8s Secrets with the retrieved Conjur secrets.
	updated, err = p.updateRequiredK8sSecrets(retrievedConjurSecrets, variableErrors, tr)
	if err != nil {
		return updated, p.log.recordedError(messages.CSPFK023E)
	}

	if updated {
		p.log.info(messages.CSPFK009I)
	}
	return updated, nil
}

func (p K8sProvider) Mutate(secret v1.Secret) (v1.Secret, error, map[string][]byte, string) {
	lock.Lock()
	defer lock.Unlock()

	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))

	//prepare clean  data
	p.requiredK8sSecrets = []string{}
	p.secretsGroups = make(map[string]map[string][]*pushtofile.SecretGroup)
	p.secretsState = k8sSecretsState{
		updateDestinations: map[string][]updateDestination{},
	}

	err := p.retrieveRequiredK8sSecret(secret)

	if err != nil {
		return secret, err, nil, ""
	}

	spanCtx, span := tr.Start(p.traceContext, "Fetch Conjur Secrets")
	defer span.End()
	//retrievedConjurSecrets, _ := p.retrxieveConjurSecrets(tr)

	var variableIDs []string

	updateDests := p.secretsState.updateDestinations
	if updateDests != nil {
		for variableID := range updateDests {
			if contains(variableIDs, variableID) {
				continue
			}
			variableIDs = append(variableIDs, variableID)
		}
	}

	authn := secret.Labels["conjur.org/auth-id"]
	if authn == "" {
		authn = secret.Labels["applicationId"]
	}
	if authn == "" {
		return secret, errors.New(fmt.Sprintf("Secret '%s/%s' doesn't contain neither '%s' nor '%s' label.", secret.Namespace, secret.Name, "applicationId", "conjur.org/auth-id")), nil, ""
	}
	authn = strings.TrimSpace(strings.ToUpper(authn))

	//only system components can reach k8s infra safes
	//k8s infra safes are available under 'k8s-system' authenticator
	if authn == "K8S-SYSTEM" && !strings.HasSuffix(secret.Namespace, "-system") {
		log.Warn(fmt.Sprintf("Secret %s in %s namespace will not be provided", secret.Name, secret.Namespace))
		return secret, errors.New(fmt.Sprintf("Infra K8s safes with 'k8s-system' Conjur authenticator can be accessed only from *-system namespaces")), nil, ""
	}

	//full name consists of 'ns/name' pattern
	fullK8sSecretName := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	// ziskama variablesID pro tenhle sekret
	if p.secretsGroups[authn] != nil {
		secretGroups := p.secretsGroups[authn]
		if secretGroups != nil {
			for _, secretGroup := range secretGroups[fullK8sSecretName] {
				for _, secretSpec := range secretGroup.SecretSpecs {
					if contains(variableIDs, secretSpec.Path) {
						continue
					}
					variableIDs = append(variableIDs, secretSpec.Path)
				}
			}
		}
	}

	if len(variableIDs) == 0 {
		return secret, nil, nil, ""
	}
	//p.log.debug("List of Conjur Secrets to fetch %s", updateDests)

	// vyzvedneme variables z conjuru
	retrievedConjurSecrets, err, variableErrors := p.conjur.retrieveSecrets(authn, variableIDs, spanCtx)
	if err != nil {
		log.Error("Secret '%s/%s' not mutated. Error: %s", secret.Namespace, secret.Name, err.Error())
		return secret, nil, nil, err.Error()
	}

	newSecretsDataMap := p.createSecretData(retrievedConjurSecrets)
	newSecretsDataMap = p.createGroupTemplateSecretData(authn, retrievedConjurSecrets, newSecretsDataMap)

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
		log.Debug("Create data entry in %s", fullK8sSecretName)
	}
	for itemName, secretValue := range newSecretsDataMap[fullK8sSecretName] {
		secret.Data[itemName] = secretValue
	}

	b := new(bytes.Buffer)
	//sort map by key alphabetically
	keys := make([]string, 0, len(newSecretsDataMap[fullK8sSecretName]))
	sortedMapForcheckum := make(map[string][]byte)
	for k := range newSecretsDataMap[fullK8sSecretName] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sortedMapForcheckum[k] = newSecretsDataMap[fullK8sSecretName][k]
	}

	//calculate checksum from roted data map as it would be retrieved from k8s
	_, _ = fmt.Fprintf(b, "%v", sortedMapForcheckum)
	checksum, _ := utils.FileChecksum(b)
	p.prevSecretsChecksums[fullK8sSecretName] = checksum

	p.log.info("Secret %s mutated", fullK8sSecretName)

	errMsg := ""
	//join all variables error into on string
	if len(variableErrors) > 0 {
		if errMsgJson, e := json.Marshal(variableErrors); e == nil {
			errMsg = string(errMsgJson)
		}
	}

	return secret, nil, newSecretsDataMap[fullK8sSecretName], errMsg

}

func (p K8sProvider) removeDeletedSecrets(tr trace.Tracer) error {
	log.Info(messages.CSPFK021I)
	emptySecrets := make(map[string]map[string][]byte)
	variablesToDelete, err := p.listConjurSecretsToFetch()
	if err != nil {
		return err
	}

	for auth, variablesToDelete := range variablesToDelete {
		emptySecrets[auth] = make(map[string][]byte)
		for _, secret := range variablesToDelete {
			emptySecrets[auth][secret] = []byte("")
		}
		_, err = p.updateRequiredK8sSecrets(emptySecrets, make(map[string]map[string]string), tr)
		if err != nil {
			continue
			//return err
		}
	}

	return nil
}
func (p K8sProvider) Delete(secrets []string) {
	emptySecrets := make(map[string][]byte)
	for _, secret := range secrets {
		delete(p.prevSecretsChecksums, secret)
		emptySecrets[secret] = []byte("")
	}
	for _, secret := range secrets {
		p.deleteK8sSecret(secret)
	}
}

// retrieveRequiredK8sSecrets retrieves all K8s Secrets that need to be
// managed/updated by the Secrets Provider.
func (p K8sProvider) retrieveRequiredK8sSecrets(tracer trace.Tracer, secrets ...string) error {
	spanCtx, span := tracer.Start(p.traceContext, "Gather required K8s Secrets")
	defer span.End()

	var err error
	k8sSecrets := &v1.SecretList{}
	if secrets != nil && len(secrets) > 0 {
		p.log.debug("Only specified k8s secrets will be retrieved: %s", secrets)
		for _, secret := range secrets {
			secretFullNameParsed := strings.Split(secret, "/")
			k8sSecret, err := p.k8s.retrieveSecret(secretFullNameParsed[0], secretFullNameParsed[1])
			if err != nil {
				p.log.logError("CSPFK020E Failed to retrieve Kubernetes Secret %s from %s namespace: %s", secretFullNameParsed[1], secretFullNameParsed[0], err.Error())
				//return p.log.recordedError("CSPFK020E Failed to retrieve Kubernetes Secret %s from %s namespace: %s", secret, p.podNamespace, err.Error()) //TODO return error onlu for non-repeatable mode
			} else {
				if k8sSecrets.Items == nil {
					k8sSecrets.Items = []v1.Secret{}
				}
				k8sSecrets.Items = append(k8sSecrets.Items, *k8sSecret)
			}
		}
	} else {
		p.log.debug("All labeled secrets will be retrieved")
		k8sSecrets, err = p.k8s.listSecret()
		if err != nil {
			p.log.logError("CSPFK020E Failed to retrieve labeled Kubernetes Secrets: %s ", err.Error())
			//return p.log.recordedError("CSPFK020E Failed to retrieve labeled Kubernetes Secrets from %s namespace", p.podNamespace) //TODO return error onlu for non-repeatable mode
		}
		if k8sSecrets.Items == nil {
			p.log.info("No labeled secret found")
		}
	}

	if k8sSecrets.Items != nil {
		for _, k8sSecret := range k8sSecrets.Items {
			_, childSpan := tracer.Start(spanCtx, "Process K8s Secret")
			defer childSpan.End()
			if err := p.retrieveRequiredK8sSecret(k8sSecret); err != nil {
				childSpan.RecordErrorAndSetStatus(err)
				span.RecordErrorAndSetStatus(err)
				return err
			}
		}
	} else {
		p.log.info("No secrets to retrieve")
	}
	return nil
}

// retrieveRequiredK8sSecret retrieves an individual K8s Secrets that needs
// to be managed/updated by the Secrets Provider.
func (p K8sProvider) retrieveRequiredK8sSecret(k8sSecret v1.Secret) error {

	authn := k8sSecret.Labels["conjur.org/auth-id"]
	if authn == "" {
		authn = k8sSecret.Labels["applicationId"]
	}
	if authn == "" {
		p.log.logError("Secret '%s/%s' doesn't contain neither '%s' nor '%s' label.", k8sSecret.Namespace, k8sSecret.Name, "applicationId", "conjur.org/auth-id")
		return nil
	}
	authn = strings.TrimSpace(strings.ToUpper(authn))

	//only system components can reach k8s infra safes
	//k8s infra safes are available under 'k8s-system' authenticator
	if authn == "K8S-SYSTEM" && !strings.HasSuffix(k8sSecret.Namespace, "-system") {
		log.Warn(fmt.Sprintf("Secret %s in %s namespace will not be provided. Infra K8s safes with 'k8s-system' Conjur authenticator can be accesed only from *-system namespaces", k8sSecret.Name, k8sSecret.Namespace))
		p.log.logError("Infra K8s safes with 'k8s-system' Conjur authenticator can be accessed only from *-system namespaces")
		return nil
	}

	k8sSecretWrapper := k8sSecretWrapper{
		fullName:   fmt.Sprintf("%s/%s", k8sSecret.Namespace, k8sSecret.Name),
		nammespace: k8sSecret.Namespace,
		authn:      authn,
	}

	// Record the K8s Secret API object
	p.originalK8sSecrets[k8sSecretWrapper.fullName] = &k8sSecret

	// Read the value of the "conjur-map" entry in the K8s Secret's Data
	// field, if it exists. If the entry does not exist or has a null
	// value, it will be logged.
	conjurMapKey := config.ConjurMapKey
	conjurSecretsYAML, conjurMapExists := k8sSecret.Data[conjurMapKey]
	if !conjurMapExists {
		p.log.debug(messages.CSPFK008D, k8sSecret.Name, conjurMapKey)
	}
	if len(conjurSecretsYAML) == 0 {
		p.log.debug(messages.CSPFK006D, k8sSecret.Name, conjurMapKey)
	}

	var secretGroups []*pushtofile.SecretGroup
	//find conjur-secrets annotations
	for annotationName, annotationValue := range k8sSecret.Annotations {
		if strings.HasPrefix(annotationName, pushtofile.SecretGroupPrefix) {
			groupName := strings.TrimPrefix(annotationName, pushtofile.SecretGroupPrefix)
			//for actual secret group found template
			if _, tplExists := k8sSecret.Annotations[pushtofile.SecretGroupFileTemplatePrefix+groupName]; tplExists {
				secretSpecs, err := pushtofile.NewSecretSpecs([]byte(annotationValue))
				if err != nil {
					err = fmt.Errorf(`unable to create secret specs from annotation "%s": %s`, pushtofile.SecretGroupFileTemplatePrefix+groupName, err)
					return err
				}
				secretGroup := &pushtofile.SecretGroup{
					Name:        groupName,
					SecretSpecs: secretSpecs,
				}
				secretGroups = append(secretGroups, secretGroup)
			} else {
				p.log.warn(messages.CSPFK010D, fmt.Sprintf("%s/%s", k8sSecret.Namespace, k8sSecret.Name), pushtofile.SecretGroupFileTemplatePrefix+groupName)
			}
		}
	}

	if len(secretGroups) < 1 {
		p.log.debug("No %s annotation will be used for %s secret", "conjur.org/conjur-secrets", k8sSecret.Name)
	} else {

		if p.secretsGroups[k8sSecretWrapper.authn] == nil {
			p.secretsGroups[k8sSecretWrapper.authn] = make(map[string][]*pushtofile.SecretGroup)
		}

		p.secretsGroups[k8sSecretWrapper.authn][k8sSecretWrapper.fullName] = secretGroups
	}

	// At least ne of "conjur-map" field or "conjur.org/conjur-secrets.*" annotation  must be defined.
	// If it is not, error is returned
	if (!conjurMapExists || len(conjurSecretsYAML) == 0) && (len(secretGroups) < 1) {
		p.log.logError("At least on of %s data entry or %s annotations must defined", conjurMapKey, "conjur.org/conjur-secrets.* & conjur.org/secret-file-template.*")
		return nil
		//return p.log.recordedError("At least on of %s or %s must defined", conjurMapKey+" data entry", conjurVariablesAnnotationName+" annotation")
	}

	// Parse the YAML-formatted Conjur secrets mapping that has been
	// retrieved from this K8s Secret.
	p.log.debug(messages.CSPFK009D, conjurMapKey, fmt.Sprintf("%s/%s", k8sSecret.Namespace, k8sSecret.Name))

	return p.parseConjurSecretsYAML(conjurSecretsYAML, k8sSecretWrapper)
}

// Parse the YAML-formatted Conjur secrets mapping that has been retrieved
// from a K8s Secret. This secrets mapping uses application secret 'ns/name' string
// as keys and Conjur variable IDs (a.k.a. policy paths) as values.
func (p K8sProvider) parseConjurSecretsYAML(
	secretsYAML []byte,
	k8sSecret k8sSecretWrapper) error {

	conjurMap := map[string]interface{}{}
	if len(secretsYAML) > 0 {
		if err := yaml.Unmarshal(secretsYAML, &conjurMap); err != nil {
			p.log.debug(messages.CSPFK007D, k8sSecret.fullName, config.ConjurMapKey, err.Error())
			return p.log.recordedError(messages.CSPFK028E, k8sSecret.fullName)
		}
		if len(conjurMap) == 0 {
			p.log.debug(messages.CSPFK007D, k8sSecret.fullName, config.ConjurMapKey, "value is empty")
			return p.log.recordedError(messages.CSPFK028E, k8sSecret.fullName)
		}
	}
	return p.refreshUpdateDestinations(conjurMap, k8sSecret)
}

// refreshUpdateDestinations populates the Provider's updateDestinations
// with the Conjur secret variable ID, K8s secret, secret name, and
// content-type as specified in the Conjur secrets mapping.
// The key is an application secret namespace/name, the value can be either a
// string (varID) or a map {id: varID (required), content-type: base64 (optional)}.
func (p K8sProvider) refreshUpdateDestinations(conjurMap map[string]interface{}, k8sSecret k8sSecretWrapper) error {

	for secretName, contents := range conjurMap {
		switch value := contents.(type) {
		case string: //in that case contents is varID

			dest := updateDestination{k8sSecret.fullName, secretName, "text", k8sSecret.authn}
			p.secretsState.updateDestinations[value] = appendDestination(p.secretsState.updateDestinations[value], dest)

		case map[interface{}]interface{}:
			varId, ok := value["id"].(string)
			if !ok || varId == "" {
				return p.log.recordedError(messages.CSPFK037E, secretName, k8sSecret.fullName)
			}

			contentType, ok := value["content-type"].(string)
			if ok && contentType == "base64" {
				dest := updateDestination{k8sSecret.fullName, secretName, "base64", k8sSecret.authn}
				p.secretsState.updateDestinations[varId] = appendDestination(p.secretsState.updateDestinations[varId], dest)
				p.log.info(messages.CSPFK022I, secretName, k8sSecret.fullName)
			} else {
				dest := updateDestination{k8sSecret.fullName, secretName, "text", k8sSecret.authn}
				p.secretsState.updateDestinations[varId] = appendDestination(p.secretsState.updateDestinations[varId], dest)
			}
		default:
			p.log.logError(messages.CSPFK028E, k8sSecret.fullName)
		}
	}

	return nil
}

// If not already exists, append new destination to list
func appendDestination(dests []updateDestination, dest updateDestination) []updateDestination {
	for _, destt := range dests {
		if destt.k8sSecretName == dest.k8sSecretName && destt.secretName == dest.secretName {
			return dests
		}
	}
	return append(dests, dest)

}

// listConjurSecretsToFetch returns all Conjur secrets to be fetch mapped by authn name
// result map contains auth name as a key and array of Canjur vairableIDs as value
func (p K8sProvider) listConjurSecretsToFetch() (map[string][]string, error) {
	updateDests := p.secretsState.updateDestinations

	if (updateDests == nil || len(updateDests) == 0) && len(p.secretsGroups) < 1 {
		p.log.debug("No secrets to update")
		return make(map[string][]string, 0), nil
	}

	// Gather the set of variable IDs for all secrets that need to be
	// retrieved from Conjur.
	var variableIDsAuthnMap = make(map[string][]string)
	for varID := range updateDests {
		for _, dest := range updateDests[varID] {
			if variableIDsAuthnMap[dest.authn] == nil {
				variableIDsAuthnMap[dest.authn] = make([]string, 0)
			}
			if contains(variableIDsAuthnMap[dest.authn], varID) {
				continue
			}
			variableIDsAuthnMap[dest.authn] = append(variableIDsAuthnMap[dest.authn], varID)
		}

	}

	//for given authn ge secrets group and its secrets
	for authn, groups := range p.secretsGroups {
		if variableIDsAuthnMap[authn] == nil {
			variableIDsAuthnMap[authn] = make([]string, 0)
		}
		for _, secretGroups := range groups {
			for _, secretGroup := range secretGroups {
				for _, secretSpec := range secretGroup.SecretSpecs {
					if contains(variableIDsAuthnMap[authn], secretSpec.Path) {
						continue
					}
					variableIDsAuthnMap[authn] = append(variableIDsAuthnMap[authn], secretSpec.Path)
				}
			}
		}
	}

	if len(variableIDsAuthnMap) == 0 {
		return nil, p.log.recordedError(messages.CSPFK025E)
	}
	p.log.debug("List of Conjur Secrets to fetch %s", updateDests)

	return variableIDsAuthnMap, nil
}

func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func (p K8sProvider) retrieveConjurSecrets(tracer trace.Tracer) (map[string]map[string][]byte, error, map[string]map[string]string) {

	retrieveSecretLock.Lock()
	defer retrieveSecretLock.Unlock()

	spanCtx, span := tracer.Start(p.traceContext, "Fetch Conjur Secrets")
	defer span.End()

	variableIDsAuthnMap, err := p.listConjurSecretsToFetch()
	if err != nil {
		return nil, err, nil
	}

	result := make(map[string]map[string][]byte)
	variableErrors := make(map[string]map[string]string)
	for authn, variableIDs := range variableIDsAuthnMap {
		retrievedConjurSecrets, err, retrievedErrors := p.conjur.retrieveSecrets(authn, variableIDs, spanCtx)
		variableErrors[authn] = retrievedErrors
		if err != nil {
			//span.RecordErrorAndSetStatus(err)
			//return nil, p.log.recordedError(messages.CSPFK034E, err.Error())
			p.log.logError("CSPFK034E Failed to retrieve DAP/Conjur with '%s' authenticator. Reason: %s", authn, err.Error())
			result[authn] = make(map[string][]byte)
		} else {
			result[authn] = retrievedConjurSecrets
		}
	}
	return result, nil, variableErrors
}

func (p K8sProvider) updateRequiredK8sSecrets(
	conjurSecretsFotAuthnMap map[string]map[string][]byte, variableErrorsAuthnMap map[string]map[string]string, tracer trace.Tracer) (bool, error) {

	updateSecretLock.Lock()
	defer updateSecretLock.Unlock()

	var updated = false

	spanCtx, span := tracer.Start(p.traceContext, "Update K8s Secrets")
	defer span.End()

	for authn, conjurSecrets := range conjurSecretsFotAuthnMap {

		newSecretsDataMap := p.createSecretData(conjurSecrets)
		newSecretsDataMap = p.createGroupTemplateSecretData(authn, conjurSecrets, newSecretsDataMap)

		var variableErrorsMap = make(map[string]map[string]string)

		if len(variableErrorsAuthnMap) > 0 && len(variableErrorsAuthnMap[authn]) > 0 {

			for variableID, errorMsg := range variableErrorsAuthnMap[authn] {
				dests := p.secretsState.updateDestinations[variableID]
				if dests != nil {
					for _, dest := range dests {
						if len(variableErrorsMap[dest.k8sSecretName]) == 0 {
							variableErrorsMap[dest.k8sSecretName] = make(map[string]string)
						}
						variableErrorsMap[dest.k8sSecretName][variableID] = errorMsg
					}
				}
			}

		}

		// Update K8s Secrets with the retrieved Conjur secrets
		// k8sSecretFullName is  'ns/name' string format
		for k8sSecretFullName, secretData := range newSecretsDataMap {
			_, childSpan := tracer.Start(spanCtx, "Update K8s Secret")
			defer childSpan.End()
			b := new(bytes.Buffer)
			_, err := fmt.Fprintf(b, "%v", secretData)
			if err != nil {
				p.log.debug(messages.CSPFK005D, err.Error())
				childSpan.RecordErrorAndSetStatus(err)
				p.log.logError(messages.CSPFK022E)
				continue
				//return updated, p.log.recordedError(messages.CSPFK022E)
			}

			// Calculate a sha256 checksum on the content
			checksum, _ := utils.FileChecksum(b)

			if utils.ContentHasChanged(k8sSecretFullName, checksum, p.prevSecretsChecksums) {
				secretFullNameParsed := strings.Split(k8sSecretFullName, "/")
				err := p.k8s.updateSecret(
					secretFullNameParsed[0],
					secretFullNameParsed[1],
					p.originalK8sSecrets[k8sSecretFullName],
					secretData,
					variableErrorsMap[k8sSecretFullName])
				if err != nil {
					// Error messages returned from K8s should be printed only in debug mode
					p.log.debug(messages.CSPFK005D, err.Error())
					childSpan.RecordErrorAndSetStatus(err)
					p.log.logError(messages.CSPFK022E)
					continue
					//return false, p.log.recordedError(messages.CSPFK022E)
				}
				p.prevSecretsChecksums[k8sSecretFullName] = checksum
				updated = true
				p.log.info("CSPFK009I %s kubernetes secret content updated", k8sSecretFullName)
			} else {
				p.log.debug("%s in %s", messages.CSPFK020I, k8sSecretFullName)
				updated = false
			}
		}
	}
	return updated, nil
}

// createSecretData creates a map of entries to be added to the 'Data' fields
// of each K8s Secret. Each entry will map an application secret name to a
// value retrieved from Conjur. If a secret has a 'base64' content type, the
// resulting secret value will be decoded.
func (p K8sProvider) createSecretData(conjurSecrets map[string][]byte) map[string]map[string][]byte {
	newSecretsDataMap := map[string]map[string][]byte{}
	for variableID, secretValue := range conjurSecrets {
		dests := p.secretsState.updateDestinations[variableID]

		if dests != nil {
			for _, dest := range dests {
				k8sSecretName := dest.k8sSecretName
				secretVariable := dest.secretName
				// If there are no data entries for this K8s Secret yet, initialize
				// its map of data entries.
				if newSecretsDataMap[k8sSecretName] == nil {
					newSecretsDataMap[k8sSecretName] = map[string][]byte{}
				}

				// Check if the secret value should be decoded in this K8s Secret
				if dest.contentType == "base64" {
					decodedSecretValue := make([]byte, base64.StdEncoding.DecodedLen(len(secretValue)))
					_, err := base64.StdEncoding.Decode(decodedSecretValue, secretValue)
					decodedSecretValue = bytes.Trim(decodedSecretValue, "\x00")
					if err != nil {
						// Log the error as a warning but still provide the original secret value
						p.log.warn(messages.CSPFK064E, secretVariable, dest.contentType, err.Error())
						newSecretsDataMap[k8sSecretName][secretVariable] = secretValue
					} else {
						newSecretsDataMap[k8sSecretName][secretVariable] = decodedSecretValue
					}
					// Null out the secret values
					decodedSecretValue = []byte{}
				} else {
					newSecretsDataMap[k8sSecretName][secretVariable] = secretValue
				}
			}
		}
		// Null out the secret values
		//conjurSecrets[variableID] = []byte{}
		//secretValue = []byte{}
	}

	return newSecretsDataMap
}

// createGroupTemplateSecretData creates a map of entries to be added to the 'Data' fields
// of each K8s Secret. Data fields are created from group secret variables and rendered corresponding group template filled with secret values retrieved from Conjur,
// If a secret has a 'base64' content type, the resulting secret value will be decoded.
func (p K8sProvider) createGroupTemplateSecretData(authn string, conjurSecrets map[string][]byte,
	newSecretsDataMap map[string]map[string][]byte) map[string]map[string][]byte {

	if conjurSecrets == nil || len(conjurSecrets) < 1 {
		p.log.warn("There isn't any values fetched from Conjur with '%s' authenticator.", authn)

	}

	if secretGroupForAuthn := p.secretsGroups[authn]; secretGroupForAuthn != nil {
		// tke k8sSecretFullName is in "ns/name" format
		for k8sSecretFullName, secretGroups := range secretGroupForAuthn {
			//group for the k8s secret
			secretsByGroup := map[string][]*pushtofile.Secret{}

			//hold names of values in this k8sSecretFullName that were not successfully updated
			secretValuesNotProvider := ""

			for _, secretGroup := range secretGroups {
				for _, secSpec := range secretGroup.SecretSpecs {
					bValue, ok := conjurSecrets[secSpec.Path]
					if !ok {
						secretValuesNotProvider = secretValuesNotProvider + fmt.Sprintf("[group: '%s' variable: '%s' path: '%s']  ", secretGroup.Name, secSpec.Alias, secSpec.Path)
						bValue = []byte{}
					}
					if ok && secSpec.ContentType == "base64" {
						decodedSecretValue := make([]byte, base64.StdEncoding.DecodedLen(len(bValue)))
						_, err := base64.StdEncoding.Decode(decodedSecretValue, bValue)
						bValue = bytes.Trim(decodedSecretValue, "\x00")
						if err != nil {
							p.log.logError("Base64 decoding failed for '%s' alias in '%s' group value", secSpec.Alias, secretGroup.Name)
						}
					}
					//add retrieved value for group
					secretsByGroup[secretGroup.Name] = append(
						secretsByGroup[secretGroup.Name],
						&pushtofile.Secret{
							Alias: secSpec.Alias,
							Value: string(bValue),
						})
				}
				if secretValuesNotProvider != "" {
					p.log.warn("In '%s' secret following template variables was not provided because its values was not fetched from Conjur: %s", k8sSecretFullName, secretValuesNotProvider)
				}
			}

			//render every group
			for groupName, sec := range secretsByGroup {

				secretsMap := map[string]*pushtofile.Secret{}
				for _, s := range sec {
					secretsMap[s.Alias] = s
				}

				tpl, err := template.New(groupName).Funcs(template.FuncMap{
					// secret is a custom utility function for streamlined access to secret values.
					// It panics for secrets aliases not specified on the group.
					"secret": func(alias string) string {
						v, ok := secretsMap[alias]
						if ok {
							return v.Value
						}
						p.log.warn("secret alias %q not present in specified secrets for group", alias)
						return ""
					},
					"b64enc": func(value string) string {
						return base64.StdEncoding.EncodeToString([]byte(value))
					},
					"b64dec": func(encValue string) string {
						decValue, err := base64.StdEncoding.DecodeString(encValue)
						if err == nil {
							return string(decValue)
						}
						// Panic in a template function is captured as an error
						// when the template is executed.
						panic("value could not be base64 decoded")
					},
					"concat": func(value ...string) string {
						result := ""
						if len(value) > 0 {
							for i := range value {
								result += value[i]
							}
							return result
						}
						return result
					},
				}).Parse(p.originalK8sSecrets[k8sSecretFullName].Annotations[pushtofile.SecretGroupFileTemplatePrefix+groupName])
				if err != nil {
					p.log.logError("Unable to get temaplate for %s group in %s secret: %s", groupName, k8sSecretFullName, err.Error())
					continue
				}

				// Render the secret file content
				tplData := pushtofile.TemplateData{
					SecretsArray: sec,
					SecretsMap:   secretsMap,
				}
				fileContent, err := pushtofile.RenderFile(tpl, tplData)
				if err != nil {
					p.log.logError("Failed render template for %s group in %s secret: %s", groupName, k8sSecretFullName, err.Error())
					continue
				}

				if newSecretsDataMap[k8sSecretFullName] == nil {
					newSecretsDataMap[k8sSecretFullName] = map[string][]byte{}
				}
				//set rendered template into secret with groupName as a key
				newSecretsDataMap[k8sSecretFullName][groupName] = fileContent.Bytes()
			}
		}
	}
	p.log.debug("New secret's data map: %s", newSecretsDataMap)
	return newSecretsDataMap
}

// removed all 'k8sFULLSecretName' secret references
// the k8sFULLSecretName is in "ns/name" format
func (p K8sProvider) deleteK8sSecret(k8sFullSecretName string) {

	p.log.debug("Deleting all %s secret references from cache", k8sFullSecretName)

	if p.secretsState.updateDestinations != nil {
		for key, dests := range p.secretsState.updateDestinations {
			if dests != nil {
				//array of non-delete destination
				remaining := make([]updateDestination, 0)
				for _, dest := range dests {
					if dest.k8sSecretName != k8sFullSecretName {
						remaining = appendDestination(remaining, dest)
					} else {
						p.log.debug("Deleting %s updateDestinations", dest)
					}
				}
				if len(remaining) > 0 {
					//update destinations array
					p.secretsState.updateDestinations[key] = remaining
				} else {
					//if non-delete is empty, delete whole record from map
					delete(p.secretsState.updateDestinations, key)
				}
			}
		}
	}

	for _, secretGroupsForAuthn := range p.secretsGroups {
		for currentK8sFullSecretName, _ := range secretGroupsForAuthn {
			if currentK8sFullSecretName == k8sFullSecretName {
				delete(secretGroupsForAuthn, k8sFullSecretName)
				break
			}
		}
	}

	delete(p.originalK8sSecrets, k8sFullSecretName)
	delete(p.prevSecretsChecksums, k8sFullSecretName)
}

func (p K8sProvider) CheckContentHasChanged(groupName string, newChecksum utils.Checksum) bool {
	return utils.ContentHasChanged(groupName, newChecksum, p.prevSecretsChecksums)

}
