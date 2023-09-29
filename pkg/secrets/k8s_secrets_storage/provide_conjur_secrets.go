package k8ssecretsstorage

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
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
	secretsGroups      map[string][]*pushtofile.SecretGroup
}

// K8sProviderConfig provides config specific to Kubernetes Secrets provider
type K8sProviderConfig struct {
	PodNamespace       string
	RequiredK8sSecrets []string
}

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
		secretsGroups:        map[string][]*pushtofile.SecretGroup{},
	}
}

// Provide implements a ProviderFunc to retrieve and push secrets to K8s secrets.
// If secrets names is passed as parameter, it override configured secrets to provide
func (p K8sProvider) Provide(secrets ...string) (bool, error) {
	// Use the global TracerProvider
	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))
	// Retrieve required K8s Secrets and parse their Data fields.
	if err := p.retrieveRequiredK8sSecrets(tr, secrets...); err != nil {
		return false, p.log.recordedError(messages.CSPFK021E)
	}
	// Retrieve Conjur secrets for all K8s Secrets.
	var updated bool
	retrievedConjurSecrets, err := p.retrieveConjurSecrets(tr)
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
		p.secretsGroups = map[string][]*pushtofile.SecretGroup{}

		return updated, p.log.recordedError(messages.CSPFK034E, err.Error())
	}

	// Update all K8s Secrets with the retrieved Conjur secrets.
	updated, err = p.updateRequiredK8sSecrets(retrievedConjurSecrets, tr)
	if err != nil {
		return updated, p.log.recordedError(messages.CSPFK023E)
	}

	if updated {
		p.log.info(messages.CSPFK009I)
	}
	return updated, nil
}

func (p K8sProvider) Mutate(secret v1.Secret) (v1.Secret, error) {
	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))

	p.retrieveRequiredK8sSecret(secret)

	spanCtx, span := tr.Start(p.traceContext, "Fetch Conjur Secrets")
	defer span.End()
	//retrievedConjurSecrets, _ := p.retrieveConjurSecrets(tr)

	var variableIDs []string
	//todo variablesIDs z conjur-map
	/*for key := range updateDests {
		variableIDs = append(variableIDs, key)
	}*/

	// ziskama variablesID pro tenhle sekret
	for _, secretGroup := range p.secretsGroups[secret.Name] {
		for _, secretSpec := range secretGroup.SecretSpecs {
			if contains(variableIDs, secretSpec.Path) {
				continue
			}
			variableIDs = append(variableIDs, secretSpec.Path)
		}
	}

	if len(variableIDs) == 0 {
		return secret, nil
	}
	//p.log.debug("List of Conjur Secrets to fetch %s", updateDests)

	// vyzvedneme variables z conjuru
	retrievedConjurSecrets, err := p.conjur.retrieveSecrets(variableIDs, spanCtx)
	if err != nil {
		log.Error(err.Error())
		return secret, nil
	}

	/*updated, err := p.updateRequiredK8sSecrets(retrievedConjurSecrets, tr)
	if err != nil {
		return updated, p.log.recordedError(messages.CSPFK023E)
	}*/

	newSecretsDataMap := p.createSecretData(retrievedConjurSecrets)
	newSecretsDataMap = p.createGroupTemplateSecretData(retrievedConjurSecrets, newSecretsDataMap)

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
		log.Debug("Create data entry in %s", secret.Name)
	}
	for itemName, secretValue := range newSecretsDataMap[secret.Name] {
		secret.Data[itemName] = secretValue
	}

	return secret, nil

}

func (p K8sProvider) removeDeletedSecrets(tr trace.Tracer) error {
	log.Info(messages.CSPFK021I)
	emptySecrets := make(map[string][]byte)
	variablesToDelete, err := p.listConjurSecretsToFetch()
	if err != nil {
		return err
	}
	for _, secret := range variablesToDelete {
		emptySecrets[secret] = []byte("")
	}
	_, err = p.updateRequiredK8sSecrets(emptySecrets, tr)
	if err != nil {
		return err
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
			k8sSecret, err := p.k8s.retrieveSecret(p.podNamespace, secret)
			if err != nil {
				p.log.logError("CSPFK020E Failed to retrieve Kubernetes Secret %s from %s namespace: %s", secret, p.podNamespace, err.Error())
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
		k8sSecrets, err = p.k8s.listSecret(p.podNamespace)
		if err != nil {
			p.log.logError("CSPFK020E Failed to retrieve labeled Kubernetes Secrets from %s namespace: ", p.podNamespace, err.Error())
			//return p.log.recordedError("CSPFK020E Failed to retrieve labeled Kubernetes Secrets from %s namespace", p.podNamespace) //TODO return error onlu for non-repeatable mode
		}
		if k8sSecrets.Items == nil {
			p.log.info("No labeled secret found in %s namespace", p.podNamespace)
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

	// Record the K8s Secret API object
	p.originalK8sSecrets[k8sSecret.Name] = &k8sSecret

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
				p.log.warn(messages.CSPFK010D, k8sSecret.Name, pushtofile.SecretGroupFileTemplatePrefix+groupName)
			}
		}
	}

	if len(secretGroups) < 1 {
		p.log.debug("No %s annotation will be used for %s secret", "conjur.org/conjur-secrets", k8sSecret.Name)
	} else {
		p.secretsGroups[k8sSecret.Name] = secretGroups
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
	p.log.debug(messages.CSPFK009D, conjurMapKey, k8sSecret.Name)
	return p.parseConjurSecretsYAML(conjurSecretsYAML, k8sSecret.Name)
}

// Parse the YAML-formatted Conjur secrets mapping that has been retrieved
// from a K8s Secret. This secrets mapping uses application secret names
// as keys and Conjur variable IDs (a.k.a. policy paths) as values.
func (p K8sProvider) parseConjurSecretsYAML(
	secretsYAML []byte,
	k8sSecretName string) error {

	conjurMap := map[string]interface{}{}
	if len(secretsYAML) > 0 {
		if err := yaml.Unmarshal(secretsYAML, &conjurMap); err != nil {
			p.log.debug(messages.CSPFK007D, k8sSecretName, config.ConjurMapKey, err.Error())
			return p.log.recordedError(messages.CSPFK028E, k8sSecretName)
		}
		if len(conjurMap) == 0 {
			p.log.debug(messages.CSPFK007D, k8sSecretName, config.ConjurMapKey, "value is empty")
			return p.log.recordedError(messages.CSPFK028E, k8sSecretName)
		}
	}
	return p.refreshUpdateDestinations(conjurMap, k8sSecretName)
}

// refreshUpdateDestinations populates the Provider's updateDestinations
// with the Conjur secret variable ID, K8s secret, secret name, and
// content-type as specified in the Conjur secrets mapping.
// The key is an application secret name, the value can be either a
// string (varID) or a map {id: varID (required), content-type: base64 (optional)}.
func (p K8sProvider) refreshUpdateDestinations(conjurMap map[string]interface{}, k8sSecretName string) error {

	for secretName, contents := range conjurMap {
		switch value := contents.(type) {
		case string: //in that case contents is varID

			dest := updateDestination{k8sSecretName, secretName, "text"}
			p.secretsState.updateDestinations[value] = appendDestination(p.secretsState.updateDestinations[value], dest)

		case map[interface{}]interface{}:
			varId, ok := value["id"].(string)
			if !ok || varId == "" {
				return p.log.recordedError(messages.CSPFK037E, secretName, k8sSecretName)
			}

			contentType, ok := value["content-type"].(string)
			if ok && contentType == "base64" {
				dest := updateDestination{k8sSecretName, secretName, "base64"}
				p.secretsState.updateDestinations[varId] = appendDestination(p.secretsState.updateDestinations[varId], dest)
				p.log.info(messages.CSPFK022I, secretName, k8sSecretName)
			} else {
				dest := updateDestination{k8sSecretName, secretName, "text"}
				p.secretsState.updateDestinations[varId] = appendDestination(p.secretsState.updateDestinations[varId], dest)
			}
		default:
			p.log.logError(messages.CSPFK028E, k8sSecretName)
		}
	}

	return nil
}

// If not already exists, append new destination to list
func appendDestination(dests []updateDestination, dest updateDestination) []updateDestination {
	for _, destt := range dests {
		if destt.k8sSecretName == dest.k8sSecretName && destt.k8sSecretName == dest.k8sSecretName {
			return dests
		}
	}
	return append(dests, dest)

}

func (p K8sProvider) listConjurSecretsToFetch() ([]string, error) {
	updateDests := p.secretsState.updateDestinations

	if (updateDests == nil || len(updateDests) == 0) && len(p.secretsGroups) < 1 {
		p.log.debug("No secrets to update")
		return make([]string, 0), nil
	}

	// Gather the set of variable IDs for all secrets that need to be
	// retrieved from Conjur.
	var variableIDs []string
	for key := range updateDests {
		variableIDs = append(variableIDs, key)
	}

	for _, secretGroups := range p.secretsGroups {
		for _, secretGroup := range secretGroups {
			for _, secretSpec := range secretGroup.SecretSpecs {
				if contains(variableIDs, secretSpec.Path) {
					continue
				}
				variableIDs = append(variableIDs, secretSpec.Path)
			}
		}
	}

	if len(variableIDs) == 0 {
		return nil, p.log.recordedError(messages.CSPFK025E)
	}
	p.log.debug("List of Conjur Secrets to fetch %s", updateDests)

	return variableIDs, nil
}

func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func (p K8sProvider) retrieveConjurSecrets(tracer trace.Tracer) (map[string][]byte, error) {
	spanCtx, span := tracer.Start(p.traceContext, "Fetch Conjur Secrets")
	defer span.End()

	variableIDs, err := p.listConjurSecretsToFetch()
	if err != nil {
		return nil, err
	}

	retrievedConjurSecrets, err := p.conjur.retrieveSecrets(variableIDs, spanCtx)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		return nil, p.log.recordedError(messages.CSPFK034E, err.Error())
	}
	return retrievedConjurSecrets, nil
}

func (p K8sProvider) updateRequiredK8sSecrets(
	conjurSecrets map[string][]byte, tracer trace.Tracer) (bool, error) {

	var updated bool

	spanCtx, span := tracer.Start(p.traceContext, "Update K8s Secrets")
	defer span.End()

	newSecretsDataMap := p.createSecretData(conjurSecrets)
	newSecretsDataMap = p.createGroupTemplateSecretData(conjurSecrets, newSecretsDataMap)

	// Update K8s Secrets with the retrieved Conjur secrets
	for k8sSecretName, secretData := range newSecretsDataMap {
		_, childSpan := tracer.Start(spanCtx, "Update K8s Secret")
		defer childSpan.End()
		b := new(bytes.Buffer)
		_, err := fmt.Fprintf(b, "%v", secretData)
		if err != nil {
			p.log.debug(messages.CSPFK005D, err.Error())
			childSpan.RecordErrorAndSetStatus(err)
			return updated, p.log.recordedError(messages.CSPFK022E)
		}

		// Calculate a sha256 checksum on the content
		checksum, _ := utils.FileChecksum(b)

		if utils.ContentHasChanged(k8sSecretName, checksum, p.prevSecretsChecksums) {
			err := p.k8s.updateSecret(
				p.podNamespace,
				k8sSecretName,
				p.originalK8sSecrets[k8sSecretName],
				secretData)
			if err != nil {
				// Error messages returned from K8s should be printed only in debug mode
				p.log.debug(messages.CSPFK005D, err.Error())
				childSpan.RecordErrorAndSetStatus(err)
				return false, p.log.recordedError(messages.CSPFK022E)
			}
			p.prevSecretsChecksums[k8sSecretName] = checksum
			updated = true
			p.log.info("CSPFK009I %s kubernetes secret content updated", k8sSecretName)
		} else {
			p.log.debug("%s in %s", messages.CSPFK020I, k8sSecretName)
			updated = false
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
func (p K8sProvider) createGroupTemplateSecretData(conjurSecrets map[string][]byte,
	newSecretsDataMap map[string]map[string][]byte) map[string]map[string][]byte {

	for k8sSecretName, secretGroups := range p.secretsGroups {
		//group for k8s secret
		secretsByGroup := map[string][]*pushtofile.Secret{}

		for _, secretGroup := range secretGroups {
			for _, secSpec := range secretGroup.SecretSpecs {
				bValue, ok := conjurSecrets[secSpec.Path]
				if !ok {
					p.log.logError("Value for '%s' group alias '%s' not fetched from Conjur", secretGroup.Name, secSpec.Alias)
					bValue = []byte{}
				}
				if ok && secSpec.ContentType == "base64" {
					decodedSecretValue := make([]byte, base64.StdEncoding.DecodedLen(len(bValue)))
					_, err := base64.StdEncoding.Decode(decodedSecretValue, bValue)
					bValue = bytes.Trim(decodedSecretValue, "\x00")
					if err != nil {
						p.log.logError("Base64 decoding failed for '%s' group : '%s' alias value", secretGroup.Name, secSpec.Alias)
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
					p.log.logError("secret alias %q not present in specified secrets for group", alias)
					return ""
				},
			}).Parse(p.originalK8sSecrets[k8sSecretName].Annotations[pushtofile.SecretGroupFileTemplatePrefix+groupName])
			if err != nil {
				p.log.logError("Unable to get temaplate for %s group in %s secret: %s", groupName, k8sSecretName, err.Error())
				continue
			}

			// Render the secret file content
			tplData := pushtofile.TemplateData{
				SecretsArray: sec,
				SecretsMap:   secretsMap,
			}
			fileContent, err := pushtofile.RenderFile(tpl, tplData)
			if err != nil {
				p.log.logError("Failed render template for %s group in %s secret: %s", groupName, k8sSecretName, err.Error())
				continue
			}

			if newSecretsDataMap[k8sSecretName] == nil {
				newSecretsDataMap[k8sSecretName] = map[string][]byte{}
			}
			//set rendered template into secret with groupName as a key
			newSecretsDataMap[k8sSecretName][groupName] = fileContent.Bytes()
		}
	}
	return newSecretsDataMap
}

// removed all 'k8sSecretName' secret references
func (p K8sProvider) deleteK8sSecret(k8sSecretName string) {

	p.log.debug("Deleting all %s secret references from cache", k8sSecretName)

	if p.secretsState.updateDestinations != nil {
		for key, dests := range p.secretsState.updateDestinations {
			if dests != nil {
				//array of non-delete destination
				remaining := make([]updateDestination, 0)
				for _, dest := range dests {
					if dest.k8sSecretName != k8sSecretName {
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

	delete(p.secretsGroups, k8sSecretName)
	delete(p.originalK8sSecrets, k8sSecretName)
	delete(p.prevSecretsChecksums, k8sSecretName)
}
