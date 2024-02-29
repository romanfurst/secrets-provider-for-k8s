package conjur

import (
	"context"
	"fmt"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/common"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/k8s"
	"regexp"
	"strings"
	"sync"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/access_token/memory"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/config"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/cyberark/conjur-opentelemetry-tracer/pkg/trace"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
)

var errorRegex = regexp.MustCompile("CONJ00076E Variable .+:.+:(.+) is empty or not found")

// SecretRetriever implements a Retrieve function that is capable of
// authenticating with Conjur and retrieving multiple Conjur variables
// in bulk.
type secretRetriever struct {
	authnMap    map[string]authenticator.Authenticator
	authnConfig config.Configuration
	//authn authenticator.Authenticator
}

// RetrieveSecretsFunc defines a function type for retrieving secrets.
type RetrieveSecretsFunc func(auth string, variableIDs []string, traceContext context.Context) (map[string][]byte, error)

// RetrieverFactory defines a function type for creating a RetrieveSecretsFunc
// implementation given an authenticator config.
type RetrieverFactory func(authnConfig config.Configuration) (RetrieveSecretsFunc, error)

type AddAuthnFunc func(auth string) (authenticator.Authenticator, error)

var lock sync.Mutex

// NewSecretRetriever creates a new SecretRetriever and Authenticator
// given an authenticator config.
func NewSecretRetriever(authnConfig config.Configuration) (RetrieveSecretsFunc, error) {
	/*accessToken, err := memory.NewAccessToken()
	if err != nil {
		return nil, fmt.Errorf("%s", messages.CSPFK001E)
	}*/

	/*authn, err := authenticator.NewAuthenticatorWithAccessToken(authnConfig, accessToken)
	if err != nil {
		return nil, fmt.Errorf("%s", messages.CSPFK009E)
	}*/

	return secretRetriever{
		authnMap:    make(map[string]authenticator.Authenticator),
		authnConfig: authnConfig,
	}.Retrieve, nil
}

func (retriever secretRetriever) GetAuthenticatorForAuthn(auth string) (authenticator.Authenticator, error) {
	auth = strings.ToUpper(auth)
	log.Debug("Getting authenticator for: %s", auth)
	accessToken, err := memory.NewAccessToken()
	if err != nil {
		return nil, fmt.Errorf("%s", messages.CSPFK001E)
	}

	if retriever.authnMap[auth] == nil {

		switch conf := retriever.authnConfig.(type) {
		case *k8s.Config:
			var newConfig = k8s.Config{
				Common:            conf.Common,
				InjectCertLogPath: conf.InjectCertLogPath,
				PodName:           conf.PodName,
				PodNamespace:      conf.PodNamespace,
			}
			newConfig.Common.ClientCertPath = strings.ReplaceAll(newConfig.Common.ClientCertPath, "client.pem", auth+"-client.pem")
			newConfig.Common.Username, _ = common.NewUsername(strings.ReplaceAll(newConfig.Common.Username.FullUsername, "$(AUTHN_NAME)", auth))
			log.Debug("Conjur client username used: %s", newConfig.Common.Username)
			newConfig.Common.TokenFilePath = newConfig.Common.TokenFilePath + "-" + auth
			newConfig.Common.ClientCertRetryCountLimit = 20
			authn, err := authenticator.NewAuthenticatorWithAccessToken(&newConfig, accessToken)
			if err != nil {
				return nil, fmt.Errorf("%s", messages.CSPFK009E)
			}
			log.Debug("Token for %s is: %s", auth, authn.GetAccessToken())
			retriever.authnMap[auth] = authn
		}

	}
	return retriever.authnMap[auth], nil
}

// Retrieve implements a RetrieveSecretsFunc for a given SecretRetriever.
// Authenticates the client, and retrieves a given batch of variables from Conjur.
func (retriever secretRetriever) Retrieve(auth string, variableIDs []string, traceContext context.Context) (map[string][]byte, error) {

	lock.Lock()
	defer lock.Unlock()

	//var err error
	authn, err := retriever.GetAuthenticatorForAuthn(auth)
	if err != nil {
		log.Error("Cannot get authenticator for %s.", auth)
		return nil, err
	}

	err = authn.AuthenticateWithContext(traceContext)
	//try again because on very first authentication after POD starts is commonly failing
	if err != nil {
		err = authn.AuthenticateWithContext(traceContext)
	}
	if err != nil {
		return nil, log.RecordedError("%s for %s authenticator", messages.CSPFK010E, auth)
	}

	accessTokenData, err := authn.GetAccessToken().Read()
	if err != nil {
		return nil, log.RecordedError("%s for %s authenticator", messages.CSPFK002E, auth)
	}
	// Always delete the access token. The deletion is idempotent and never fails
	defer authn.GetAccessToken().Delete()

	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))
	_, span := tr.Start(traceContext, "Retrieve secrets")
	span.SetAttributes(attribute.Int("variable_count", len(variableIDs)))
	defer span.End()

	return retrieveConjurSecrets(auth, accessTokenData, variableIDs)
}

func retrieveConjurSecrets(auth string, accessToken []byte, variableIDs []string) (map[string][]byte, error) {
	log.Debug(messages.CSPFK003I, variableIDs)

	if len(variableIDs) == 0 {
		log.Info(messages.CSPFK016I)
		return nil, nil
	}

	conjurClient, err := NewConjurClient(auth, accessToken)
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK033E)
	}

	retrievedSecretsByFullIDs, err := conjurClient.RetrieveBatchSecretsSafe(variableIDs)
	if err != nil {

		log.Debug("Error while retrieving batch variableIDs %s : %s", variableIDs, err.Error())
		log.Debug("Client for %s auth with %s token", auth, accessToken)
		//if there is one failed variable in batch request, whole request failed no data is returned.
		//if batch failed we check the corrupted variableID, remove it from array ant try the batch request again
		matches := errorRegex.FindStringSubmatch(err.Error())
		if matches != nil {
			if errorRegex.NumSubexp() > 0 && len(variableIDs) > 1 {
				log.Debug("Removing failed %s variableID from list and try batch retrieve again", matches[1])
				for i, v := range variableIDs {
					if v == matches[1] {
						log.Warn("Variable %s has not been retrieved from Conjiur: %s", v, err.Error())
						variableIDs = append(variableIDs[:i], variableIDs[i+1:]...)
						break
					}
				}
				return retrieveConjurSecrets(auth, accessToken, variableIDs)
			}
		}
		return nil, nil
	}

	// Normalise secret IDs from batch secrets back to <variable_id>
	var retrievedSecrets = map[string][]byte{}
	for id, secret := range retrievedSecretsByFullIDs {
		retrievedSecrets[normaliseVariableId(id)] = secret
		delete(retrievedSecretsByFullIDs, id)
	}

	return retrievedSecrets, nil
}

// The variable ID can be in the format "<account>:variable:<variable_id>". This function
// just makes sure that if a variable is of the form "<account>:variable:<variable_id>"
// we normalise it to "<variable_id>", otherwise we just leave it be!
func normaliseVariableId(fullVariableId string) string {
	variableIdParts := strings.SplitN(fullVariableId, ":", 3)
	if len(variableIdParts) == 3 {
		return variableIdParts[2]
	}

	return fullVariableId
}
