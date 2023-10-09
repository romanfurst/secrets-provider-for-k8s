package conjur

import (
	"context"
	"fmt"
	"regexp"
	"strings"

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

func (retriever secretRetriever) AddAuthn(auth string) (authenticator.Authenticator, error) {
	accessToken, err := memory.NewAccessToken()
	if err != nil {
		return nil, fmt.Errorf("%s", messages.CSPFK001E)
	}
	authn, err := authenticator.NewAuthenticatorWithAccessToken(retriever.authnConfig, accessToken)
	if err != nil {
		return nil, fmt.Errorf("%s", messages.CSPFK009E)
	}
	retriever.authnMap[auth] = authn
	return authn, nil
}

// Retrieve implements a RetrieveSecretsFunc for a given SecretRetriever.
// Authenticates the client, and retrieves a given batch of variables from Conjur.
func (retriever secretRetriever) Retrieve(auth string, variableIDs []string, traceContext context.Context) (map[string][]byte, error) {

	authn := retriever.authnMap[auth]
	if authn == nil {
		var err error
		authn, err = retriever.AddAuthn(auth)
		if err != nil {
			log.Error("Cannot get authenticator for %s.", auth)
			return nil, err
		}
	}

	err := authn.AuthenticateWithContext(traceContext)
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK010E)
	}

	accessTokenData, err := authn.GetAccessToken().Read()
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK002E)
	}
	// Always delete the access token. The deletion is idempotent and never fails
	defer authn.GetAccessToken().Delete()

	tr := trace.NewOtelTracer(otel.Tracer("secrets-provider"))
	_, span := tr.Start(traceContext, "Retrieve secrets")
	span.SetAttributes(attribute.Int("variable_count", len(variableIDs)))
	defer span.End()

	return retrieveConjurSecrets(accessTokenData, variableIDs)
}

func retrieveConjurSecrets(accessToken []byte, variableIDs []string) (map[string][]byte, error) {
	log.Debug(messages.CSPFK003I, variableIDs)

	if len(variableIDs) == 0 {
		log.Info(messages.CSPFK016I)
		return nil, nil
	}

	conjurClient, err := NewConjurClient(accessToken)
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK033E)
	}

	retrievedSecretsByFullIDs, err := conjurClient.RetrieveBatchSecretsSafe(variableIDs)
	if err != nil {

		log.Error(err.Error())
		//if there is one failed variable in batch request, whole request failed no data is returned.
		//if batch failed we check the corrupted variableID, remove it from array ant try the batch request again
		matches := errorRegex.FindStringSubmatch(err.Error())
		if errorRegex.NumSubexp() > 0 && len(variableIDs) > 1 {
			log.Debug("Removing failed %s variableID from list and try batch retrieve again", matches[1])
			for i, v := range variableIDs {
				if v == matches[1] {
					variableIDs = append(variableIDs[:i], variableIDs[i+1:]...)
					break
				}
			}
			return retrieveConjurSecrets(accessToken, variableIDs)
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
