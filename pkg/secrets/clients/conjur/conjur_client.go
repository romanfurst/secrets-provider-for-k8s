package conjur

import (
	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"

	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
)

/*
Client for communication with Conjur. In this project it is used only for
batch secrets retrieval so we expose only this method of the client.

The name ConjurClient also improves readability as Client can be ambiguous.
*/

var cliensMap map[string]*conjurapi.Client

func init() {
	cliensMap = make(map[string]*conjurapi.Client)
}

type ConjurClient interface {
	RetrieveBatchSecretsSafe([]string) (map[string][]byte, error)
}

func NewConjurClient(auth string, tokenData []byte) (ConjurClient, error) {
	log.Debug(messages.CSPFK002I)
	config, err := conjurapi.LoadConfig()
	//config.U
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK031E, err.Error())
	}

	client, err := conjurapi.NewClientFromToken(config, string(tokenData))
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK032E, err.Error())
	}

	return client, nil
}
