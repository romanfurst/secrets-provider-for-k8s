package k8ssecretsstorage

import (
	"github.com/cyberark/secrets-provider-for-k8s/pkg/utils"
	"sync"
)

type PrevSecretsChecksums struct {
	sync.Mutex
	prevSecretsChecksums map[string]utils.Checksum
}

func (p *PrevSecretsChecksums) set(key string, sum utils.Checksum) {
	p.Lock()
	defer p.Unlock()
	if p.prevSecretsChecksums == nil {
		p.prevSecretsChecksums = make(map[string]utils.Checksum)
	}
	p.prevSecretsChecksums[key] = sum
}

func (p *PrevSecretsChecksums) get(key string) utils.Checksum {
	p.Lock()
	defer p.Unlock()
	if p.prevSecretsChecksums == nil {
		p.prevSecretsChecksums = make(map[string]utils.Checksum)
	}
	return p.prevSecretsChecksums[key]
}

func (p *PrevSecretsChecksums) delete(key string) {
	p.Lock()
	defer p.Unlock()
	if p.prevSecretsChecksums == nil {
		return
	}
	delete(p.prevSecretsChecksums, key)
}
