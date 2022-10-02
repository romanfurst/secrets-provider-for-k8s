package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"time"
)

type WatchK8sSecretFunc func()

type K8sSecretWatcher struct {
	PodNamespace string
	AddFunc      func(obj interface{})
	UpdateFunc   func(oldObj, newObj interface{})
	DeleteFunc   func(obj interface{})
}

func (w K8sSecretWatcher) Watch() {
	kubeClient, _ := configK8sClient()

	labelOptions := informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.LabelSelector = "conjur.org/application-mode=true"
	})
	factory := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Second, informers.WithNamespace(w.PodNamespace), labelOptions)
	informer := factory.Core().V1().Secrets().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.AddFunc,
		UpdateFunc: w.UpdateFunc,
		DeleteFunc: w.DeleteFunc,
	})
	factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
}
