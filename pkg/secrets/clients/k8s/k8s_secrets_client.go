package k8s

import (
	"context"
	"encoding/json"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/annotations"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"strings"

	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
)

type RetrieveK8sSecretFunc func(namespace string, secretName string) (*v1.Secret, error)
type UpdateK8sSecretFunc func(namespace string, secretName string, originalK8sSecret *v1.Secret, stringDataEntriesMap map[string][]byte, variablesErrorsMap ...map[string]string) error
type RetrieveK8sSecretListFunc func() (*v1.SecretList, error)

var kubeClient *kubernetes.Clientset

func init() {
	kubeClient, _ = configK8sClient()
}

func RetrieveK8sSecret(namespace string, secretName string) (*v1.Secret, error) {
	// get K8s client object
	//kubeClient, _ := configK8sClient()
	log.Info(messages.CSPFK005I, secretName, namespace)
	k8sSecret, err := kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		// Error messages returned from K8s should be printed only in debug mode
		log.Debug(messages.CSPFK004D, err.Error())
		return nil, log.RecordedError(messages.CSPFK020E)
	}

	return k8sSecret, nil
}

func UpdateK8sSecret(namespace string, secretName string, originalK8sSecret *v1.Secret, stringDataEntriesMap map[string][]byte, variablesErrorsMap ...map[string]string) error {
	return updateK8sSecretWithRetry(true, namespace, secretName, originalK8sSecret, stringDataEntriesMap, variablesErrorsMap...)
}

func updateK8sSecretWithRetry(shouldRetry bool, namespace string, secretName string, originalK8sSecret *v1.Secret, stringDataEntriesMap map[string][]byte, variablesErrorsMap ...map[string]string) error {

	if originalK8sSecret.Data == nil {
		originalK8sSecret.Data = map[string][]byte{}
		log.Debug("Create data entry in %s", secretName)
	}

	for secretItemName, secretValue := range stringDataEntriesMap {
		originalK8sSecret.Data[secretItemName] = secretValue
	}

	//add magic annotation to let mutation webhook know it should ignore this action
	if originalK8sSecret.Annotations == nil {
		originalK8sSecret.Annotations = make(map[string]string)
	}
	originalK8sSecret.Annotations["conjur.org/just-provided"] = "true"
	originalK8sSecret.SetAnnotations(originalK8sSecret.Annotations)
	//delete old errors
	delete(originalK8sSecret.Annotations, annotations.LastProvidedErrors)
	originalK8sSecret.SetAnnotations(originalK8sSecret.Annotations)

	if len(variablesErrorsMap) > 0 && len(variablesErrorsMap[0]) > 0 {
		jsonErrorMsq, err := json.Marshal(&variablesErrorsMap)
		if err == nil {
			//add latest errors
			originalK8sSecret.Annotations[annotations.LastProvidedErrors] = string(jsonErrorMsq)
			originalK8sSecret.SetAnnotations(originalK8sSecret.Annotations)
		}

	}

	log.Debug(messages.CSPFK006I, secretName, namespace)
	_, err := kubeClient.CoreV1().Secrets(namespace).Update(context.Background(), originalK8sSecret, metav1.UpdateOptions{})
	// Clear secret from memory
	stringDataEntriesMap = nil
	originalK8sSecret = nil
	if err != nil {
		// Error messages returned from K8s should be printed only in debug mode
		log.Debug(messages.CSPFK005D, err.Error())
		//race condition  between period provisioning and   webhook provisioning might have occurred. Give it another chance
		if shouldRetry && strings.Contains(err.Error(), "please apply your changes to the latest version and try again") {
			originalK8sSecret, err = kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
			if err != nil {
				log.Debug("Trying update secret one more time.")
				return updateK8sSecretWithRetry(false, namespace, secretName, originalK8sSecret, stringDataEntriesMap, variablesErrorsMap...)
			}
		}
		return log.RecordedError(messages.CSPFK022E)
	}

	return nil
}

func RetrieveK8sSecretList() (*v1.SecretList, error) {
	log.Info("Retrieving labeled Kubernetes secrets from all namespaces")
	nsList, err := kubeClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	resultSecretList := &v1.SecretList{}
	for _, ns := range nsList.Items {
		secretList, err := kubeClient.CoreV1().Secrets(ns.Name).List(context.Background(), metav1.ListOptions{LabelSelector: "conjur.org/managed-by-provider=true"})
		if err != nil {
			log.Error("Error while getting secrets from namespace %s: %s", ns.Namespace, err.Error())
			continue
		}
		if secretList != nil {
			logSecrets := func() []string {
				var nameList []string
				for _, sec := range secretList.Items {
					nameList = append(nameList, sec.Name)
				}
				return nameList
			}
			log.Debug("Labeled secrets found in %s ns: %s", ns.Name, logSecrets())
			resultSecretList.Items = append(resultSecretList.Items, secretList.Items...)
		}
	}
	return resultSecretList, nil
}

func configK8sClient() (*kubernetes.Clientset, error) {
	// Create the Kubernetes client
	log.Info(messages.CSPFK004I)
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		// Error messages returned from K8s should be printed only in debug mode
		log.Debug(messages.CSPFK002D, err.Error())
		return nil, log.RecordedError(messages.CSPFK019E)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		// Error messages returned from K8s should be printed only in debug mode
		log.Debug(messages.CSPFK003D, err.Error())
		return nil, log.RecordedError(messages.CSPFK018E)
	}
	// return a K8s client
	return kubeClient, err
}
