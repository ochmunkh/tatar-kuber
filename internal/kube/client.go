// Package kube wraps read-only Kubernetes access for Mode B (client-go).
package kube

import "errors"

// Client — read-only cluster хандалт (get/list/watch).
type Client struct {
	Context string
}

// New — kubeconfig/context-оос client үүсгэнэ.
// TODO: k8s.io/client-go ашиглаж бодит client үүсгэх.
func New(kubeconfig, context string) (*Client, error) {
	return nil, errors.New("kube: not implemented")
}
