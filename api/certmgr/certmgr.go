// Package certmgr provides a REST API for managing TLS certificates.
package certmgr

import (
	"net/http"

	"github.com/database64128/shadowsocks-go/api/internal/restapi"
	"github.com/database64128/shadowsocks-go/tlscerts"
)

// StandardError is the standard error response.
type StandardError struct {
	Message string `json:"error"`
}

// CertificateManager handles TLS certificate management API requests.
type CertificateManager struct {
	store *tlscerts.Store
}

type certListSummary struct {
	Name             string `json:"name"`
	Reloadable       bool   `json:"reloadable,omitzero"`
	CertificateCount int    `json:"certificateCount"`
}

type certPoolSummary struct {
	Name            string `json:"name"`
	CertificateCount int   `json:"certificateCount"`
}

func summarizeCertList(config tlscerts.TLSCertListConfig) certListSummary {
	return certListSummary{
		Name:             config.Name,
		Reloadable:       config.Reloadable,
		CertificateCount: len(config.Certs),
	}
}

func summarizeCertPool(config tlscerts.X509CertPoolConfig) certPoolSummary {
	return certPoolSummary{
		Name:             config.Name,
		CertificateCount: len(config.CertPaths),
	}
}

// NewCertificateManager returns a new certificate manager.
func NewCertificateManager(store *tlscerts.Store) *CertificateManager {
	return &CertificateManager{
		store: store,
	}
}

// RegisterHandlers sets up handlers for the /certlists and /x509certpools endpoints.
func (cm *CertificateManager) RegisterHandlers(register func(method string, path string, handler restapi.HandlerFunc)) {
	register(http.MethodGet, "/certlists", cm.newListCertListsHandler())
	register(http.MethodGet, "/certlists/{name}", newGetCertListHandler(cm.store))
	register(http.MethodPost, "/certlists/{name}/reload", newReloadCertListHandler(cm.store))

	register(http.MethodGet, "/x509certpools", cm.newListX509CertPoolsHandler())
}

func (cm *CertificateManager) newListCertListsHandler() restapi.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) (int, error) {
		configs := cm.store.Config().CertLists
		certLists := make([]certListSummary, 0, len(configs))
		for _, config := range configs {
			certLists = append(certLists, summarizeCertList(config))
		}
		return restapi.EncodeResponse(w, http.StatusOK, certLists)
	}
}

func (cm *CertificateManager) newListX509CertPoolsHandler() restapi.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) (int, error) {
		configs := cm.store.Config().X509CertPools
		certPools := make([]certPoolSummary, 0, len(configs))
		for _, config := range configs {
			certPools = append(certPools, summarizeCertPool(config))
		}
		return restapi.EncodeResponse(w, http.StatusOK, certPools)
	}
}

var (
	certListNotFoundJSON      = []byte(`{"error":"certificate list not found"}`)
	certListNotReloadableJSON = []byte(`{"error":"certificate list is not reloadable"}`)
)

func newGetCertListHandler(store *tlscerts.Store) restapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		name := r.PathValue("name")
		certList, ok := store.GetCertList(name)
		if !ok {
			return restapi.EncodeResponse(w, http.StatusNotFound, &certListNotFoundJSON)
		}
		return restapi.EncodeResponse(w, http.StatusOK, summarizeCertList(*certList.Config()))
	}
}

func newReloadCertListHandler(store *tlscerts.Store) restapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		name := r.PathValue("name")
		certList, ok := store.GetCertList(name)
		if !ok {
			return restapi.EncodeResponse(w, http.StatusNotFound, &certListNotFoundJSON)
		}
		if err := certList.Reload(); err != nil {
			if err == (tlscerts.ReloadDisabledError{}) {
				return restapi.EncodeResponse(w, http.StatusNotFound, &certListNotReloadableJSON)
			}
			return restapi.EncodeResponse(w, http.StatusInternalServerError, StandardError{Message: err.Error()})
		}
		return restapi.EncodeResponse(w, http.StatusNoContent, nil)
	}
}
