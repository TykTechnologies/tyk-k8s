package _test_util

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/gojsonschema"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"os"
	"path"
)

type DashServerMock struct {
	s     *http.Server
	h     *mux.Router
	wkDir string
}

func (d *DashServerMock) Start(addr string) {
	d.h = mux.NewRouter()
	d.h.HandleFunc("/api/apis/{id}", d.GetAPI).Methods("GET")
	d.h.HandleFunc("/api/apis/{id}", d.UpdateAPI).Methods("PUT")
	d.h.HandleFunc("/api/apis/{id}", d.DeleteAPI).Methods("DELETE")
	d.h.HandleFunc("/api/apis", d.CreateAPI).Methods("POST")
	d.h.HandleFunc("/api/apis", d.ListAPIs).Methods("GET")
	d.h.HandleFunc("/api/apis", d.SearchAPI).Methods("GET")
	d.h.HandleFunc("/api/portal/policies/", d.PoliciesList).Methods("GET")
	d.h.HandleFunc("/api/portal/policies/", d.PolicySearch).Methods("GET")
	d.h.HandleFunc("/api/portal/policies/{id}", d.GetPolicy).Methods("GET")
	d.h.HandleFunc("/api/portal/policies/{id}", d.UpdatePolicy).Methods("PUT")
	d.h.HandleFunc("/api/portal/policies/{id}", d.CreatePolicy).Methods("POST")
	d.h.HandleFunc("/api/portal/policies/{id}", d.DeletePolicy).Methods("DELETE")
	d.h.HandleFunc("/api/apis/{api-id}/keys/{key-id}", d.GetToken).Methods("GET")
	d.h.HandleFunc("/api/apis/{api-id}/keys/{key-id}", d.UpdateToken).Methods("PUT")
	d.h.HandleFunc("/api/keys", d.CreateToken).Methods("POST")
	d.h.HandleFunc("/api/apis/{api-id}/keys/{key-id}", d.DeleteToken).Methods("DELETE")

	d.s = &http.Server{Addr: addr}
	d.s.Handler = d.h

	d.wkDir = os.Getenv("TYKCTRL_WKDIR")

	go func() {
		if err := d.s.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("ERR: ListenAndServe(): %s", err)
		}
	}()
}

func (d *DashServerMock) Stop() {
	if d.s != nil {
		if err := d.s.Shutdown(context.TODO()); err != nil {
			panic(err) // failure/timeout shutting down the server gracefully
		}
	}
}

func (d *DashServerMock) UndefinedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("undefined endpoint"))
	w.WriteHeader(500)
}

func (d *DashServerMock) doJSONWrite(w http.ResponseWriter, code int, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(obj); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (d *DashServerMock) doRawWrite(w http.ResponseWriter, code int, obj string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err := w.Write([]byte(obj))
	if err != nil {
		panic(err)
	}
}

func (d *DashServerMock) ListAPIs(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, apiList)
}

func (d *DashServerMock) checkForID(check string, w http.ResponseWriter, r *http.Request) bool {
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		d.doRawWrite(w, 403, "no ID present")
		return false
	}

	if id != check {
		d.doRawWrite(w, 404, "not found")
		return false
	}

	return true
}

func (d *DashServerMock) GetAPI(w http.ResponseWriter, r *http.Request) {
	if !d.checkForID("581b5e91854a610001a2d3ff", w, r) {
		return
	}

	d.doRawWrite(w, 200, singleAPI)
}

func (d *DashServerMock) UpdateAPI(w http.ResponseWriter, r *http.Request) {
	if !d.checkForID("581b5e91854a610001a2d3ff", w, r) {
		return
	}

	d.doRawWrite(w, 200, `{"Status":"OK","Message":"Api updated","Meta":null}`)
}

func (d *DashServerMock) CreateAPI(w http.ResponseWriter, r *http.Request) {

	d.doRawWrite(w, 200, `{"Status":"OK","Message":"API created","Meta":"5c43f0ffd1f3fd0001ff797e"}`)
}

func (d *DashServerMock) DeleteAPI(w http.ResponseWriter, r *http.Request) {
	if !d.checkForID("581b5e91854a610001a2d3ff", w, r) {
		return
	}

	d.doRawWrite(w, 200, `{"Status":"OK","Message":"API deleted","Meta":null}`)
}

func (d *DashServerMock) SearchAPI(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, apiSearchResult)
}

func (d *DashServerMock) PoliciesList(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, policyList)
}

func (d *DashServerMock) PolicySearch(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, policySearch)
}

func (d *DashServerMock) GetPolicy(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, singlePolicy)
}

func (d *DashServerMock) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, `{"Status":"OK","Message":"5c43f5a42e26f4000132fcc3","Meta":null}`)
}

func (d *DashServerMock) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, `{"Status":"OK","Message":"Data updated","Meta":null}`)
}

func (d *DashServerMock) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, `{"Status":"OK","Message":"Data deleted","Meta":null}`)
}

func (d *DashServerMock) validateToken(w http.ResponseWriter, r *http.Request) bool {
	sch, err := ioutil.ReadFile(path.Join(d.wkDir, "api/_test_util", "schemas/key_data.json"))
	if err != nil {
		d.doRawWrite(w, 500, fmt.Sprintf("failed to load schema: %v", err))
		return false
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		d.doRawWrite(w, 500, fmt.Sprintf("failed to read body: %v", err))
		return false
	}

	schemaLoader := gojsonschema.NewStringLoader(string(sch))
	docLoader := gojsonschema.NewStringLoader(string(b))
	result, err := gojsonschema.Validate(schemaLoader, docLoader)
	if err != nil {
		d.doRawWrite(w, 500, err.Error())
		return false
	}

	if !result.Valid() {
		errs := ""
		for _, desc := range result.Errors() {
			errs += fmt.Sprintf("- %s\n", desc)
		}

		d.doRawWrite(w, 500, errs)
		return false
	}

	return true
}

func (d *DashServerMock) GetToken(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, `{"api_model":{},"key_id":"581b5e63106e5900016bdfbd348d87c0b2c346eabafe9126dcd87914","data":{"last_check":0,"allowance":10,"rate":10,"per":1,"expires":0,"quota_max":100,"quota_renews":1547975452,"quota_remaining":100,"quota_renewal_rate":3600,"access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"api_name":"Test API","api_id":"fec6464406c4489b51bf20ecae1f23bb","versions":["Default"],"allowed_urls":[]}},"org_id":"581b5e63106e5900016bdfbd","oauth_client_id":"","basic_auth_data":{"password":"","hash_type":""},"jwt_data":{"secret":""},"hmac_enabled":false,"hmac_string":"","is_inactive":false,"apply_policy_id":"","apply_policies":["581b7142854a610001a2d400"],"data_expires":0,"monitor":{"trigger_limits":null},"meta_data":{},"tags":["test-policy"],"alias":"","last_updated":"1478193474","certificate":""}}`)
}

func (d *DashServerMock) UpdateToken(w http.ResponseWriter, r *http.Request) {
	ok := d.validateToken(w, r)
	if !ok {
		return
	}

	d.doRawWrite(w, 200, `{"Status":"OK","Message":"Key updated","Meta":null}`)
}

func (d *DashServerMock) CreateToken(w http.ResponseWriter, r *http.Request) {
	ok := d.validateToken(w, r)
	if !ok {
		return
	}

	d.doRawWrite(w, 200, `{"api_model":{},"key_id":"581b5e63106e5900016bdfbd348d87c0b2c346eabafe9126dcd87914","data":{"last_check":0,"allowance":10,"rate":10,"per":1,"expires":0,"quota_max":100,"quota_renews":1547975452,"quota_remaining":100,"quota_renewal_rate":3600,"access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"api_name":"Test API","api_id":"fec6464406c4489b51bf20ecae1f23bb","versions":["Default"],"allowed_urls":[]}},"org_id":"581b5e63106e5900016bdfbd","oauth_client_id":"","basic_auth_data":{"password":"","hash_type":""},"jwt_data":{"secret":""},"hmac_enabled":false,"hmac_string":"","is_inactive":false,"apply_policy_id":"","apply_policies":["581b7142854a610001a2d400"],"data_expires":0,"monitor":{"trigger_limits":null},"meta_data":{},"tags":["test-policy"],"alias":"","last_updated":"1478193474","certificate":""},"key_hash":"de72e54e"}`)
}

func (d *DashServerMock) DeleteToken(w http.ResponseWriter, r *http.Request) {
	d.doRawWrite(w, 200, `{"Status":"OK","Message":"Key deleted succesfully","Meta":null}`)
}

var apiList = `
{"apis":[{"created_at":"2016-11-08T09:40:29Z","api_model":{},"api_definition":{"id":"58219d8dbb1afe00013172f3","name":"Test 4","slug":"test-4","api_id":"4d6b32278e6a42634d3842d579e337c5","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/4d6b32278e6a42634d3842d579e337c5/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-08T09:40:23Z","api_model":{},"api_definition":{"id":"58219d87bb1afe00013172f2","name":"Test 3","slug":"test-3","api_id":"1bec7ade0b6640ea61574046097c3980","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/1bec7ade0b6640ea61574046097c3980/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-08T09:40:17Z","api_model":{},"api_definition":{"id":"58219d81bb1afe00013172f1","name":"Test 2","slug":"test-2","api_id":"1822c97236854c87441faffe69fab666","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/1822c97236854c87441faffe69fab666/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-03T15:58:09Z","api_model":{},"api_definition":{"id":"581b5e91854a610001a2d3ff","name":"Test API","slug":"test-api","api_id":"fec6464406c4489b51bf20ecae1f23bb","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{"track_endpoints":[{"path":"ip","method":"GET"}]},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/fec6464406c4489b51bf20ecae1f23bb/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0}],"pages":0}
`

var singleAPI = `
{"api_model":{},"api_definition":{"id":"581b5e91854a610001a2d3ff","name":"Test API","slug":"test-api","api_id":"fec6464406c4489b51bf20ecae1f23bb","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{"track_endpoints":[{"path":"ip","method":"GET"}]},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/fec6464406c4489b51bf20ecae1f23bb/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0}
`

var apiSearchResult = `
{"apis":[{"created_at":"2016-11-08T09:40:29Z","api_model":{},"api_definition":{"id":"58219d8dbb1afe00013172f3","name":"Test 4","slug":"test-4","api_id":"4d6b32278e6a42634d3842d579e337c5","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/4d6b32278e6a42634d3842d579e337c5/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-08T09:40:23Z","api_model":{},"api_definition":{"id":"58219d87bb1afe00013172f2","name":"Test 3","slug":"test-3","api_id":"1bec7ade0b6640ea61574046097c3980","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/1bec7ade0b6640ea61574046097c3980/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-08T09:40:17Z","api_model":{},"api_definition":{"id":"58219d81bb1afe00013172f1","name":"Test 2","slug":"test-2","api_id":"1822c97236854c87441faffe69fab666","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":null,"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/1822c97236854c87441faffe69fab666/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":null,"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":null},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":null,"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":null,"tag_headers":null,"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0},{"created_at":"2016-11-03T15:58:09Z","api_model":{},"api_definition":{"id":"581b5e91854a610001a2d3ff","name":"Test API","slug":"test-api","api_id":"fec6464406c4489b51bf20ecae1f23bb","org_id":"581b5e63106e5900016bdfbd","use_keyless":false,"use_oauth2":false,"use_openid":false,"openid_options":{"providers":[],"segregate_by_client":false},"oauth_meta":{"allowed_access_types":[],"allowed_authorize_types":[],"auth_login_redirect":""},"auth":{"use_param":false,"param_name":"","use_cookie":false,"cookie_name":"","auth_header_name":"Authorization","use_certificate":false},"use_basic_auth":false,"basic_auth":{"disable_caching":false,"cache_ttl":0},"use_mutual_tls_auth":false,"client_certificates":[],"upstream_certificates":{},"pinned_public_keys":{},"enable_jwt":false,"use_standard_auth":true,"enable_coprocess_auth":false,"jwt_signing_method":"","jwt_source":"","jwt_identity_base_field":"","jwt_client_base_field":"","jwt_policy_field_name":"","jwt_disable_issued_at_validation":false,"jwt_disable_expires_at_validation":false,"jwt_disable_not_before_validation":false,"jwt_skip_kid":false,"notifications":{"shared_secret":"","oauth_on_keychange_url":""},"enable_signature_checking":false,"hmac_allowed_clock_skew":-1,"base_identity_provided_by":"","definition":{"location":"header","key":"x-api-version","strip_path":false},"version_data":{"not_versioned":true,"default_version":"","versions":{"Default":{"name":"Default","expires":"","paths":{"ignored":[],"white_list":[],"black_list":[]},"use_extended_paths":true,"extended_paths":{"track_endpoints":[{"path":"ip","method":"GET"}]},"global_headers":{},"global_headers_remove":[],"global_size_limit":0,"override_target":""}}},"uptime_tests":{"check_list":[],"config":{"expire_utime_after":0,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"","port_data_path":"","target_path":"","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"recheck_wait":0}},"proxy":{"preserve_host_header":false,"listen_path":"/fec6464406c4489b51bf20ecae1f23bb/","target_url":"http://httpbin.org/","strip_listen_path":true,"enable_load_balancing":false,"target_list":[],"check_host_against_uptime_tests":false,"service_discovery":{"use_discovery_service":false,"query_endpoint":"","use_nested_query":false,"parent_data_path":"","data_path":"hostname","port_data_path":"port","target_path":"/api-slug","use_target_list":false,"cache_timeout":60,"endpoint_returns_list":false},"transport":{"ssl_ciphers":[],"ssl_min_version":0,"proxy_url":""}},"disable_rate_limit":false,"disable_quota":false,"custom_middleware":{"pre":[],"post":[],"post_key_auth":[],"auth_check":{"name":"","path":"","require_session":false},"response":[],"driver":"","id_extractor":{"extract_from":"","extract_with":"","extractor_config":{}}},"custom_middleware_bundle":"","cache_options":{"cache_timeout":60,"enable_cache":true,"cache_all_safe_requests":false,"cache_response_codes":[],"enable_upstream_cache_control":false,"cache_control_ttl_header":""},"session_lifetime":0,"active":true,"auth_provider":{"name":"","storage_engine":"","meta":{}},"session_provider":{"name":"","storage_engine":"","meta":{}},"event_handlers":{"events":{}},"enable_batch_request_support":false,"enable_ip_whitelisting":false,"allowed_ips":[],"enable_ip_blacklisting":false,"blacklisted_ips":[],"dont_set_quota_on_create":false,"expire_analytics_after":0,"response_processors":[],"CORS":{"enable":false,"allowed_origins":[],"allowed_methods":[],"allowed_headers":[],"exposed_headers":[],"allow_credentials":false,"max_age":24,"options_passthrough":false,"debug":false},"domain":"","do_not_track":false,"tags":[],"enable_context_vars":false,"config_data":{},"tag_headers":[],"global_rate_limit":{"rate":0,"per":0},"strip_auth_data":false},"hook_references":[],"is_site":false,"sort_by":0}],"pages":0}`

var policyList = `
{"Data":[{"_id":"581b7142854a610001a2d400","access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"allowed_urls":[],"apiid":"fec6464406c4489b51bf20ecae1f23bb","apiname":"Test API","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478193474","name":"Default","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":1,"quota_max":100,"quota_renewal_rate":3600,"rate":10,"tags":["test-policy"]},{"_id":"58219d9dbb1afe00013172f4","access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"allowed_urls":[],"apiid":"fec6464406c4489b51bf20ecae1f23bb","apiname":"Test API","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598045","name":"P1","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]},{"_id":"58219daa7ef3fb00018b8b78","access_rights":{"1822c97236854c87441faffe69fab666":{"allowed_urls":[],"apiid":"1822c97236854c87441faffe69fab666","apiname":"Test 2","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598058","name":"P2","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]},{"_id":"58219db77ef3fb00018b8b79","access_rights":{"1bec7ade0b6640ea61574046097c3980":{"allowed_urls":[],"apiid":"1bec7ade0b6640ea61574046097c3980","apiname":"Test 3","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598071","name":"P3","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]},{"_id":"58219dc37ef3fb00018b8b7a","access_rights":{"4d6b32278e6a42634d3842d579e337c5":{"allowed_urls":[],"apiid":"4d6b32278e6a42634d3842d579e337c5","apiname":"Test 4","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598082","name":"P4","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]},{"_id":"58219dd27ef3fb00018b8b7b","access_rights":{"1822c97236854c87441faffe69fab666":{"allowed_urls":[],"apiid":"1822c97236854c87441faffe69fab666","apiname":"Test 2","versions":["Default"]},"1bec7ade0b6640ea61574046097c3980":{"allowed_urls":[],"apiid":"1bec7ade0b6640ea61574046097c3980","apiname":"Test 3","versions":["Default"]},"fec6464406c4489b51bf20ecae1f23bb":{"allowed_urls":[],"apiid":"fec6464406c4489b51bf20ecae1f23bb","apiname":"Test API","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598098","name":"P5","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]},{"_id":"58219de1bb1afe00013172f5","access_rights":{"1822c97236854c87441faffe69fab666":{"allowed_urls":[],"apiid":"1822c97236854c87441faffe69fab666","apiname":"Test 2","versions":["Default"]},"fec6464406c4489b51bf20ecae1f23bb":{"allowed_urls":[],"apiid":"fec6464406c4489b51bf20ecae1f23bb","apiname":"Test API","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598113","name":"P6","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]}],"Pages":0}
`

var singlePolicy = `
{"_id":"58219d9dbb1afe00013172f4","id":"","org_id":"581b5e63106e5900016bdfbd","rate":1000,"per":60,"quota_max":-1,"quota_renewal_rate":60,"access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"api_name":"Test API","api_id":"fec6464406c4489b51bf20ecae1f23bb","versions":["Default"],"allowed_urls":[]}},"hmac_enabled":false,"active":true,"name":"P1","is_inactive":false,"date_created":"0001-01-01T00:00:00Z","tags":[],"key_expires_in":0,"partitions":{"quota":false,"rate_limit":false,"acl":false},"last_updated":"1478598045"}
`

var policySearch = `
{"Data":[{"_id":"58219d9dbb1afe00013172f4","access_rights":{"fec6464406c4489b51bf20ecae1f23bb":{"allowed_urls":[],"apiid":"fec6464406c4489b51bf20ecae1f23bb","apiname":"Test API","versions":["Default"]}},"active":true,"date_created":"0001-01-01T00:00:00Z","hmac_enabled":false,"is_inactive":false,"key_expires_in":0,"last_updated":"1478598045","name":"P1","org_id":"581b5e63106e5900016bdfbd","partitions":{"acl":false,"quota":false,"rate_limit":false},"per":60,"quota_max":-1,"quota_renewal_rate":60,"rate":1000,"tags":[]}],"Pages":0}
`
