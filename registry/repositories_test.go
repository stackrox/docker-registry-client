// Copyright 2019 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This test is essentially copied from [1],
// so we add the above license to be safe.
//
// [1] https://github.com/google/go-containerregistry/blob/v0.15.2/pkg/v1/remote/catalog_test.go

package registry

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRepositories(t *testing.T) {
	cases := []struct {
		name      string
		pages     [][]byte
		wantErr   bool
		wantRepos []string
	}{{
		name: "success",
		pages: [][]byte{
			[]byte(`{"repositories":["test/one","test/two"]}`),
			[]byte(`{"repositories":["test/three","test/four"]}`),
		},
		wantErr:   false,
		wantRepos: []string{"test/one", "test/two", "test/three", "test/four"},
	}, {
		name:    "not json",
		pages:   [][]byte{[]byte("notjson")},
		wantErr: true,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalogPath := "/v2/_catalog"
			pageTwo := "/v2/_catalog_two"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := 0
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case pageTwo:
					page = 1
					fallthrough
				case catalogPath:
					if r.Method != http.MethodGet {
						t.Errorf("Method; got %v, want %v", r.Method, http.MethodGet)
					}

					if page == 0 {
						w.Header().Set("Link", fmt.Sprintf(`<%s>; type="application/json"; rel="next"`, pageTwo))
					}
					w.Write(tc.pages[page])
				default:
					t.Fatalf("Unexpected path: %v", r.URL.Path)
				}
			}))
			defer server.Close()

			reg, err := New(server.URL, "", "")
			if err != nil {
				t.Fatal("I don't know how to make a registry I guess")
			}

			repos, err := reg.Repositories()
			if (err != nil) != tc.wantErr {
				t.Errorf("Catalog() wrong error: %v, want %v: %v\n", (err != nil), tc.wantErr, err)
			}

			if diff := cmp.Diff(tc.wantRepos, repos); diff != "" {
				t.Errorf("Catalog() wrong repos (-want +got) = %s", diff)
			}
		})
	}
}
