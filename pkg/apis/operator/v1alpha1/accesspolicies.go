package v1alpha1

var ElasticSearch = `{
      "displayName": {
        "default": "elasticsearch"
      },
      "actions": [{
          "id": "PUT /logstash-*",
          "displayName": {
            "default": "logging.elasticsearch.index"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "POST /logstash-*",
          "displayName": {
            "default": "logging.elasticsearch.index2"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "GET /logstash-*",
          "displayName": {
            "default": "logging.elasticsearch.index3"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "HEAD /logstash-*",
          "displayName": {
            "default": "logging.elasticsearch.index4"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "DELETE /logstash-*",
          "displayName": {
            "default": "logging.elasticsearch.index5"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "GET /_mget",
          "displayName": {
            "default": "logging.elasticsearch.index6"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "GET /_refresh",
          "displayName": {
            "default": "logging.elasticsearch.index7"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        },
        {
          "id": "POST /_reindex",
          "displayName": {
            "default": "logging.elasticsearch.index8"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator"
          ]
        }
      ],
      "enabled": true,
      "supportedAttributes": [{
        "key": "string"
      }],
      "supportedRoles": [{
          "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Operator"
        }
      ]
    }
`

var HelmApi = `{
    "chartName": "helm-api",
    "displayName": {
        "default": "helmapi"
    },
    "actions": [
        {
            "id": "GET /helm-api/api/v1/repos",
            "displayName": {
                "default": "helmapi.repos.get.allorsingular"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "PUT /helm-api/api/v1/repos",
            "displayName": {
                "default": "helmapi.repos.put.updaterepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "POST /helm-api/api/v1/repos",
            "displayName": {
                "default": "helmapi.repos.post.addrepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "DELETE /helm-api/api/v1/repos",
            "displayName": {
                "default": "helmapi.repos.delete.removerepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/synch",
            "displayName": {
                "default": "helmapi.synch.get"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/releasesCRNs",
            "displayName": {
                "default": "helmapi.releasesCRNs.get.all"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/releases",
            "displayName": {
                "default": "helmapi.releases.get.allorspecific"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "POST /helm-api/api/v1/releases",
            "displayName": {
                "default": "helmapi.releases.post.addorrollback"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "PUT /helm-api/api/v1/releases",
            "displayName": {
                "default": "helmapi.releases.put.updaterelease"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "DELETE /helm-api/api/v1/releases",
            "displayName": {
                "default": "helmapi.releases.delete.removerelease"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/charts",
            "displayName": {
                "default": "helmapi.charts.get.allorspecific"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/history",
            "displayName": {
                "default": "helmapi.history.get.releasehistory"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "PUT /helm-api/api/v1/restoreDefaults",
            "displayName": {
                "default": "helmapi.defaults.get.restoredefaultrepos"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/values",
            "displayName": {
                "default": "helmapi.values.get.chartversiondefaults"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v1/status",
            "displayName": {
                "default": "helmapi.status.get.releasestatus"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/assets",
            "displayName": {
                "default": "helmapi.assets.get.staticassetsforchart"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/healthcheck",
            "displayName": {
                "default": "helmapi.healthcheck.get"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/repos",
            "displayName": {
                "default": "helmapi.repos.get.allorsingular"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "PUT /helm-api/api/v2/repos",
            "displayName": {
                "default": "helmapi.repos.put.updaterepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "POST /helm-api/api/v2/repos",
            "displayName": {
                "default": "helmapi.repos.post.addrepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "DELETE /helm-api/api/v2/repos",
            "displayName": {
                "default": "helmapi.repos.delete.removerepo"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/synch",
            "displayName": {
                "default": "helmapi.synch.get"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/releasesCRNs",
            "displayName": {
                "default": "helmapi.releasesCRNs.get.all"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/releases",
            "displayName": {
                "default": "helmapi.releases.get.allorspecific"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "POST /helm-api/api/v2/releases",
            "displayName": {
                "default": "helmapi.releases.post.addorrollback"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "PUT /helm-api/api/v2/releases",
            "displayName": {
                "default": "helmapi.releases.put.updaterelease"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "DELETE /helm-api/api/v2/releases",
            "displayName": {
                "default": "helmapi.releases.delete.removerelease"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/charts",
            "displayName": {
                "default": "helmapi.charts.get.allorspecific"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/history",
            "displayName": {
                "default": "helmapi.history.get.releasehistory"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "PUT /helm-api/api/v2/restoreDefaults",
            "displayName": {
                "default": "helmapi.defaults.get.restoredefaultrepos"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/values",
            "displayName": {
                "default": "helmapi.values.get.chartversiondefaults"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        },
        {
            "id": "GET /helm-api/api/v2/status",
            "displayName": {
                "default": "helmapi.status.get.releasestatus"
            },
            "roles": [
                "crn:v1:icp:private:iam::::role:ClusterAdministrator",
                "crn:v1:icp:private:iam::::role:AccountAdministrator",
                "crn:v1:icp:private:iam::::role:Administrator",
                "crn:v1:icp:private:iam::::role:Operator",
                "crn:v1:icp:private:iam::::role:Editor",
                "crn:v1:icp:private:iam::::role:Viewer"
            ]
        }
    ],
    "enabled": true,
    "supportedAttributes": [
        {
            "key": "string"
        }
    ],
    "supportedRoles": [
        {
            "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Operator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Editor"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Viewer"
        }
    ]
}
`

var HelmRepo = `{
      "displayName": {
        "default": "helmrepo-repos"
      },
      "actions": [{
          "id": "GET /helm-repo/charts/index.yaml",
          "displayName": {
            "default": "helmrepo.repos.get.indexyaml"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "id": "GET /helm-repo/requiredAssets",
          "displayName": {
            "default": "helmrepo.charts.get.requiredassets"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "id": "PUT /helm-repo/charts",
          "displayName": {
            "default": "helmrepo.repos.put.updatecreatechart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        },
        {
          "id": "DELETE /helm-repo/charts",
          "displayName": {
            "default": "helmrepo.repos.delete.allorsingularchart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        },
        {
          "id": "GET /helm-repo/api/v1/charts/index.yaml",
          "displayName": {
            "default": "helmrepo.repos.v1.get.indexyaml"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "id": "GET /helm-repo/api/v1/requiredAssets",
          "displayName": {
            "default": "helmrepo.charts.v1.get.requiredassets"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "id": "PUT /helm-repo/api/v1/charts",
          "displayName": {
            "default": "helmrepo.repos.v1.put.updatecreatechart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        },
        {
          "id": "DELETE /helm-repo/api/v1/charts",
          "displayName": {
            "default": "helmrepo.repos.v1.delete.allorsingularchart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        }
      ],
      "enabled": true,
      "supportedAttributes": [{
        "key": "string"
      }],
      "supportedRoles": [
        {
          "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Operator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Editor"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Viewer"
        }
      ]
    }
`

var Kms = `{
      "displayName": {
          "default": "kms"
      },
      "actions": [
        {
          "displayName": {"default": "key-protect-secrets-create-action"},
          "id": "POST /kms/secrets/create",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Editor"
          ]
        },
        {
          "displayName": {"default": "key-protect-secrets-delete-action"},
          "id": "DELETE /kms/secrets/delete",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        },
        {
          "displayName": {"default": "key-protect-secrets-list-action"},
          "id": "GET /kms/secrets/list",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Editor"
          ]
        },
        {
          "displayName": {"default": "key-protect-secrets-read-action"},
          "id": "GET /kms/secrets/read",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Editor"
          ]
        },
        {
          "displayName": {"default":"key-protect-secrets-wrap-action"},
          "id": "POST /kms/secrets/wrap",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "displayName": {"default": "key-protect-secrets-unwrap-action"},
          "id": "POST /kms/secrets/unwrap",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },
        {
          "displayName": {"default": "key-protect-secrets-rotate-action"},
          "id": "POST /kms/secrets/rotate",
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator"
          ]
        }
      ],
    "enabled": true,
    "supportedAttributes": [{
      "key": "string"
    }],
    "supportedRoles": [
        {
            "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Editor"
        },
        {
            "id": "crn:v1:icp:private:iam::::role:Viewer"
        }
      ]
    }
`
var MgmtRepo = `{
      "displayName": {
        "default": "mgmtrepo-repos"
      },
      "actions": [{
          "id": "GET /mgmt-repo/charts/index.yaml",
          "displayName": {
            "default": "mgmtrepo.repos.get.indexyaml"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "GET /mgmt-repo/requiredAssets",
          "displayName": {
            "default": "mgmtrepo.charts.get.requiredassets"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "PUT /mgmt-repo/charts",
          "displayName": {
            "default": "mgmtrepo.repos.put.updatecreatechart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "DELETE /mgmt-repo/charts",
          "displayName": {
            "default": "mgmtrepo.repos.delete.allorsingularchart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "GET /mgmt-repo/api/v1/charts/index.yaml",
          "displayName": {
            "default": "mgmtrepo.repos.v1.get.indexyaml"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "GET /mgmt-repo/api/v1/requiredAssets",
          "displayName": {
            "default": "mgmtrepo.charts.v1.get.requiredassets"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "PUT /mgmt-repo/api/v1/charts",
          "displayName": {
            "default": "mgmtrepo.repos.v1.put.updatecreatechart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        },
        {
          "id": "DELETE /mgmt-repo/api/v1/charts",
          "displayName": {
            "default": "mgmtrepo.repos.v1.delete.allorsingularchart"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          ]
        }
      ],
      "enabled": true,
      "supportedAttributes": [{
        "key": "string"
      }],
      "supportedRoles": [
        {
          "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        }
      ]
    }
`
var Monitoring = `{
      "displayName": {
        "default": "service-monitoring"
      },
      "actions": [
        {
          "id": "GET /prometheus",
          "displayName": {
            "default": "service-monitoring.prometheus.get"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator",
              "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
          "id": "DELETE /prometheus/api",
          "displayName": {
            "default": "service-monitoring.prometheus.series.delete"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator"
            ]
        },
        {
          "id": "GET /alertmanager",
          "displayName": {
            "default": "service-monitoring.alertmanager.get"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator",
              "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
          "id": "GET /grafana",
          "displayName": {
            "default": "service-monitoring.grafana.get"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator",
              "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
          "id": "POST /grafana/api/user/using",
          "displayName": {
            "default": "service-monitoring.grafana.switch"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator",
              "crn:v1:icp:private:iam::::role:Operator"
            ]
        },
        {
          "id": "POST /grafana/api",
          "displayName": {
            "default": "service-monitoring.grafana.create"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator"
            ]
        },
        {
          "id": "DELETE /grafana/api",
          "displayName": {
            "default": "service-monitoring.grafana.delete"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator"
            ]
        },
        {
          "id": "PUT /grafana/api",
          "displayName": {
            "default": "service-monitoring.grafana.update"
          },
            "roles": [
              "crn:v1:icp:private:iam::::role:ClusterAdministrator",
              "crn:v1:icp:private:iam::::role:AccountAdministrator",
              "crn:v1:icp:private:iam::::role:Administrator"
            ]
        }
      ],
      "enabled": true,
      "supportedAttributes": [
        {
          "key": "string"
        }
      ],
      "supportedRoles": [{
          "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Operator"
        }
      ]
    }
`
var TillerService = `{
      "displayName": {
        "default": "tiller-service"
      },
      "actions": [{
          "id": "GET /idmgmt/identity/api/v1/service/teamRoleBindings",
          "displayName": {
            "default": "tiller.service.get.teamrolebindings"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        },{
          "id": "GET /identity/api/v1/service/teamRoleBindings",
          "displayName": {
            "default": "tiller.service.get.identity.teamrolebindings"
          },
          "roles": [
            "crn:v1:icp:private:iam::::role:ClusterAdministrator",
            "crn:v1:icp:private:iam::::role:AccountAdministrator",
            "crn:v1:icp:private:iam::::role:Administrator",
            "crn:v1:icp:private:iam::::role:Operator",
            "crn:v1:icp:private:iam::::role:Editor",
            "crn:v1:icp:private:iam::::role:Viewer"
          ]
        }
      ],
      "enabled": true,
      "supportedAttributes": [{
        "key": "string"
      }],
      "supportedRoles": [
        {
          "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Administrator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Operator"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Editor"
        },
        {
          "id": "crn:v1:icp:private:iam::::role:Viewer"
        }
      ]
    }
`
var Tiller_Serviceid_Policies = `{
      "resources": [
          {
              "namespaceId": "kube-system",
              "serviceName": "tiller-service"
          }
      ],
      "roles": [
          {
              "id": "crn:v1:icp:private:iam::::role:ClusterAdministrator"
          },
          {
              "id": "crn:v1:icp:private:iam::::role:AccountAdministrator"
          },
          {
              "id": "crn:v1:icp:private:iam::::role:Administrator"
          },
          {
              "id": "crn:v1:icp:private:iam::::role:Operator"
          },
          {
              "id": "crn:v1:icp:private:iam::::role:Viewer"
          },
          {
              "id": "crn:v1:icp:private:iam::::role:Editor"
          }
      ]
    }
`
var Onboard_Script = `import requests
import json
import time
import os
def mapActionRoles(iam_service_name, filepath, accessToken):
    with open(filepath) as f:
        fdata = f.read()
        url = 'https://iam-pap:39001/acms/v1/services/' + iam_service_name
        headersDef = {'Authorization': accessToken, 'Content-Type': 'application/json', 'Accept': 'application/json'}
        while True:
            r = requests.put(url, data=fdata, headers=headersDef, verify='/app/cluster-ca/ca.crt')
            if r.status_code == 201 or r.status_code == 200:
                break
            else:
                time.sleep(2)
def getServiceId(serviceName, accessToken):
    cluster_name = os.environ.get('CLUSTER_NAME')
    url = 'https://iam-token-service:10443/serviceids/?boundTo=crn%3Av1%3Aicp%3Aprivate%3Aiam%3A' + cluster_name + '%3An/kube-system%3Acore%3Aservice%3A' + serviceName
    headersDef = {'Authorization': accessToken, 'Content-Type': 'application/json', 'Accept': 'application/json'}
    while True:
        r = requests.get(url, headers=headersDef, verify=False)
        print r.status_code
        if r.status_code == 200:
            response = r.json()
            if (len(response['items']) != 0):
                break
            else:
                time.sleep(10)
        else:
            time.sleep(2)
    serviceId = response['items'][0]['metadata']['iam_id']
    return serviceId
def mapServiceIdPolicies(serviceName, filepath, accessToken):
    serviceId = getServiceId(serviceName, accessToken)
    with open(filepath) as f:
        fdata = f.read()
        url = 'https://iam-pap:39001/acms/v1/scopes/n%252Fkube-system/service_ids/' + serviceId + '/policies'
        headersDef = {'Authorization': accessToken, 'Content-Type': 'application/json', 'Accept': 'application/json'}
        while True:
            r = requests.post(url, data=fdata, headers=headersDef, verify='/app/cluster-ca/ca.crt')
            if r.status_code == 201:
                break
            else:
                time.sleep(2)
def getApiKeyToken():
    url = 'https://iam-token-service:10443/oidc/token'
    apikey = os.environ.get('ICP_API_KEY')
    payload = 'grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=' + apikey + '&response_type=cloud_iam'
    headersDef = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    while True:
        r = requests.post(url, data=payload, headers=headersDef, verify=False)
        if r.status_code == 200:
            break
        else:
            time.sleep(2)
    response = r.json()
    accessToken = response['access_token']
    return accessToken
def onboardToSecurity(iamServiceName, filePath):
    accessToken = getApiKeyToken()
    mapActionRoles(iamServiceName, filePath, accessToken)
def onboardServiceIdPolicies(serviceName, filePath):
    accessToken = getApiKeyToken()
    mapServiceIdPolicies(serviceName, filePath, accessToken)
def main():
    # Any new service that is trying to onboard should append their service name and the mounted access policy file path to this list
    #  serviceList=[{'serviceName':'elasticsearch-service','filePath':'/app/elasticsearch/action_role_elasticsearch.json'},
    #  {'serviceName':'service-monitoring-service','filePath':'/app/monitoring/action_role_monitoring.json'},
    #  {'serviceName':'new-service','filePath':'/app/monitoring/action_role_newservice.json'}]
    serviceList = [
        {'serviceName': 'elasticsearch-service', 'filePath': '/app/elasticsearch/action_role_elasticsearch.json'},
        {'serviceName': 'service-monitoring-service', 'filePath': '/app/monitoring/action_role_monitoring.json'},
        {'serviceName': 'helmapi-service', 'filePath': '/app/helmapi/action_role_helmapi.json'},
        {'serviceName': 'helmrepo-service', 'filePath': '/app/helmrepo/action_role_helmrepo.json'},
        {'serviceName': 'mgmtrepo-service', 'filePath': '/app/mgmtrepo/action_role_mgmtrepo.json'},
        {'serviceName': 'tiller-service', 'filePath': '/app/tillerservice/action_role_tillerservice.json'},
        {'serviceName': 'kms', 'filePath': '/app/kms/action_role_kms.json'}]
    for service in serviceList:
        onboardToSecurity(service['serviceName'], service['filePath'])
    onboardServiceIdPolicies('tiller-service', '/app/tiller_serviceid_policies/tiller_serviceid_policies.json')
if __name__ == "__main__":
	main()
`