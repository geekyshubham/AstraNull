/**
 * Vendored edge-fingerprint corpus. GENERATED — do not edit by hand.
 * Regenerate with `node scripts/generate-edge-signatures.mjs` from the pinned source commits
 * recorded in EDGE_SIGNATURE_CORPUS_MANIFEST.
 *
 * wafw00f signature data: BSD-3-Clause, Copyright (c) 2009-2026 WAFW00F Developers.
 * cdncheck range/CNAME data: MIT, Copyright (c) 2021 ProjectDiscovery, Inc.
 * Complete notices: THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt and
 * THIRD_PARTY_NOTICES/cdncheck-MIT.txt.
 */

export const EDGE_SIGNATURE_CORPUS_MANIFEST = Object.freeze({
  "output_version": 2,
  "format": "astranull-edge-signature-corpus-v2",
  "generator": "scripts/generate-edge-signatures.mjs",
  "generator_sha256": "086f72d2f558de45fcdf79f7dd96c03d56e93e6218c43f108d2dc06cf69a83ed",
  "output_manifest": "src/lib/data/edgeSignatureData.manifest.json",
  "sources": {
    "wafw00f": {
      "repository": "https://github.com/EnableSecurity/wafw00f",
      "commit": "69fbe3956bba47a172cf87e40e9037535d32a130",
      "license": "BSD-3-Clause",
      "license_notice": "THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt",
      "plugin_tree_sha256": "44f4379d119d7cd688b2b8f68e5a1cd9e5bcf150491f46cb438d8a71f223b002",
      "plugin_tree_hash_encoding": "sorted-path-length-content-length-v1",
      "plugin_files": 172,
      "matcher_calls": 518,
      "license_sha256": "fdaaf8393afcbab5a0db158ae742e76ec3803a7c72af19489f5bd521d3db08ea"
    },
    "cdncheck": {
      "repository": "https://github.com/projectdiscovery/cdncheck",
      "commit": "dac12984ef12fa5663c2b7591d0a304ef27c659b",
      "license": "MIT",
      "license_notice": "THIRD_PARTY_NOTICES/cdncheck-MIT.txt",
      "ported_categories": [
        "cdn",
        "waf",
        "common"
      ],
      "excluded_categories": [
        {
          "category": "cloud",
          "reason": "general hosting ranges are not edge-protection evidence"
        }
      ],
      "sources_data_sha256": "4a7482b64ded7a611e11eadda6730cc8df159942c16713f17bbfecdb8a7cd2a3",
      "cname_implementation_sha256": "37182c8c3bc5a6182f2ced734d00fb252c5b0ae08cf284bd0437f44bc305244a",
      "license_sha256": "cbcdaab87df3175107aa28915bd253cebdd618a49c9ac5d6c669c0b1cbebcacb",
      "cname_item_type": "waf"
    }
  }
});

/** Strict AST ports of every pinned wafw00f plugin, including its decision tree. */
export const WAF_VENDOR_SIGNATURES = Object.freeze({
  "aesecure": {
    "name": "aeSecure (aeSecure)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "aesecure-code",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "aesecure_denied\\.png"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "airee": {
    "name": "AireeCDN (Airee)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Airee",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cache",
        "pattern": "(\\w+\\.)?airee\\.cloud",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "airee\\.cloud"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "airlock": {
    "name": "Airlock (Phion/Ergon)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^al[_-]?(sess|lb)="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "server detected a syntax error in your request"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "alertlogic": {
    "name": "Alert Logic (Alert Logic)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>requested url cannot be found"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "we are sorry.{0,10}?but the page you are looking for cannot be found"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "back to previous page"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "proceed to homepage"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "reference id"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        }
      }
    }
  },
  "aliyundun": {
    "name": "AliYunDun (Alibaba Cloud Computing)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "error(s)?\\.aliyun(dun)?\\.(com|net)?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "alicdn\\.com\\/sd\\-base\\/static\\/\\d{1,2}\\.\\d{1,2}\\.\\d{1,2}\\/image\\/405\\.png"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Sorry, your request has been blocked as it may cause potential threats to the server\\'s security."
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 405
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        }
      }
    }
  },
  "anquanbao": {
    "name": "Anquanbao (Anquanbao)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-powered-by-anquanbao",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "aqb_cc/error/"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "anubis": {
    "name": "Anubis (Techaro)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "-anubis-auth="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/\\.within\\.website/x/cmd/anubis/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<script id=\"anubis_version\""
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<script id=\"anubis_challenge\""
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Protected by.*Anubis.*From.*Techaro"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "github\\.com/TecharoHQ/anubis"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "const",
                  "value": false
                }
              }
            }
          }
        }
      }
    }
  },
  "anyu": {
    "name": "AnYu (AnYu Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "anyu.{0,10}?the green channel"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "your access has been intercepted by anyu"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "applicationgateway": {
    "name": "Azure Application Gateway (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<center>Microsoft-Azure-Application-Gateway/v2</center>"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<h1>403 Forbidden</h1>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "and",
        "args": [
          {
            "op": "signal",
            "id": 0
          },
          {
            "op": "signal",
            "id": 1
          }
        ]
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "approach": {
    "name": "Approach (Approach)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "approach.{0,10}?web application (firewall|filtering)"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "approach.{0,10}?infrastructure team"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "armor": {
    "name": "Armor Defense (Armor)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "blocked by website protection from armor"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "please create an armor support ticket"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "arvancloud": {
    "name": "ArvanCloud (ArvanCloud)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ArvanCloud",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "aspa": {
    "name": "ASPA Firewall (ASPA Engineering Co.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ASPA[\\-_]?WAF",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "aspa-cache-status",
        "pattern": ".+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "aspnetgen": {
    "name": "ASP.NET Generic (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "iis (\\d+.)+?detailed error"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "potentially dangerous request querystring"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "application error from being viewed remotely (for security reasons)?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "An application error occurred on the server"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "astra": {
    "name": "Astra (Czar Securities)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^cz_astra_csrf_cookie"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "astrawebsecurity\\.freshdesk\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.getastra\\.com/assets/images"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "awswaf": {
    "name": "AWS Elastic Load Balancer (Amazon)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-amz-id",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-amz-request-id",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^aws.?alb="
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "server",
        "pattern": "aws.?elb",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-blocked-by-waf",
        "pattern": "Blocked_by_custom_response_for_AWSManagedRules.*",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "azion": {
    "name": "Azion Edge Firewall (Azion)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-azion-edge-pop",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-azion-request-id",
        "pattern": ".+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "baffinbay": {
    "name": "Baffin Bay (Mastercard)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "baffin-bay-inlet",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "baidu": {
    "name": "Yunjiasu (Baidu Cloud Computing)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "yunjiasu.*",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "href=\"/.well-known/yunjiasu-cgi/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "document.cookie='yjs_use_ob=0"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "barikode": {
    "name": "Barikode (Ethic Ninja)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<strong>barikode<.strong>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "barracuda": {
    "name": "Barracuda (Barracuda Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^barra_counter_session="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^BNI__BARRACUDA_LB_COOKIE="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^BNI_persistence="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^BN[IE]S_.*?="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Barracuda.Networks"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "bekchy": {
    "name": "Bekchy (Faydata Technologies Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Bekchy.{0,10}?Access Denied"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "bekchy\\.com/report"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "beluga": {
    "name": "Beluga CDN (Beluga)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Beluga",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^beluga_request_trail="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "binarysec": {
    "name": "BinarySec (BinarySec)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "BinarySec",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-binarysec-via",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-binarysec-nocache",
        "pattern": ".+",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "bitninja": {
    "name": "BitNinja (BitNinja)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Security check by BitNinja"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Visitor anti-robot validation"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "blockdos": {
    "name": "BlockDoS (BlockDoS)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "blockdos\\.net",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "bluedon": {
    "name": "Bluedon (Bluedon IST)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "BDWAF",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "bluedon web application firewall"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "bulletproof": {
    "name": "BulletProof Security Pro (AITpro Security)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "\\+?bpsMessage"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "403 Forbidden Error Page"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "If you arrived here due to a search"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      }
    }
  },
  "cachefly": {
    "name": "CacheFly CDN (CacheFly)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "bestcdn",
        "pattern": "Cachefly",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^cfly_req.*="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "cachewall": {
    "name": "CacheWall (Varnish)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Varnish",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-varnish",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cachewall-action",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cachewall-reason",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "security by cachewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "403 naughty.{0,10}?not nice!"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "varnish cache server"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "const",
                    "value": false
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "cdnns": {
    "name": "CdnNS Application Gateway (CdnNs/WdidcNet)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cdnnswaf application gateway"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "cerber": {
    "name": "WP Cerber Security (Cerber Tech)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "your request looks suspicious or similar to automated"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "our server stopped processing your request"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "We.re sorry.{0,10}?you are not allowed to proceed"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "requests from spam posting software"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>403 Access Forbidden"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        }
      }
    }
  },
  "chinacache": {
    "name": "ChinaCache Load Balancer (ChinaCache)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "powered-by-chinacache",
        "pattern": ".+",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "chuangyu": {
    "name": "Chuang Yu Shield (Yunaq)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.365cyd\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "help\\.365cyd\\.com/cyd\\-error\\-help.html\\?code=403"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "ciscoacexml": {
    "name": "ACE XML Gateway (Cisco)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ACE XML Gateway",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "cloudbric": {
    "name": "Cloudbric (Penta Security)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Cloudbric.{0,5}?ERROR!"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Your request was blocked by Cloudbric"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "please contact Cloudbric Support"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cloudbric\\.zendesk\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Cloudbric Help Center"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "malformed request syntax.{0,4}?invalid request message framing.{0,4}?or deceptive request routing"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "const",
                  "value": false
                }
              }
            }
          }
        }
      }
    }
  },
  "cloudflare": {
    "name": "Cloudflare (Cloudflare Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "cloudflare",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "cloudflare[-_]nginx",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "cf-ray",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "__cfduid"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "cloudfloordns": {
    "name": "Cloudfloor (Cloudfloor DNS)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "CloudfloorDNS(.WAF)?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>CloudfloorDNS.{0,6}?Web Application Firewall Error"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.cloudfloordns\\.com/contact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "cloudfront": {
    "name": "Cloudfront (Amazon)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Cloudfront",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "via",
        "pattern": "([0-9\\.]+?)? \\w+?\\.cloudfront\\.net \\(Cloudfront\\)",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-amz-cf-id",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-cache",
        "pattern": "Error from Cloudfront",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Generated by cloudfront \\(CloudFront\\)"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "cloudprotector": {
    "name": "Cloud Protector (Rohde & Schwarz CyberSecurity)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Cloud Protector.*?by Rohde.{3,8}?Schwarz Cybersecurity"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<a href='https?:\\/\\/(?:www\\.)?cloudprotector\\.com\\/'>R.{1,6}?S.Cloud Protector"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "comodo": {
    "name": "Comodo cWatch (Comodo CyberSecurity)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Protected by COMODO WAF(.+)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "crawlprotect": {
    "name": "CrawlProtect (Jean-Denis Brun)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^crawlprotecttag="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>crawlprotect"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "this site is protected by crawlprotect"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "ddosguard": {
    "name": "DDoS-GUARD (DDOS-GUARD CORP.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^__ddg1.*?="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^__ddg2.*?="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^__ddgid.*?="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^__ddgmark.*?="
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ddos-guard",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "denyall": {
    "name": "DenyALL (Rohde & Schwarz CyberSecurity)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "status",
        "tier": "block_page",
        "status": 200
      },
      {
        "signal": "reason",
        "tier": "block_page",
        "value": "Condition Intercepted"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "distil": {
    "name": "Distil (Distil Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cdn\\.distilnetworks\\.com/images/anomaly\\.detected\\.png"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "distilCaptchaForm"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "distilCallbackGuard"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "dosarrest": {
    "name": "DOSarrest (DOSarrest Internet Security)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-dis-request-id",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "DOSarrest(.*)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "dotdefender": {
    "name": "DotDefender (Applicure Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-dotdefender-denied",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "dotdefender blocked your request"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Applicure is the leading provider of web application security"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "dynamicweb": {
    "name": "DynamicWeb Injection Check (DynamicWeb)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-403-status-by",
        "pattern": "dw.inj.check",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "by dynamic check(.{0,10}?module)?"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "edgecast": {
    "name": "Edgecast (Verizon Digital Media)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "^ECD(.+)?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "^ECS(.*)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "eisoo": {
    "name": "Eisoo Cloud Firewall (Eisoo)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "EisooWAF(\\-AZURE)?/?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<link.{0,10}?href=\\\"/eisoo\\-firewall\\-block\\.css"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.eisoo\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "&copy; \\d{4} Eisoo Inc"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "envoy": {
    "name": "Envoy (EnvoyProxy)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "envoy",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-upstream-service-time",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-downstream-service-cluster",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-downstream-service-node",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-external-address",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-force-trace",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-internal",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-original-dst-host",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-original-path",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-envoy-local-overloaded",
        "pattern": ".+",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "if",
                    "condition": {
                      "op": "signal",
                      "id": 7
                    },
                    "then": {
                      "op": "const",
                      "value": true
                    },
                    "else": {
                      "op": "if",
                      "condition": {
                        "op": "signal",
                        "id": 8
                      },
                      "then": {
                        "op": "const",
                        "value": true
                      },
                      "else": {
                        "op": "if",
                        "condition": {
                          "op": "signal",
                          "id": 9
                        },
                        "then": {
                          "op": "const",
                          "value": true
                        },
                        "else": {
                          "op": "const",
                          "value": false
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "expressionengine": {
    "name": "Expression Engine (EllisLab)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^exp_track.+?="
      },
      {
        "signal": "cookie",
        "tier": "block_page",
        "pattern": "^exp_last_.+?="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "invalid get data"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "f5bigipapm": {
    "name": "BIG-IP AP Manager (F5 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^LastMRH_Session"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^MRHSession"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^MRHSession"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "server",
        "pattern": "Big([-_])?IP",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^F5_fullWT"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^F5_fullWT"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^F5_HT_shrinked"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 4
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 5
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 6
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "const",
                  "value": false
                }
              }
            }
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "f5bigipasm": {
    "name": "BIG-IP AppSec Manager (F5 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "the requested url was rejected"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "please consult with your administrator"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "TS[a-fA-F0-9]{8}=.+"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "TS[a-fA-F0-9]{6}=.+"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 2
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 3
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "f5bigipltm": {
    "name": "BIG-IP Local Traffic Manager (F5 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^bigipserver"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-cnection",
        "pattern": "close",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "f5firepass": {
    "name": "FirePass (F5 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^VHOST"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "location",
        "pattern": "\\/my\\.logon\\.php3",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^F5_fire.+?"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^F5_passid_shrinked"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "f5trafficshield": {
    "name": "Trafficshield (F5 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^ASINFO="
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "F5-TrafficShield",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "fastly": {
    "name": "Fastly (Fastly CDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-fastly-request-id",
        "pattern": "\\w+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-served-by",
        "pattern": "^cache-[a-z]{3}\\d+-[A-Z]{3}",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "fortigate": {
    "name": "FortiGate (Fortinet)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "//globalurl.fortinet.net"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "FortiGate Application Control"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Web Application Firewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Event ID"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "//globalurl.fortinet.net"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "fortiguard": {
    "name": "FortiGuard (Fortinet)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "FortiGuard Intrusion Prevention"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "//globalurl.fortinet.net"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "fortiweb": {
    "name": "FortiWeb (Fortinet)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^FORTIWAFSID="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": ".fgd_icon"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "fgd_icon"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "web.page.blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "url"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "attack.id"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "message.id"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "client.ip"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "not",
                  "arg": {
                    "op": "signal",
                    "id": 5
                  }
                },
                "then": {
                  "op": "const",
                  "value": false
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "not",
                    "arg": {
                      "op": "signal",
                      "id": 6
                    }
                  },
                  "then": {
                    "op": "const",
                    "value": false
                  },
                  "else": {
                    "op": "if",
                    "condition": {
                      "op": "not",
                      "arg": {
                        "op": "signal",
                        "id": 7
                      }
                    },
                    "then": {
                      "op": "const",
                      "value": false
                    },
                    "else": {
                      "op": "const",
                      "value": true
                    }
                  }
                }
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "frontdoor": {
    "name": "Azure Front Door (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-azure-ref",
        "pattern": ".+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "gcparmor": {
    "name": "Google Cloud App Armor (Google Cloud)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "via",
        "pattern": "1.1 google",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "godaddy": {
    "name": "GoDaddy Website Protection (GoDaddy)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "GoDaddy (security|website firewall)"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "greywizard": {
    "name": "Greywizard (Grey Wizard)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "greywizard",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>Grey Wizard"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "contact the website owner or Grey Wizard"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "We.ve detected attempted attack or non standard traffic from your ip address"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "huaweicloud": {
    "name": "Huawei Cloud Firewall (Huawei)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^HWWAFSESID="
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "HuaweiCloudWAF",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "hwclouds\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "hws_security@"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "hyperguard": {
    "name": "HyperGuard (Art of Defense)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^WODSESSION="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "ibmdatapower": {
    "name": "DataPower (IBM)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-backside-transport",
        "pattern": "(OK|FAIL)",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "imunify360": {
    "name": "Imunify360 (CloudLinux)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "imunify360.{0,10}?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "protected.by.{0,10}?imunify360"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "powered.by.{0,10}?imunify360"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "imunify360.preloader"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "incapsula": {
    "name": "Incapsula (Imperva Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^incap_ses.*?="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^visid_incap.*?="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "incapsula incident id"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "powered by incapsula"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/_Incapsula_Resource"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "indusguard": {
    "name": "IndusGuard (Indusface)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "IF_WAF",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This website is secured against online attacks. Your request was blocked"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "instartdx": {
    "name": "Instart DX (Instart Logic)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-instart-request-id",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-instart-cache",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-instart-wl",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "the requested url was rejected"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "please consult with your administrator"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "your support id is"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 2
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 3
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 4
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 5
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "isaserver": {
    "name": "ISA Server (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "The.{0,10}?(isa.)?server.{0,10}?denied the specified uniform resource locator \\(url\\)"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "janusec": {
    "name": "Janusec Application Gateway (Janusec)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "janusec application gateway"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "jiasule": {
    "name": "Jiasule (Jiasule)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "jiasule\\-waf",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^jsl_tracking(.+)?="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "__jsluid="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "notice\\-jiasule"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "static\\.jiasule\\.com"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "kemp": {
    "name": "Kemp LoadMaster (Progress Software)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-servedby",
        "pattern": "KEMP-LM",
        "header_kind": "exact"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>403 Forbidden</title>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "and",
        "args": [
          {
            "op": "signal",
            "id": 0
          },
          {
            "op": "signal",
            "id": 1
          },
          {
            "op": "signal",
            "id": 2
          }
        ]
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "keycdn": {
    "name": "KeyCDN (KeyCDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "KeyCDN",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "knownsec": {
    "name": "KS-WAF (KnownSec)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/ks[-_]waf[-_]error\\.png"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "kona": {
    "name": "Kona SiteDefender (Akamai)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "AkamaiGHost",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "server",
        "pattern": "AkamaiGHost",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "limelight": {
    "name": "LimeLight CDN (LimeLight)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^limelight"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^l[mg]_sessid="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "link11": {
    "name": "Link11 WAAP (Link11)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "rhino-core-shield",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "litespeed": {
    "name": "LiteSpeed (LiteSpeed Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "LiteSpeed",
        "header_kind": "exact"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Proudly powered by litespeed web server"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.litespeedtech\\.com/error\\-page"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "malcare": {
    "name": "Malcare (Inactiv)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "firewall.{0,15}?powered.by.{0,15}?malcare.{0,15}?pro"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "blocked because of malicious activities"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "maxcdn": {
    "name": "MaxCDN (MaxCDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cdn",
        "pattern": "maxcdn",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "missioncontrol": {
    "name": "Mission Control Shield (Mission Control)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Mission Control Application Shield",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "modsecurity": {
    "name": "ModSecurity (SpiderLabs)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "(mod_security|Mod_Security|NOYB)",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This error was generated by Mod.?Security"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "rules of the mod.security.module"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "mod.security.rules triggered"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Protected by Mod.?Security"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/modsecurity[\\-_]errorpage/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "modsecurity iis"
      },
      {
        "signal": "reason",
        "tier": "block_page",
        "value": "ModSecurity Action"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "reason",
        "tier": "block_page",
        "value": "ModSecurity Action"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 406
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 2
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 3
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 4
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 5
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "if",
                    "condition": {
                      "op": "signal",
                      "id": 6
                    },
                    "then": {
                      "op": "const",
                      "value": true
                    },
                    "else": {
                      "op": "const",
                      "value": false
                    }
                  }
                }
              }
            }
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 7
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 8
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 9
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 10
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "naxsi": {
    "name": "NAXSI (NBS Systems)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-data-origin",
        "pattern": "^naxsi(.+)?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "naxsi(.+)?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "blocked by naxsi"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "naxsi blocked information"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "nemesida": {
    "name": "Nemesida (PentestIt)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "@?nemesida(\\-security)?\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Suspicious activity detected.{0,10}?Access to the site is blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "nwaf@"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 222
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "netcontinuum": {
    "name": "NetContinuum (Barracuda Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^NCI__SessionId="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "netscaler": {
    "name": "NetScaler AppFirewall (Citrix Systems)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "via",
        "pattern": "NS\\-CACHE",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^(ns_af=|citrix_ns_id|NSC_)"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "(NS Transaction|AppFW Session) id"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Violation Category.{0,5}?APPFW_"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Citrix\\|NetScaler"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "cneonction",
        "pattern": "^(keep alive|close)",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "nncoection",
        "pattern": "^(keep alive|close)",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "const",
                    "value": false
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "nevisproxy": {
    "name": "NevisProxy (AdNovum)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^Navajo"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^NP_ID"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "newdefend": {
    "name": "Newdefend (NewDefend)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Newdefend",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.newdefend\\.com/feedback"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/nd\\-block/"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "nexusguard": {
    "name": "NexusGuard Firewall (NexusGuard)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Powered by Nexusguard"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "nexusguard\\.com/wafpage/.+#\\d{3};"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "ninja": {
    "name": "NinjaFirewall (NinTechNet)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>NinjaFirewall.{0,10}?\\d{3}.forbidden"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "For security reasons?.{0,10}?it was blocked and logged"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "nsfocus": {
    "name": "NSFocus (NSFocus Global Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "NSFocus",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "nullddos": {
    "name": "NullDDoS Protection (NullDDoS)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "NullDDoS(.System)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "onmessage": {
    "name": "OnMessage Shield (BlackBaud)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-engine",
        "pattern": "onMessage Shield",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Blackbaud K\\-12 conducts routine maintenance"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "onMessage SHEILD"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "maintenance\\.blackbaud\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "status\\.blackbaud\\.com"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "openresty": {
    "name": "Open-Resty Lua Nginx (FLOSS)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "^openresty/[0-9\\.]+?",
        "header_kind": "exact"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "openresty/[0-9\\.]+?"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 406
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "oraclecloud": {
    "name": "Oracle Cloud (Oracle)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>fw_error_www"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "src=\\\"/oralogo_small\\.gif\\\""
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.oracleimg\\.com/us/assets/metrics/ora_ocom\\.js"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "paloalto": {
    "name": "Palo Alto Next Gen Firewall (Palo Alto Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Download of virus.spyware blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Palo Alto Next Generation Security Platform"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "panyun360": {
    "name": "360PanYun (360 Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "panyun",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-panyun-request-id",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-panyun-error-reason",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-panyun-error-step",
        "pattern": ".+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "pentawaf": {
    "name": "PentaWAF (Global Network Services)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "PentaWaf(/[0-9\\.]+)?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Penta.?Waf/[0-9\\.]+?.server"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "perimeterx": {
    "name": "PerimeterX (PerimeterX)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.perimeterx\\.(com|net)/whywasiblocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "client\\.perimeterx\\.(net|com)"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "denied because we believe you are using automation tools"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "pksec": {
    "name": "pkSecurity IDS (pkSec)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "pk.?Security.?Module"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Security.Alert"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "As this could be a potential hack attack"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "A safety critical (call|request) was (detected|discovered) and blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "maximum number of reloads per minute and prevented access"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "powercdn": {
    "name": "PowerCDN (PowerCDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "via",
        "pattern": "(.*)?powercdn.com(.*)?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cache",
        "pattern": "(.*)?powercdn.com(.*)?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cdn",
        "pattern": "PowerCDN",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "profense": {
    "name": "Profense (ArmorLogic)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Profense",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^PLBSID="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "ptaf": {
    "name": "PT Application Firewall (Positive Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<h1.{0,10}?Forbidden"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<pre>Request.ID:.{0,10}?\\d{4}\\-(\\d{2})+.{0,35}?pre>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "puhui": {
    "name": "Puhui (Puhui)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Puhui[\\-_]?WAF",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "qcloud": {
    "name": "Qcloud (Tencent Cloud)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "腾讯云Web应用防火墙"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "qiniu": {
    "name": "Qiniu (Qiniu CDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-qiniu-cdn",
        "pattern": "\\d+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "qrator": {
    "name": "Qrator (Qrator)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "QRATOR",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "radware": {
    "name": "AppWall (Radware)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "CloudWebSec\\.radware\\.com"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-sl-compstate",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "because we have detected unauthorized activity"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Unauthorized Request Blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "if you believe that there has been some mistake"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "\\?Subject=Security Page.{0,10}?Case Number"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "not",
                  "arg": {
                    "op": "signal",
                    "id": 5
                  }
                },
                "then": {
                  "op": "const",
                  "value": false
                },
                "else": {
                  "op": "const",
                  "value": true
                }
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "reblaze": {
    "name": "Reblaze (Reblaze)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^rbzid"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Reblaze Secure Web Gateway",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "current session has been terminated"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "do not hesitate to contact us"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "access denied \\(\\d{3}\\)"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "reflected": {
    "name": "Reflected Networks (Reflected Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<img class=\"logo loader\" src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAbgAAABHCAIAAAD6G8WcAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyRpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "content=\"Request is denied\""
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Forbidden</title>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "and",
        "args": [
          {
            "op": "signal",
            "id": 0
          },
          {
            "op": "signal",
            "id": 1
          },
          {
            "op": "signal",
            "id": 2
          },
          {
            "op": "signal",
            "id": 3
          }
        ]
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "rsfirewall": {
    "name": "RSFirewall (RSJoomla!)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "com_rsfirewall_(\\d{3}_forbidden|event)?"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "rvmode": {
    "name": "RequestValidationMode (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Request Validation has detected a potentially dangerous client input"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "ASP\\.NET has detected data in the request"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "HttpRequestValidationException"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "sabre": {
    "name": "Sabre Firewall (Sabre)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "dxsupport\\.sabre\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Application Firewall Error"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "add some important details to the email for us to investigate"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 2
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "safe3": {
    "name": "Safe3 Web Firewall (Safe3)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Safe3 Web Firewall",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-powered-by",
        "pattern": "Safe3WAF/[\\.0-9]+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Safe3waf/[0-9\\.]+?"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "safedog": {
    "name": "Safedog (SafeDog)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^safedog\\-flow\\-item="
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Safedog",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "safedogsite/broswer_logo\\.jpg"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "404\\.safedog\\.cn/sitedog_stat.html"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "404\\.safedog\\.cn/images/safedogsite/head\\.png"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "const",
                "value": false
              }
            }
          }
        }
      }
    }
  },
  "safeline": {
    "name": "Safeline (Chaitin Tech.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "safeline|<!\\-\\-\\sevent id:"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "scutum": {
    "name": "Scutum (Secure Sky Technology Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Scutum",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "secking": {
    "name": "SecKing (SecKing)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "secking(.?waf)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "secupress": {
    "name": "SecuPress WP Security (SecuPress)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>SecuPress"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "secureentry": {
    "name": "Secure Entry (United Security Providers)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Secure Entry Server",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "secureiis": {
    "name": "eEye SecureIIS (BeyondTrust)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "SecureIIS is an internet security application"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Download SecureIIS Personal Edition"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "https?://www\\.eeye\\.com/Secure\\-?IIS"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "securesphere": {
    "name": "SecureSphere (Imperva Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h2)>Error"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "The incident ID is"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This page can't be displayed"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Contact support for additional information"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        }
      }
    }
  },
  "senginx": {
    "name": "SEnginx (Neusoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "SENGINX\\-ROBOT\\-MITIGATION"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "serverdefender": {
    "name": "ServerDefender VP (Port80 Software)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-pint",
        "pattern": "p(ort\\-)?80",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "shadowd": {
    "name": "Shadow Daemon (Zecure)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<h\\d{1}>\\d{3}.forbidden<.h\\d{1}>"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "request forbidden by administrative rules"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "shieldon": {
    "name": "Shieldon Firewall (Shieldon.io)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Please solve CAPTCHA"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "shieldon_captcha"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Unusual behavior detected"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "status-user-info"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access denied"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "The IP address you are using has been blocked."
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "status-user-info"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Please line up"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This page is limiting the number of people online. Please wait a moment."
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "[Xx]-[Pp]rotected-[Bb]y",
        "pattern": "shieldon.io",
        "header_kind": "regex"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 2
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 3
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 4
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 5
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 6
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 7
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 8
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 9
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "shieldsecurity": {
    "name": "Shield Security (One Dollar Plugin)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "You were blocked by the Shield"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "remaining transgression\\(s\\) against this site"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Something in the URL.{0,5}?Form or Cookie data wasn\\'t appropriate"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "siteground": {
    "name": "SiteGround (SiteGround)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Our system thinks you might be a robot!"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "access is restricted due to a security rule"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "siteguard": {
    "name": "SiteGuard (EG Secure Solutions Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Powered by SiteGuard"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "The server refuse to browse the page"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "sitelock": {
    "name": "Sitelock (TrueShield)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "SiteLock will remember you"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Sitelock is leader in Business Website Security Services"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "sitelock[_\\-]shield([_\\-]logo|[\\-_]badge)?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "SiteLock incident ID"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "sonicwall": {
    "name": "SonicWall (Dell)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "SonicWALL",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>Web Site Blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "\\+?nsa_banner"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "sophos": {
    "name": "UTM Web Protection (Sophos)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.sophos\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Powered by.?(Sophos)? UTM Web Protection"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Access to the requested URL was blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access to the requested URL was blocked"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "incident was logged with the following log identifier"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Inbound Anomaly Score exceeded"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Your cache administrator is"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 4
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "not",
                  "arg": {
                    "op": "signal",
                    "id": 5
                  }
                },
                "then": {
                  "op": "const",
                  "value": false
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "not",
                    "arg": {
                      "op": "signal",
                      "id": 6
                    }
                  },
                  "then": {
                    "op": "const",
                    "value": false
                  },
                  "else": {
                    "op": "const",
                    "value": true
                  }
                }
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "squarespace": {
    "name": "Squarespace (Squarespace)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Squarespace",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^SS_ANALYTICS_ID="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^SS_MATTR="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^SS_MID="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "SS_CVT="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "status\\.squarespace\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "BRICK\\-\\d{2}"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "const",
                    "value": false
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "squidproxy": {
    "name": "SquidProxy IDS (SquidProxy)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "squid(/[0-9\\.]+)?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access control configuration prevents your request"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "not",
        "arg": {
          "op": "signal",
          "id": 0
        }
      },
      "then": {
        "op": "const",
        "value": false
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 1
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "const",
          "value": true
        }
      }
    }
  },
  "stackpath": {
    "name": "StackPath (StackPath)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>StackPath[^<]+</title>"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Protected by <a href=\"https?:\\/\\/(?:www\\.)?stackpath\\.com\\/\"[^>]+>StackPath"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "is using a security service for protection against online attacks"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "An action has triggered the service and blocked your request"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "sucuri": {
    "name": "Sucuri CloudProxy (Sucuri Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-sucuri-id",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-sucuri-cache",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Sucuri(\\-Cloudproxy)?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "x-sucuri-block",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access Denied.{0,6}?Sucuri Website Firewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Sucuri WebSite Firewall.{0,6}?(CloudProxy)?.{0,6}?Access Denied"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "sucuri\\.net/privacy\\-policy"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cdn\\.sucuri\\.net/sucuri[-_]firewall[-_]block\\.css"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cloudproxy@sucuri\\.net"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "if",
                    "condition": {
                      "op": "signal",
                      "id": 7
                    },
                    "then": {
                      "op": "const",
                      "value": true
                    },
                    "else": {
                      "op": "if",
                      "condition": {
                        "op": "signal",
                        "id": 8
                      },
                      "then": {
                        "op": "const",
                        "value": true
                      },
                      "else": {
                        "op": "const",
                        "value": false
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "tencent": {
    "name": "Tencent Cloud Firewall (Tencent Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "waf\\.tencent\\-?cloud\\.com/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "window\\.location\\.href.{1,3}?https?://waf.tencent(?:-?cloud)?.com/(?:403|501)page\\.html"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "teros": {
    "name": "Teros (Citrix Systems)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^st8id="
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "threatx": {
    "name": "ThreatX (A10 Networks)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-request-id",
        "pattern": ".*",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "^Forbidden - ID: ([a-fA-F0-9]{32})$"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "and",
        "args": [
          {
            "op": "signal",
            "id": 0
          },
          {
            "op": "signal",
            "id": 1
          },
          {
            "op": "signal",
            "id": 2
          }
        ]
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "transip": {
    "name": "TransIP Web Firewall (TransIP)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-transip-backend",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-transip-balancer",
        "pattern": ".+",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "uewaf": {
    "name": "UEWaf (UCloud)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "uewaf(/[0-9\\.]+)?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/uewaf_deny_pages/default/img/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "ucloud\\.cn"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "urlmaster": {
    "name": "URLMaster SecurityCheck (iFinity/DotNetNuke)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-urlmaster-debug",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-urlmaster-ex",
        "pattern": ".+",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Ur[li]RewriteModule"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "SecurityCheck"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 0
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 1
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "urlscan": {
    "name": "URLScan (Microsoft)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Rejected[-_]By[_-]UrlScan"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "A custom filter or module.{0,4}?such as URLScan"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "variti": {
    "name": "Variti (Variti)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Variti(?:\\/[a-z0-9\\.\\-]+)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "varnish": {
    "name": "Varnish (OWASP)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Request rejected by xVarnish\\-WAF"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "vercel": {
    "name": "Vercel WAF (Vercel)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<title>Vercel Security Checkpoint</title>"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/vercel/security/"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "viettel": {
    "name": "Viettel (Cloudrity)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access Denied.{0,10}?Viettel WAF"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cloudrity\\.com\\.(vn)?/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Viettel WAF System"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "virusdie": {
    "name": "VirusDie (VirusDie LLC)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "cdn\\.virusdie\\.ru/splash/firewallstop\\.png"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "copy.{0,10}?Virusdie\\.ru"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "wallarm": {
    "name": "Wallarm (Wallarm Inc.)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "nginx[\\-_]wallarm",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "watchguard": {
    "name": "WatchGuard (WatchGuard Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "WatchGuard",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Request denied by WatchGuard Firewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "WatchGuard Technologies Inc\\."
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "webarx": {
    "name": "WebARX (WebARX Security Solutions)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "WebARX.{0,10}?Web Application Firewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.webarxsecurity\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/wp\\-content/plugins/webarx/includes/"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "webknight": {
    "name": "WebKnight (AQTRONIX)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "status",
        "tier": "block_page",
        "status": 999
      },
      {
        "signal": "reason",
        "tier": "block_page",
        "value": "No Hacking"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 404
      },
      {
        "signal": "reason",
        "tier": "block_page",
        "value": "Hack Not Found"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "WebKnight Application Firewall Alert"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "What is webknight\\?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "AQTRONIX WebKnight is an application firewall"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "WebKnight will take over and protect"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "aqtronix\\.com/WebKnight"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "AQTRONIX.{0,10}?WebKnight"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "const",
            "value": true
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 2
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 3
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "const",
              "value": true
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 4
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 5
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 6
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 7
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "if",
                    "condition": {
                      "op": "signal",
                      "id": 8
                    },
                    "then": {
                      "op": "const",
                      "value": true
                    },
                    "else": {
                      "op": "if",
                      "condition": {
                        "op": "signal",
                        "id": 9
                      },
                      "then": {
                        "op": "const",
                        "value": true
                      },
                      "else": {
                        "op": "const",
                        "value": false
                      }
                    }
                  }
                }
              }
            }
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "webland": {
    "name": "WebLand (WebLand)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "protected by webland",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "webray": {
    "name": "RayWAF (WebRay Solutions)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "WebRay\\-WAF",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "drivedby",
        "pattern": "RaySrv.RayEng/[0-9\\.]+?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "webseal": {
    "name": "WebSEAL (IBM)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "WebSEAL",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This is a WebSEAL error message template file"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "WebSEAL server received an invalid HTTP request"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "webtotem": {
    "name": "WebTotem (WebTotem)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "The current request was blocked.{0,8}?>WebTotem"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "west263cdn": {
    "name": "West263 CDN (West263CDN)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cache",
        "pattern": "WS?T263CDN",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "const",
        "value": false
      }
    }
  },
  "wordfence": {
    "name": "Wordfence (Defiant)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "wf[_\\-]?WAF",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Generated by Wordfence"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "broke one of (the )?Wordfence (advanced )?blocking rules"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/plugins/wordfence"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "const",
              "value": false
            }
          }
        }
      }
    }
  },
  "wpmudev": {
    "name": "wpmudev WAF (Incsub)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "href=\"http(s)?.\\/\\/wpmudev.com\\/.{0,15}?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Click on the Logs tab, then the WAF Log."
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Choose your site from the list"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<h1>Whoops, this request has been blocked!"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "This request has been deemed suspicious"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "possible attack on our servers."
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 403
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "if",
        "condition": {
          "op": "not",
          "arg": {
            "op": "signal",
            "id": 0
          }
        },
        "then": {
          "op": "const",
          "value": false
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 1
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 2
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 3
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "const",
                "value": true
              }
            }
          }
        }
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "if",
          "condition": {
            "op": "not",
            "arg": {
              "op": "signal",
              "id": 4
            }
          },
          "then": {
            "op": "const",
            "value": false
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "not",
              "arg": {
                "op": "signal",
                "id": 5
              }
            },
            "then": {
              "op": "const",
              "value": false
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "not",
                "arg": {
                  "op": "signal",
                  "id": 6
                }
              },
              "then": {
                "op": "const",
                "value": false
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "not",
                  "arg": {
                    "op": "signal",
                    "id": 7
                  }
                },
                "then": {
                  "op": "const",
                  "value": false
                },
                "else": {
                  "op": "const",
                  "value": true
                }
              }
            }
          }
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "wts": {
    "name": "WTS-WAF (WTS)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "wts/[0-9\\.]+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "<(title|h\\d{1})>WTS\\-WAF"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "wzb360": {
    "name": "360WangZhanBao (360 Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "qianxin\\-waf",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "wzws-ray",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-powered-by-360wzb",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "wzws\\-waf\\-cgi/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "wangshan\\.360\\.cn"
      },
      {
        "signal": "status",
        "tier": "block_page",
        "status": 493
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "const",
                  "value": false
                }
              }
            }
          }
        }
      }
    }
  },
  "xlabssecuritywaf": {
    "name": "XLabs Security WAF (XLabs)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cdn",
        "pattern": "XLabs Security",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "secured",
        "pattern": "^By XLabs Security",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "block_page",
        "header": "server",
        "pattern": "XLabs[-_]?.?WAF",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "xuanwudun": {
    "name": "Xuanwudun (Xuanwudun)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "admin\\.dbappwaf\\.cn/(index\\.php/Admin/ClientMisinform/)?"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "class=.(db[\\-_]?)?waf(.)?([\\-_]?row)?>"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "yundun": {
    "name": "Yundun (Yundun)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "YUNDUN",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-cache",
        "pattern": "YUNDUN",
        "header_kind": "exact"
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^yd_cookie="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Blocked by YUNDUN Cloud WAF"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "yundun\\.com/yd[-_]http[_-]error/"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "www\\.yundun\\.com/(static/js/fingerprint\\d{1}?\\.js)?"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "const",
                  "value": false
                }
              }
            }
          }
        }
      }
    }
  },
  "yunsuo": {
    "name": "Yunsuo (Yunsuo)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^yunsuo_session="
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "class=\\\"yunsuologo\\\""
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "const",
          "value": false
        }
      }
    }
  },
  "yxlink": {
    "name": "YXLink (YxLink Technologies)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^yx_ci_session="
      },
      {
        "signal": "cookie",
        "tier": "passive",
        "pattern": "^yx_language="
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "Yxlink([\\-_]?WAF)?",
        "header_kind": "exact"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "zenedge": {
    "name": "Zenedge (Zenedge)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ZENEDGE",
        "header_kind": "exact"
      },
      {
        "signal": "header",
        "tier": "passive",
        "header": "x-zen-fury",
        "pattern": ".+?",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "/__zenedge/"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "const",
            "value": false
          }
        }
      }
    }
  },
  "zscaler": {
    "name": "ZScaler (Accenture)",
    "port_status": "supported",
    "signatures": [
      {
        "signal": "header",
        "tier": "passive",
        "header": "server",
        "pattern": "ZScaler",
        "header_kind": "exact"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Access Denied.{0,10}?Accenture Policy"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "policies\\.accenture\\.com"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "login\\.zscloud\\.net/img_logo_new1\\.png"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Zscaler to protect you from internet threats"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Internet Security by ZScaler"
      },
      {
        "signal": "content",
        "tier": "block_page",
        "pattern": "Accenture.{0,10}?webfilters indicate that the site likely contains"
      }
    ],
    "matcher": {
      "op": "if",
      "condition": {
        "op": "signal",
        "id": 0
      },
      "then": {
        "op": "const",
        "value": true
      },
      "else": {
        "op": "if",
        "condition": {
          "op": "signal",
          "id": 1
        },
        "then": {
          "op": "const",
          "value": true
        },
        "else": {
          "op": "if",
          "condition": {
            "op": "signal",
            "id": 2
          },
          "then": {
            "op": "const",
            "value": true
          },
          "else": {
            "op": "if",
            "condition": {
              "op": "signal",
              "id": 3
            },
            "then": {
              "op": "const",
              "value": true
            },
            "else": {
              "op": "if",
              "condition": {
                "op": "signal",
                "id": 4
              },
              "then": {
                "op": "const",
                "value": true
              },
              "else": {
                "op": "if",
                "condition": {
                  "op": "signal",
                  "id": 5
                },
                "then": {
                  "op": "const",
                  "value": true
                },
                "else": {
                  "op": "if",
                  "condition": {
                    "op": "signal",
                    "id": 6
                  },
                  "then": {
                    "op": "const",
                    "value": true
                  },
                  "else": {
                    "op": "const",
                    "value": false
                  }
                }
              }
            }
          }
        }
      }
    }
  }
});

/** CDN provider address ranges (cdncheck sources_data.json `cdn`). */
export const CDN_ADDRESS_RANGES = Object.freeze({
  "arvancloud": [
    "178.131.120.48/28",
    "185.143.232.0/22",
    "185.215.232.0/22",
    "188.229.116.16/30",
    "2.144.3.128/28",
    "37.32.16.0/27",
    "37.32.17.0/27",
    "37.32.18.0/27",
    "37.32.19.0/27",
    "78.157.36.112/28",
    "94.101.182.0/27",
    "94.101.183.0/28",
    "95.38.61.80/28"
  ],
  "cafe24": [
    "14.128.128.0/17"
  ],
  "cdnetworks": [
    "101.79.144.0/20",
    "101.79.160.0/20",
    "101.79.208.0/20",
    "101.79.224.0/20",
    "103.248.104.0/22",
    "114.111.48.0/20",
    "116.193.80.0/20",
    "118.107.160.0/20",
    "119.31.248.0/21",
    "14.0.32.0/19",
    "14.0.64.0/21",
    "14.0.72.0/22",
    "14.0.76.0/23",
    "14.0.80.0/20",
    "14.0.96.0/19",
    "175.41.0.0/20",
    "211.43.144.0/20",
    "61.110.192.0/19",
    "61.110.224.0/20",
    "61.110.240.0/21",
    "61.110.248.0/22",
    "61.110.252.0/23",
    "61.110.254.0/24"
  ],
  "cloudfront": [
    "108.138.0.0/15",
    "108.156.0.0/14",
    "111.13.171.128/26",
    "111.13.171.192/26",
    "111.13.185.32/27",
    "111.13.185.64/27",
    "116.129.226.0/25",
    "116.129.226.128/26",
    "118.193.97.128/25",
    "118.193.97.64/26",
    "119.147.182.0/25",
    "119.147.182.128/26",
    "120.232.236.0/25",
    "120.232.236.128/26",
    "120.253.240.192/26",
    "120.253.241.160/27",
    "120.253.245.128/26",
    "120.253.245.192/27",
    "120.52.12.64/26",
    "120.52.153.192/26",
    "120.52.22.96/27",
    "120.52.39.128/27",
    "13.113.196.64/26",
    "13.113.203.0/24",
    "13.124.199.0/24",
    "13.134.24.0/23",
    "13.134.94.0/23",
    "13.203.133.0/26",
    "13.210.67.128/26",
    "13.224.0.0/14",
    "13.228.69.0/24",
    "13.233.177.192/26",
    "13.249.0.0/16",
    "13.32.0.0/15",
    "13.35.0.0/16",
    "13.54.63.128/26",
    "13.59.250.0/26",
    "130.176.0.0/17",
    "130.176.128.0/18",
    "130.176.192.0/19",
    "130.176.224.0/20",
    "143.204.0.0/16",
    "144.220.0.0/16",
    "15.158.0.0/16",
    "15.188.184.0/24",
    "15.207.13.128/25",
    "15.207.213.128/25",
    "18.154.0.0/15",
    "18.160.0.0/15",
    "18.164.0.0/15",
    "18.172.0.0/15",
    "18.175.65.0/24",
    "18.175.66.0/24",
    "18.175.67.0/24",
    "18.192.142.0/23",
    "18.199.68.0/22",
    "18.199.72.0/22",
    "18.199.76.0/22",
    "18.200.212.0/23",
    "18.216.170.128/25",
    "18.229.220.192/26",
    "18.230.229.0/24",
    "18.230.230.0/25",
    "18.238.0.0/15",
    "18.244.0.0/15",
    "18.64.0.0/14",
    "18.68.0.0/16",
    "180.163.57.0/25",
    "180.163.57.128/26",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "204.246.172.0/24",
    "204.246.173.0/24",
    "204.246.174.0/23",
    "204.246.176.0/20",
    "205.251.202.0/23",
    "205.251.204.0/23",
    "205.251.206.0/23",
    "205.251.208.0/20",
    "205.251.249.0/24",
    "205.251.250.0/23",
    "205.251.252.0/23",
    "205.251.254.0/24",
    "216.137.32.0/19",
    "23.228.212.0/24",
    "23.228.213.0/24",
    "23.228.214.0/24",
    "23.228.220.0/24",
    "23.228.221.0/24",
    "23.228.222.0/24",
    "23.228.223.0/24",
    "23.228.244.0/24",
    "23.228.246.0/24",
    "23.228.247.0/24",
    "23.228.248.0/24",
    "23.228.249.0/24",
    "23.228.250.0/24",
    "23.228.251.0/24",
    "23.234.192.0/18",
    "23.91.0.0/19",
    "24.110.128.0/17",
    "24.110.32.0/19",
    "3.10.17.128/25",
    "3.101.158.0/23",
    "3.107.43.128/25",
    "3.107.44.0/25",
    "3.107.44.128/25",
    "3.11.53.0/24",
    "3.128.93.0/24",
    "3.134.215.0/24",
    "3.146.232.0/22",
    "3.147.164.0/22",
    "3.147.244.0/22",
    "3.160.0.0/14",
    "3.164.0.0/18",
    "3.164.128.0/17",
    "3.164.64.0/18",
    "3.165.0.0/16",
    "3.166.0.0/15",
    "3.168.0.0/14",
    "3.172.0.0/18",
    "3.172.64.0/18",
    "3.173.0.0/17",
    "3.173.128.0/18",
    "3.173.192.0/18",
    "3.174.0.0/15",
    "3.231.2.0/25",
    "3.234.232.224/27",
    "3.236.169.192/26",
    "3.236.48.0/23",
    "3.29.40.128/26",
    "3.29.40.192/26",
    "3.29.40.64/26",
    "3.29.57.0/26",
    "3.35.130.128/25",
    "34.195.252.0/24",
    "34.216.51.0/25",
    "34.223.12.224/27",
    "34.223.80.192/26",
    "34.226.14.0/24",
    "35.158.136.0/24",
    "35.162.63.192/26",
    "35.167.191.128/26",
    "35.93.168.0/23",
    "35.93.170.0/23",
    "35.93.172.0/23",
    "36.103.232.0/25",
    "36.103.232.128/26",
    "43.218.56.128/26",
    "43.218.56.192/26",
    "43.218.56.64/26",
    "43.218.71.0/26",
    "44.220.194.0/23",
    "44.220.196.0/23",
    "44.220.198.0/23",
    "44.220.200.0/23",
    "44.220.202.0/23",
    "44.222.66.0/24",
    "44.227.178.0/24",
    "44.234.108.128/25",
    "44.234.90.252/30",
    "47.129.82.0/24",
    "47.129.83.0/24",
    "47.129.84.0/24",
    "51.44.234.0/23",
    "51.44.236.0/23",
    "51.44.238.0/23",
    "51.74.192.0/18",
    "52.124.128.0/17",
    "52.15.127.128/26",
    "52.199.127.192/26",
    "52.212.248.0/26",
    "52.220.191.0/26",
    "52.222.128.0/17",
    "52.46.0.0/18",
    "52.47.139.0/24",
    "52.52.191.128/26",
    "52.56.127.0/25",
    "52.57.254.0/24",
    "52.66.194.128/26",
    "52.78.247.128/26",
    "52.82.128.0/19",
    "52.84.0.0/15",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/17",
    "54.230.128.0/18",
    "54.230.200.0/21",
    "54.230.208.0/20",
    "54.230.224.0/19",
    "54.233.255.128/26",
    "54.239.128.0/18",
    "54.239.192.0/19",
    "54.240.128.0/18",
    "56.125.46.0/24",
    "56.125.47.0/32",
    "56.125.48.0/24",
    "57.182.253.0/24",
    "57.183.42.0/25",
    "58.254.138.0/25",
    "58.254.138.128/26",
    "64.252.128.0/18",
    "64.252.64.0/18",
    "65.8.0.0/16",
    "65.9.0.0/17",
    "65.9.128.0/18",
    "70.132.0.0/18",
    "71.152.0.0/17",
    "99.79.169.0/24",
    "99.84.0.0/16",
    "99.86.0.0/16"
  ],
  "fastly": [
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.128.0/17",
    "140.248.64.0/18",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.232.0.0/16",
    "199.27.72.0/21",
    "23.235.32.0/20",
    "2a04:4e40::/32",
    "2a04:4e42::/32",
    "43.249.72.0/22"
  ],
  "gcore": [
    "1.37.77.98/32",
    "101.53.220.210/32",
    "102.130.69.141/32",
    "102.216.238.170/32",
    "102.67.99.50/32",
    "103.103.194.23/32",
    "103.151.135.4/32",
    "103.151.135.5/32",
    "103.151.135.6/32",
    "103.213.110.202/32",
    "103.75.239.42/32",
    "103.75.239.43/32",
    "103.75.239.45/32",
    "105.235.250.129/32",
    "105.235.250.131/32",
    "109.107.159.108/32",
    "109.107.159.121/32",
    "109.107.159.18/32",
    "109.107.159.183/32",
    "109.107.159.241/32",
    "109.107.159.78/32",
    "109.230.114.2/32",
    "109.61.122.4/32",
    "109.61.122.5/32",
    "109.61.122.6/32",
    "109.61.127.167/32",
    "109.61.127.174/32",
    "109.61.127.208/32",
    "109.61.39.212/32",
    "109.61.39.217/32",
    "109.61.39.249/32",
    "109.61.39.50/32",
    "109.61.39.82/32",
    "109.61.39.85/32",
    "109.68.233.242/32",
    "118.103.136.245/32",
    "120.28.10.46/32",
    "125.214.171.164/32",
    "128.75.231.10/32",
    "128.75.231.11/32",
    "128.75.231.2/32",
    "128.75.231.3/32",
    "128.75.231.4/32",
    "128.75.231.5/32",
    "128.75.231.6/32",
    "128.75.231.7/32",
    "128.75.231.8/32",
    "128.75.231.9/32",
    "130.193.166.2/32",
    "134.0.219.26/32",
    "134.0.219.37/32",
    "139.28.7.5/32",
    "139.28.7.6/32",
    "139.28.7.8/32",
    "143.137.230.226/32",
    "150.107.126.4/32",
    "150.107.126.5/32",
    "151.248.104.69/32",
    "151.248.104.91/32",
    "154.120.250.210/32",
    "154.160.40.2/32",
    "154.160.40.3/32",
    "168.232.103.194/32",
    "168.232.103.195/32",
    "169.239.158.154/32",
    "170.238.234.217/32",
    "176.222.182.186/32",
    "176.222.187.180/32",
    "176.222.189.242/32",
    "179.51.50.82/32",
    "180.149.90.66/32",
    "181.174.80.182/32",
    "181.208.199.10/32",
    "184.105.29.50/32",
    "185.101.136.10/32",
    "185.101.136.11/32",
    "185.101.136.14/32",
    "185.101.136.15/32",
    "185.101.136.16/32",
    "185.101.136.17/32",
    "185.101.136.18/32",
    "185.101.136.19/32",
    "185.101.136.23/32",
    "185.101.136.24/32",
    "185.101.136.25/32",
    "185.101.136.26/32",
    "185.101.136.27/32",
    "185.101.136.4/32",
    "185.101.136.5/32",
    "185.101.136.6/32",
    "185.105.1.10/32",
    "185.112.81.19/32",
    "185.158.211.186/32",
    "185.163.3.4/32",
    "185.163.3.5/32",
    "185.188.144.4/32",
    "185.188.144.5/32",
    "185.188.144.7/32",
    "185.188.144.8/32",
    "185.211.231.187/32",
    "185.244.209.10/32",
    "185.244.209.11/32",
    "185.244.209.12/32",
    "185.244.209.13/32",
    "185.244.209.14/32",
    "185.244.209.4/32",
    "185.244.209.5/32",
    "185.244.209.6/32",
    "185.244.209.7/32",
    "185.244.209.8/32",
    "185.244.209.9/32",
    "185.249.133.4/32",
    "185.48.136.150/32",
    "185.57.75.74/32",
    "185.76.48.122/32",
    "186.16.19.94/32",
    "186.2.150.34/32",
    "188.47.194.130/32",
    "188.47.205.130/32",
    "190.143.249.98/32",
    "190.95.248.34/32",
    "192.108.172.33/32",
    "193.143.1.97/32",
    "193.169.239.75/32",
    "193.169.250.4/32",
    "193.169.250.5/32",
    "193.169.250.7/32",
    "193.169.251.13/32",
    "193.169.251.14/32",
    "193.169.251.4/32",
    "193.169.251.5/32",
    "193.169.251.6/32",
    "193.169.251.7/32",
    "193.36.180.13/32",
    "193.36.180.14/32",
    "193.36.180.15/32",
    "193.36.180.16/32",
    "193.36.180.17/32",
    "193.36.180.18/32",
    "193.36.180.19/32",
    "193.36.180.20/32",
    "193.36.180.21/32",
    "193.36.180.22/32",
    "193.36.180.23/32",
    "193.36.180.24/32",
    "193.57.88.222/32",
    "193.57.89.4/32",
    "193.57.89.5/32",
    "194.158.198.1/32",
    "194.158.198.2/32",
    "194.158.198.3/32",
    "194.158.198.4/32",
    "194.158.198.5/32",
    "194.158.198.6/32",
    "194.158.198.7/32",
    "194.44.246.206/32",
    "195.14.146.81/32",
    "195.216.237.197/32",
    "195.216.237.199/32",
    "195.216.237.201/32",
    "195.216.237.203/32",
    "196.216.216.90/32",
    "196.97.8.18/32",
    "197.148.108.106/32",
    "197.160.157.1/32",
    "197.188.22.102/32",
    "197.215.44.65/32",
    "197.218.12.250/32",
    "197.225.145.26/32",
    "197.242.183.193/32",
    "197.242.183.195/32",
    "2.78.47.38/32",
    "200.10.177.54/32",
    "200.24.129.100/32",
    "200.24.129.98/32",
    "200.24.129.99/32",
    "2001:1670::130:0:0:107/128",
    "2001:1670::130:0:0:e2/128",
    "2001:19f0:5400:312d:5400:6ff:fe48:3e9b/128",
    "2001:1a10:cd:9c01::2/128",
    "2001:4290:c:d::26/128",
    "2001:67c:2700:c001::2/128",
    "2001:fe0:4775::147/128",
    "202.129.236.162/32",
    "204.157.181.94/32",
    "212.232.103.11/32",
    "212.232.103.73/32",
    "212.232.104.191/32",
    "212.232.109.191/32",
    "212.47.156.36/32",
    "212.47.156.37/32",
    "212.47.156.38/32",
    "212.47.156.39/32",
    "212.47.156.40/32",
    "212.47.156.41/32",
    "212.65.33.11/32",
    "212.96.94.58/32",
    "213.151.225.33/32",
    "213.156.144.4/32",
    "213.156.144.4/32",
    "213.156.144.5/32",
    "213.156.144.6/32",
    "213.156.144.7/32",
    "213.156.151.4/32",
    "213.156.151.5/32",
    "213.156.151.6/32",
    "213.156.156.4/32",
    "213.156.156.5/32",
    "213.252.220.4/32",
    "213.55.123.91/32",
    "217.195.193.10/32",
    "217.195.193.11/32",
    "217.195.193.12/32",
    "217.195.193.13/32",
    "217.195.193.4/32",
    "217.195.193.5/32",
    "217.195.193.6/32",
    "217.195.193.7/32",
    "217.195.193.8/32",
    "217.195.193.9/32",
    "217.76.64.195/32",
    "2400:adc0:60::202/128",
    "2401:9700:22c0:2::162/128",
    "2401:d600:0:1fff::31/128",
    "2402:5060:1:2801::4/128",
    "2402:5060:1:2801::5/128",
    "2402:5060:1:2801::6/128",
    "2405:1340:1001:7::1/128",
    "2405:1500:0:46::42/128",
    "2405:1500:0:46::43/128",
    "2405:1500:0:46::45/128",
    "2405:ec00:fa02::245/128",
    "2406:5a00:0:23::4/128",
    "2602:f8b2:2:300::11/128",
    "2800:2a0:ffff:1b::a/128",
    "2800:320:40f::2/128",
    "2800:3a0:1:1::5e/128",
    "2800:880:3:c00::2/128",
    "2801:12:e800:4::2/128",
    "2801:135:0:9::2/128",
    "2801:1d:a001:7::2/128",
    "2803:180:2:1d::2/128",
    "2803:2540:f:13::100/128",
    "2803:2540:f:13::98/128",
    "2803:2540:f:13::99/128",
    "2803:8100:3201:7::10/128",
    "2803:c800:0:9a::2/128",
    "2803:d700:0:c013::1002/128",
    "2803:d700:0:c013::1003/128",
    "2804:3674::400:42/128",
    "2a00:1358:2000:e01::1/128",
    "2a00:1760:6007:20::210/128",
    "2a00:1760:6007:20::211/128",
    "2a00:1760:6007:20::212/128",
    "2a00:ab40:3000:15::226/128",
    "2a00:d2c0:1e:20::15/128",
    "2a00:f46:120::2/128",
    "2a00:f46:12b::2/128",
    "2a00:f500:c:3::34/128",
    "2a00:fc00:1:1055::2/128",
    "2a01:410:1:5024::1/128",
    "2a01:4b40:1001:c::3/128",
    "2a01:4b40:1:19::2/128",
    "2a01:4b40:801:19::2/128",
    "2a01:68c0:0:1:ffff::21/128",
    "2a01:68c0:0:1:ffff::22/128",
    "2a01:9c80:ada:5::202/128",
    "2a01:c500:1:6::d4e8:670b/128",
    "2a01:c500:1:6::d4e8:6749/128",
    "2a01:c500:1:6::d4e8:68bf/128",
    "2a01:c500:1:6::d4e8:6dbf/128",
    "2a01:c840:40:530::1/128",
    "2a01:c9c0:c000:1001::/128",
    "2a01:c9c0:c000:1002::/128",
    "2a01:c9c0:c000:1003::/128",
    "2a01:c9c0:c000:2001::/128",
    "2a01:c9c0:c000:2002::/128",
    "2a01:c9c0:c000:2003::/128",
    "2a01:c9c0:c000:3001::/128",
    "2a01:c9c0:c000:3002::/128",
    "2a01:c9c0:c000:3003::/128",
    "2a01:c9c0:c000:4001::/128",
    "2a01:c9c0:c000:4002::/128",
    "2a01:c9c0:c000:4003::/128",
    "2a01:c9c0:c000:5001::/128",
    "2a01:c9c0:c000:5002::/128",
    "2a01:c9c0:c000:5003::/128",
    "2a01:c9c0:c000:6001::/128",
    "2a01:c9c0:c000:6002::/128",
    "2a01:c9c0:c000:6003::/128",
    "2a01:c9c0:c000:7001::/128",
    "2a01:c9c0:c000:7002::/128",
    "2a01:c9c0:c000:7003::/128",
    "2a01:c9c0:c000:8001::/128",
    "2a01:c9c0:c000:8002::/128",
    "2a01:c9c0:c000:8003::/128",
    "2a01:c9c0:c002:100::1/128",
    "2a01:c9c0:c002::1/128",
    "2a01:c9c0:c004:100::1/128",
    "2a01:c9c0:c004:100::3/128",
    "2a01:c9c0:c004:100::5/128",
    "2a01:c9c0:c004:100::7/128",
    "2a01:c9c0:c004:200::1/128",
    "2a01:c9c0:c004:200::3/128",
    "2a01:c9c0:c004:200::5/128",
    "2a01:c9c0:c004:300::1/128",
    "2a01:c9c0:c004:300::3/128",
    "2a01:c9c0:c004::1/128",
    "2a01:c9c0:c006:200::1/128",
    "2a01:c9c0:c006:200::3/128",
    "2a01:c9c0:c006:200::5/128",
    "2a01:c9c0:c006:3000::1/128",
    "2a01:c9c0:c006:500::1/128",
    "2a01:c9c0:c006:500::3/128",
    "2a01:c9c0:c006:500::5/128",
    "2a01:c9c0:c006:500::7/128",
    "2a01:c9c0:c006:500::9/128",
    "2a01:c9c0:c006:600::1/128",
    "2a01:c9c0:c006:600::3/128",
    "2a01:c9c0:c006:600::5/128",
    "2a01:c9c0:c006:600::7/128",
    "2a01:c9c0:c00a::1/128",
    "2a01:c9c0:c012:100::5/128",
    "2a01:c9c0:c012::5/128",
    "2a01:c9c0:c014:100::5/128",
    "2a01:c9c0:c014::5/128",
    "2a01:c9c0:c016:100::1/128",
    "2a01:c9c0:c016:100::3/128",
    "2a01:c9c0:c016::1/128",
    "2a01:c9c0:c016::3/128",
    "2a01:c9c0:c016::5/128",
    "2a01:c9c0:c018:100::1/128",
    "2a01:c9c0:c018:100::3/128",
    "2a01:c9c0:c018::1/128",
    "2a01:c9c0:c018::3/128",
    "2a01:c9c0:c01a::5/128",
    "2a01:c9c0:c01c:100::1/128",
    "2a01:c9c0:c01c:100::3/128",
    "2a01:c9c0:c01c::1/128",
    "2a01:c9c0:c01c::3/128",
    "2a01:c9c0:c020::1/128",
    "2a01:c9c0:c020::3/128",
    "2a01:c9c0:c022::1/128",
    "2a01:c9c0:c022::3/128",
    "2a01:c9c0:c026::1/128",
    "2a01:c9c0:c026::3/128",
    "2a01:c9c0:c040::1/128",
    "2a01:c9c0:c040::3/128",
    "2a01:c9c0:c062:100::5/128",
    "2a01:c9c0:c062:100::7/128",
    "2a01:c9c0:c062:200::1/128",
    "2a01:c9c0:c062:200::3/128",
    "2a01:c9c0:c062::5/128",
    "2a01:c9c0:c062::7/128",
    "2a01:c9c0:c080::1/128",
    "2a01:c9c0:c080::3/128",
    "2a01:cd20::1a:65/128",
    "2a02:2208:e:1c::1/128",
    "2a02:2208:e:1c::2/128",
    "2a02:2208:e:1c::3/128",
    "2a02:2208:e:1c::4/128",
    "2a02:2208:e:1c::5/128",
    "2a02:2208:e:1c::6/128",
    "2a02:2208:e:1c::7/128",
    "2a02:2278:fffd:6::186/128",
    "2a02:a58:10:30::2/128",
    "2a02:a58:11:30::2/128",
    "2a02:f040:7:2::6/128",
    "2a02:f040:a::12/128",
    "2a03:32c0:3008:4006::74/128",
    "2a03:32c0:4008:4006::58/128",
    "2a03:32c0:8:4006::195/128",
    "2a03:90c0:101:2801::22/128",
    "2a03:90c0:101:2801::23/128",
    "2a03:90c0:101:2801::24/128",
    "2a03:90c0:101:2801::25/128",
    "2a03:90c0:101:2801::26/128",
    "2a03:90c0:101:2801::27/128",
    "2a03:90c0:101:2801::28/128",
    "2a03:90c0:111:2801::10/128",
    "2a03:90c0:111:2801::11/128",
    "2a03:90c0:111:2801::21/128",
    "2a03:90c0:111:2801::22/128",
    "2a03:90c0:111:2801::23/128",
    "2a03:90c0:111:2801::24/128",
    "2a03:90c0:111:2801::25/128",
    "2a03:90c0:111:2801::26/128",
    "2a03:90c0:111:2801::27/128",
    "2a03:90c0:111:2801::28/128",
    "2a03:90c0:111:2801::29/128",
    "2a03:90c0:111:2801::4/128",
    "2a03:90c0:111:2801::5/128",
    "2a03:90c0:111:2801::6/128",
    "2a03:90c0:111:2801::8/128",
    "2a03:90c0:111:2801::9/128",
    "2a03:90c0:11:2801::132/128",
    "2a03:90c0:11:2801::133/128",
    "2a03:90c0:11:2801::134/128",
    "2a03:90c0:11:2801::135/128",
    "2a03:90c0:11:2801::136/128",
    "2a03:90c0:11:2801::137/128",
    "2a03:90c0:11:2801::142/128",
    "2a03:90c0:11:2801::143/128",
    "2a03:90c0:11:2801::144/128",
    "2a03:90c0:11:2801::145/128",
    "2a03:90c0:11:2801::146/128",
    "2a03:90c0:11:2801::147/128",
    "2a03:90c0:11:2801::148/128",
    "2a03:90c0:11:2801::149/128",
    "2a03:90c0:11:2801::151/128",
    "2a03:90c0:11:2801::158/128",
    "2a03:90c0:11:2801::160/128",
    "2a03:90c0:11:2801::161/128",
    "2a03:90c0:11:2801::165/128",
    "2a03:90c0:11:2801::166/128",
    "2a03:90c0:11:2801::167/128",
    "2a03:90c0:11:2801::168/128",
    "2a03:90c0:11:2801::169/128",
    "2a03:90c0:11:2801::170/128",
    "2a03:90c0:11:2801::175/128",
    "2a03:90c0:11:2801::176/128",
    "2a03:90c0:11:2801::177/128",
    "2a03:90c0:11:2801::178/128",
    "2a03:90c0:11:2801::179/128",
    "2a03:90c0:11:2801::180/128",
    "2a03:90c0:11:2801::181/128",
    "2a03:90c0:11:2801::182/128",
    "2a03:90c0:11:2801::184/128",
    "2a03:90c0:11:2801::186/128",
    "2a03:90c0:11:2801::187/128",
    "2a03:90c0:11:2801::188/128",
    "2a03:90c0:11:2801::189/128",
    "2a03:90c0:11:2801::190/128",
    "2a03:90c0:11:2801::191/128",
    "2a03:90c0:11:2801::192/128",
    "2a03:90c0:11:2801::193/128",
    "2a03:90c0:11:2801::194/128",
    "2a03:90c0:11:2801::195/128",
    "2a03:90c0:121:2801::21/128",
    "2a03:90c0:151:2801::4/128",
    "2a03:90c0:151:2801::5/128",
    "2a03:90c0:161:2801::21/128",
    "2a03:90c0:161:2801::25/128",
    "2a03:90c0:170:2801::5/128",
    "2a03:90c0:170:2801::6/128",
    "2a03:90c0:170:2801::7/128",
    "2a03:90c0:180:2801::10/128",
    "2a03:90c0:180:2801::11/128",
    "2a03:90c0:180:2801::12/128",
    "2a03:90c0:180:2801::13/128",
    "2a03:90c0:180:2801::18/128",
    "2a03:90c0:180:2801::20/128",
    "2a03:90c0:180:2801::21/128",
    "2a03:90c0:180:2801::25/128",
    "2a03:90c0:180:2801::26/128",
    "2a03:90c0:180:2801::27/128",
    "2a03:90c0:180:2801::9/128",
    "2a03:90c0:191:2801::4/128",
    "2a03:90c0:191:2801::5/128",
    "2a03:90c0:191:2801::7/128",
    "2a03:90c0:191:2801::8/128",
    "2a03:90c0:1a1:2801::10/128",
    "2a03:90c0:1a1:2801::6/128",
    "2a03:90c0:1a1:2801::7/128",
    "2a03:90c0:1a1:2801::8/128",
    "2a03:90c0:1b1:2801::10/128",
    "2a03:90c0:1b1:2801::16/128",
    "2a03:90c0:1b1:2801::17/128",
    "2a03:90c0:1b1:2801::4/128",
    "2a03:90c0:1b1:2801::5/128",
    "2a03:90c0:1b1:2801::6/128",
    "2a03:90c0:1b1:2801::7/128",
    "2a03:90c0:1b1:2801::8/128",
    "2a03:90c0:1b1:2801::9/128",
    "2a03:90c0:1e1:2801::5/128",
    "2a03:90c0:1f1:2801::10/128",
    "2a03:90c0:1f1:2801::11/128",
    "2a03:90c0:1f1:2801::13/128",
    "2a03:90c0:1f1:2801::4/128",
    "2a03:90c0:1f1:2801::5/128",
    "2a03:90c0:1f1:2801::6/128",
    "2a03:90c0:211:2801::11/128",
    "2a03:90c0:211:2801::12/128",
    "2a03:90c0:211:2801::13/128",
    "2a03:90c0:211:2801::15/128",
    "2a03:90c0:211:2801::16/128",
    "2a03:90c0:211:2801::17/128",
    "2a03:90c0:211:2801::8/128",
    "2a03:90c0:21:2801::132/128",
    "2a03:90c0:21:2801::133/128",
    "2a03:90c0:21:2801::134/128",
    "2a03:90c0:21:2801::135/128",
    "2a03:90c0:21:2801::136/128",
    "2a03:90c0:21:2801::137/128",
    "2a03:90c0:21:2801::138/128",
    "2a03:90c0:21:2801::139/128",
    "2a03:90c0:21:2801::140/128",
    "2a03:90c0:21:2801::141/128",
    "2a03:90c0:21:2801::146/128",
    "2a03:90c0:221:2801::10/128",
    "2a03:90c0:221:2801::11/128",
    "2a03:90c0:221:2801::4/128",
    "2a03:90c0:221:2801::5/128",
    "2a03:90c0:221:2801::6/128",
    "2a03:90c0:221:2801::7/128",
    "2a03:90c0:221:2801::8/128",
    "2a03:90c0:221:2801::9/128",
    "2a03:90c0:251:2801::10/128",
    "2a03:90c0:251:2801::11/128",
    "2a03:90c0:251:2801::14/128",
    "2a03:90c0:251:2801::15/128",
    "2a03:90c0:251:2801::16/128",
    "2a03:90c0:251:2801::17/128",
    "2a03:90c0:251:2801::18/128",
    "2a03:90c0:251:2801::19/128",
    "2a03:90c0:251:2801::23/128",
    "2a03:90c0:251:2801::24/128",
    "2a03:90c0:251:2801::25/128",
    "2a03:90c0:251:2801::26/128",
    "2a03:90c0:251:2801::27/128",
    "2a03:90c0:251:2801::4/128",
    "2a03:90c0:251:2801::5/128",
    "2a03:90c0:251:2801::6/128",
    "2a03:90c0:271:2801:1::13/128",
    "2a03:90c0:271:2801:1::14/128",
    "2a03:90c0:271:2801:1::15/128",
    "2a03:90c0:271:2801:1::16/128",
    "2a03:90c0:271:2801:1::17/128",
    "2a03:90c0:271:2801:1::23/128",
    "2a03:90c0:271:2801:1::24/128",
    "2a03:90c0:271:2801:1::25/128",
    "2a03:90c0:271:2801:1::26/128",
    "2a03:90c0:271:2801:1::27/128",
    "2a03:90c0:271:2801:1::28/128",
    "2a03:90c0:271:2801:1::29/128",
    "2a03:90c0:271:2801:1::30/128",
    "2a03:90c0:271:2801:1::31/128",
    "2a03:90c0:271:2801:1::32/128",
    "2a03:90c0:271:2801:1::4/128",
    "2a03:90c0:271:2801:1::5/128",
    "2a03:90c0:271:2801:1::6/128",
    "2a03:90c0:271:2801:1::7/128",
    "2a03:90c0:281:2801::10/128",
    "2a03:90c0:291:2801::37/128",
    "2a03:90c0:2f1:2801::4/128",
    "2a03:90c0:311:2801::10/128",
    "2a03:90c0:311:2801::11/128",
    "2a03:90c0:311:2801::12/128",
    "2a03:90c0:311:2801::13/128",
    "2a03:90c0:311:2801::14/128",
    "2a03:90c0:311:2801::15/128",
    "2a03:90c0:311:2801::16/128",
    "2a03:90c0:311:2801::17/128",
    "2a03:90c0:311:2801::4/128",
    "2a03:90c0:311:2801::5/128",
    "2a03:90c0:311:2801::6/128",
    "2a03:90c0:311:2801::7/128",
    "2a03:90c0:311:2801::8/128",
    "2a03:90c0:311:2801::9/128",
    "2a03:90c0:31:2801::10/128",
    "2a03:90c0:31:2801::11/128",
    "2a03:90c0:31:2801::12/128",
    "2a03:90c0:31:2801::13/128",
    "2a03:90c0:31:2801::14/128",
    "2a03:90c0:31:2801::15/128",
    "2a03:90c0:31:2801::16/128",
    "2a03:90c0:31:2801::17/128",
    "2a03:90c0:31:2801::18/128",
    "2a03:90c0:31:2801::19/128",
    "2a03:90c0:31:2801::196/128",
    "2a03:90c0:31:2801::197/128",
    "2a03:90c0:31:2801::198/128",
    "2a03:90c0:31:2801::20/128",
    "2a03:90c0:31:2801::203/128",
    "2a03:90c0:31:2801::204/128",
    "2a03:90c0:31:2801::208/128",
    "2a03:90c0:31:2801::209/128",
    "2a03:90c0:31:2801::21/128",
    "2a03:90c0:31:2801::210/128",
    "2a03:90c0:31:2801::211/128",
    "2a03:90c0:31:2801::212/128",
    "2a03:90c0:31:2801::214/128",
    "2a03:90c0:31:2801::215/128",
    "2a03:90c0:31:2801::216/128",
    "2a03:90c0:31:2801::217/128",
    "2a03:90c0:31:2801::218/128",
    "2a03:90c0:31:2801::219/128",
    "2a03:90c0:31:2801::22/128",
    "2a03:90c0:31:2801::220/128",
    "2a03:90c0:31:2801::221/128",
    "2a03:90c0:31:2801::222/128",
    "2a03:90c0:31:2801::23/128",
    "2a03:90c0:31:2801::24/128",
    "2a03:90c0:31:2801::25/128",
    "2a03:90c0:31:2801::26/128",
    "2a03:90c0:31:2801::27/128",
    "2a03:90c0:31:2801::28/128",
    "2a03:90c0:31:2801::29/128",
    "2a03:90c0:31:2801::31/128",
    "2a03:90c0:31:2801::6/128",
    "2a03:90c0:31:2801::8/128",
    "2a03:90c0:321:2803::200/128",
    "2a03:90c0:321:2803::201/128",
    "2a03:90c0:321:2803::202/128",
    "2a03:90c0:321:2803::204/128",
    "2a03:90c0:321:2803::205/128",
    "2a03:90c0:321:2803::206/128",
    "2a03:90c0:321:2803::207/128",
    "2a03:90c0:321:2803::208/128",
    "2a03:90c0:321:2803::210/128",
    "2a03:90c0:321:2803::211/128",
    "2a03:90c0:321:2803::212/128",
    "2a03:90c0:321:2803::213/128",
    "2a03:90c0:321:2803::214/128",
    "2a03:90c0:321:2803::215/128",
    "2a03:90c0:321:2803::216/128",
    "2a03:90c0:321:2803::217/128",
    "2a03:90c0:321:2803::220/128",
    "2a03:90c0:321:2803::221/128",
    "2a03:90c0:321:2803::222/128",
    "2a03:90c0:321:2803::223/128",
    "2a03:90c0:321:2803::224/128",
    "2a03:90c0:321:2803::225/128",
    "2a03:90c0:321:2803::226/128",
    "2a03:90c0:321:2803::227/128",
    "2a03:90c0:321:2803::229/128",
    "2a03:90c0:321:2803::230/128",
    "2a03:90c0:321:2803::231/128",
    "2a03:90c0:321:2803::232/128",
    "2a03:90c0:321:2803::233/128",
    "2a03:90c0:321:2803::234/128",
    "2a03:90c0:321:2803::235/128",
    "2a03:90c0:321:2803::236/128",
    "2a03:90c0:321:2803::237/128",
    "2a03:90c0:321:2803::238/128",
    "2a03:90c0:321:2803::239/128",
    "2a03:90c0:321:2803::240/128",
    "2a03:90c0:321:2803::241/128",
    "2a03:90c0:321:2803::242/128",
    "2a03:90c0:321:2803::243/128",
    "2a03:90c0:321:2803::244/128",
    "2a03:90c0:331:2801::4/128",
    "2a03:90c0:331:2801::5/128",
    "2a03:90c0:341:2801::10/128",
    "2a03:90c0:341:2801::11/128",
    "2a03:90c0:341:2801::12/128",
    "2a03:90c0:341:2801::13/128",
    "2a03:90c0:341:2801::4/128",
    "2a03:90c0:341:2801::5/128",
    "2a03:90c0:341:2801::6/128",
    "2a03:90c0:341:2801::7/128",
    "2a03:90c0:341:2801::8/128",
    "2a03:90c0:341:2801::9/128",
    "2a03:90c0:371:2801::5/128",
    "2a03:90c0:371:2801::6/128",
    "2a03:90c0:371:2801::7/128",
    "2a03:90c0:371:2801::8/128",
    "2a03:90c0:391:2801::4/128",
    "2a03:90c0:391:2801::5/128",
    "2a03:90c0:391:2801::6/128",
    "2a03:90c0:3a1:2801::10/128",
    "2a03:90c0:3a1:2801::11/128",
    "2a03:90c0:3a1:2801::5/128",
    "2a03:90c0:3a1:2801::6/128",
    "2a03:90c0:3a1:2801::7/128",
    "2a03:90c0:3c1:2801::10/128",
    "2a03:90c0:3c1:2801::11/128",
    "2a03:90c0:3c1:2801::12/128",
    "2a03:90c0:3c1:2801::4/128",
    "2a03:90c0:3c1:2801::5/128",
    "2a03:90c0:3c1:2801::6/128",
    "2a03:90c0:3c1:2801::7/128",
    "2a03:90c0:3c1:2801::8/128",
    "2a03:90c0:3d1:2801::4/128",
    "2a03:90c0:3d1:2801::5/128",
    "2a03:90c0:3d1:2801::6/128",
    "2a03:90c0:3f1:2801::4/128",
    "2a03:90c0:3f1:2801::5/128",
    "2a03:90c0:3f1:2801::6/128",
    "2a03:90c0:3f1:2801::7/128",
    "2a03:90c0:3f1:2801::8/128",
    "2a03:90c0:41:2801::10/128",
    "2a03:90c0:41:2801::11/128",
    "2a03:90c0:41:2801::12/128",
    "2a03:90c0:41:2801::13/128",
    "2a03:90c0:41:2801::14/128",
    "2a03:90c0:41:2801::16/128",
    "2a03:90c0:41:2801::17/128",
    "2a03:90c0:41:2801::18/128",
    "2a03:90c0:41:2801::19/128",
    "2a03:90c0:41:2801::21/128",
    "2a03:90c0:41:2801::22/128",
    "2a03:90c0:41:2801::23/128",
    "2a03:90c0:41:2801::24/128",
    "2a03:90c0:41:2801::25/128",
    "2a03:90c0:41:2801::26/128",
    "2a03:90c0:41:2801::27/128",
    "2a03:90c0:41:2801::28/128",
    "2a03:90c0:41:2801::29/128",
    "2a03:90c0:41:2801::30/128",
    "2a03:90c0:41:2801::31/128",
    "2a03:90c0:41:2801::32/128",
    "2a03:90c0:41:2801::34/128",
    "2a03:90c0:41:2801::36/128",
    "2a03:90c0:41:2801::37/128",
    "2a03:90c0:41:2801::38/128",
    "2a03:90c0:41:2801::39/128",
    "2a03:90c0:41:2801::4/128",
    "2a03:90c0:41:2801::40/128",
    "2a03:90c0:41:2801::41/128",
    "2a03:90c0:41:2801::42/128",
    "2a03:90c0:41:2801::44/128",
    "2a03:90c0:41:2801::45/128",
    "2a03:90c0:41:2801::46/128",
    "2a03:90c0:41:2801::47/128",
    "2a03:90c0:41:2801::48/128",
    "2a03:90c0:41:2801::5/128",
    "2a03:90c0:41:2801::50/128",
    "2a03:90c0:41:2801::51/128",
    "2a03:90c0:41:2801::52/128",
    "2a03:90c0:41:2801::53/128",
    "2a03:90c0:41:2801::54/128",
    "2a03:90c0:41:2801::55/128",
    "2a03:90c0:41:2801::56/128",
    "2a03:90c0:41:2801::57/128",
    "2a03:90c0:41:2801::58/128",
    "2a03:90c0:41:2801::6/128",
    "2a03:90c0:41:2801::7/128",
    "2a03:90c0:41:2801::8/128",
    "2a03:90c0:41:2801::9/128",
    "2a03:90c0:421:2801::4/128",
    "2a03:90c0:421:2801::5/128",
    "2a03:90c0:460:2801::10/128",
    "2a03:90c0:460:2801::11/128",
    "2a03:90c0:460:2801::12/128",
    "2a03:90c0:460:2801::4/128",
    "2a03:90c0:460:2801::5/128",
    "2a03:90c0:460:2801::6/128",
    "2a03:90c0:460:2801::7/128",
    "2a03:90c0:460:2801::8/128",
    "2a03:90c0:460:2801::9/128",
    "2a03:90c0:491:2801::10/128",
    "2a03:90c0:491:2801::12/128",
    "2a03:90c0:491:2801::14/128",
    "2a03:90c0:491:2801::15/128",
    "2a03:90c0:491:2801::16/128",
    "2a03:90c0:491:2801::17/128",
    "2a03:90c0:491:2801::18/128",
    "2a03:90c0:491:2801::4/128",
    "2a03:90c0:491:2801::5/128",
    "2a03:90c0:491:2801::6/128",
    "2a03:90c0:491:2801::7/128",
    "2a03:90c0:491:2801::8/128",
    "2a03:90c0:491:2801::9/128",
    "2a03:90c0:4b1:2801::4/128",
    "2a03:90c0:4b1:2801::5/128",
    "2a03:90c0:4b1:2801::6/128",
    "2a03:90c0:4b1:2801::7/128",
    "2a03:90c0:4b1:2801::8/128",
    "2a03:90c0:4c1:2801::4/128",
    "2a03:90c0:4c1:2801::5/128",
    "2a03:90c0:4c1:2801::6/128",
    "2a03:90c0:4c1:2801::7/128",
    "2a03:90c0:4c1:2801::8/128",
    "2a03:90c0:4d1:2801::13/128",
    "2a03:90c0:4d1:2801::14/128",
    "2a03:90c0:4d1:2801::4/128",
    "2a03:90c0:4d1:2801::5/128",
    "2a03:90c0:4d1:2801::6/128",
    "2a03:90c0:4d1:2801::7/128",
    "2a03:90c0:4e1:2801::9/128",
    "2a03:90c0:4f1:2801::10/128",
    "2a03:90c0:4f1:2801::11/128",
    "2a03:90c0:4f1:2801::12/128",
    "2a03:90c0:4f1:2801::13/128",
    "2a03:90c0:4f1:2801::4/128",
    "2a03:90c0:4f1:2801::5/128",
    "2a03:90c0:4f1:2801::6/128",
    "2a03:90c0:4f1:2801::7/128",
    "2a03:90c0:4f1:2801::9/128",
    "2a03:90c0:501:2801::4/128",
    "2a03:90c0:501:2801::5/128",
    "2a03:90c0:501:2801::6/128",
    "2a03:90c0:501:2801::7/128",
    "2a03:90c0:501:2801::8/128",
    "2a03:90c0:501:2801::9/128",
    "2a03:90c0:51:2801::4/128",
    "2a03:90c0:51:2801::5/128",
    "2a03:90c0:51:2801::7/128",
    "2a03:90c0:521:2801::10/128",
    "2a03:90c0:521:2801::11/128",
    "2a03:90c0:521:2801::4/128",
    "2a03:90c0:521:2801::5/128",
    "2a03:90c0:521:2801::6/128",
    "2a03:90c0:521:2801::7/128",
    "2a03:90c0:521:2801::8/128",
    "2a03:90c0:521:2801::9/128",
    "2a03:90c0:541:2801::4/128",
    "2a03:90c0:541:2801::5/128",
    "2a03:90c0:541:2801::6/128",
    "2a03:90c0:541:2801::7/128",
    "2a03:90c0:551:2801::4/128",
    "2a03:90c0:551:2801::5/128",
    "2a03:90c0:551:2801::6/128",
    "2a03:90c0:591:2801::4/128",
    "2a03:90c0:591:2801::6/128",
    "2a03:90c0:591:2801::8/128",
    "2a03:90c0:5a1:2801::10/128",
    "2a03:90c0:5a1:2801::16/128",
    "2a03:90c0:5a1:2801::17/128",
    "2a03:90c0:5a1:2801::18/128",
    "2a03:90c0:5a1:2801::19/128",
    "2a03:90c0:5a1:2801::21/128",
    "2a03:90c0:5a1:2801::22/128",
    "2a03:90c0:5a1:2801::23/128",
    "2a03:90c0:5a1:2801::24/128",
    "2a03:90c0:5a1:2801::25/128",
    "2a03:90c0:5a1:2801::26/128",
    "2a03:90c0:5a1:2801::27/128",
    "2a03:90c0:5a1:2801::28/128",
    "2a03:90c0:5a1:2801::29/128",
    "2a03:90c0:5a1:2801::4/128",
    "2a03:90c0:5a1:2801::5/128",
    "2a03:90c0:5a1:2801::6/128",
    "2a03:90c0:5a1:2801::7/128",
    "2a03:90c0:5a1:2801::8/128",
    "2a03:90c0:5a1:2801::9/128",
    "2a03:90c0:5b1:2801::4/128",
    "2a03:90c0:5b1:2801::5/128",
    "2a03:90c0:5c1:2801::4/128",
    "2a03:90c0:5c1:2801::5/128",
    "2a03:90c0:5d1:2801::4/128",
    "2a03:90c0:5d1:2801::5/128",
    "2a03:90c0:5d1:2801::6/128",
    "2a03:90c0:5d1:2801::7/128",
    "2a03:90c0:5d1:2801::8/128",
    "2a03:90c0:5e1:2801::4/128",
    "2a03:90c0:5e1:2801::5/128",
    "2a03:90c0:5f1:2801::4/128",
    "2a03:90c0:5f1:2801::5/128",
    "2a03:90c0:611:2801::10/128",
    "2a03:90c0:611:2801::13/128",
    "2a03:90c0:611:2801::14/128",
    "2a03:90c0:611:2801::15/128",
    "2a03:90c0:611:2801::16/128",
    "2a03:90c0:611:2801::17/128",
    "2a03:90c0:611:2801::18/128",
    "2a03:90c0:611:2801::19/128",
    "2a03:90c0:611:2801::20/128",
    "2a03:90c0:611:2801::21/128",
    "2a03:90c0:611:2801::22/128",
    "2a03:90c0:611:2801::24/128",
    "2a03:90c0:611:2801::25/128",
    "2a03:90c0:611:2801::4/128",
    "2a03:90c0:611:2801::8/128",
    "2a03:90c0:62::68/128",
    "2a03:90c0:62::69/128",
    "2a03:90c0:62::70/128",
    "2a03:90c0:62::71/128",
    "2a03:90c0:62::72/128",
    "2a03:90c0:661:2801::4/128",
    "2a03:90c0:661:2801::5/128",
    "2a03:90c0:661:2801::6/128",
    "2a03:90c0:661:2801::7/128",
    "2a03:90c0:661:2801::8/128",
    "2a03:90c0:691:2801::4/128",
    "2a03:90c0:691:2801::5/128",
    "2a03:90c0:6a1:2801::10/128",
    "2a03:90c0:6a1:2801::11/128",
    "2a03:90c0:6a1:2801::12/128",
    "2a03:90c0:6a1:2801::13/128",
    "2a03:90c0:6a1:2801::14/128",
    "2a03:90c0:6a1:2801::15/128",
    "2a03:90c0:6a1:2801::4/128",
    "2a03:90c0:6a1:2801::5/128",
    "2a03:90c0:6a1:2801::6/128",
    "2a03:90c0:6a1:2801::7/128",
    "2a03:90c0:6a1:2801::8/128",
    "2a03:90c0:6b1:2801::4/128",
    "2a03:90c0:6b1:2801::5/128",
    "2a03:90c0:6d1:2801::10/128",
    "2a03:90c0:6d1:2801::11/128",
    "2a03:90c0:6d1:2801::12/128",
    "2a03:90c0:6d1:2801::13/128",
    "2a03:90c0:6d1:2801::14/128",
    "2a03:90c0:6d1:2801::15/128",
    "2a03:90c0:6d1:2801::16/128",
    "2a03:90c0:6d1:2801::17/128",
    "2a03:90c0:6d1:2801::18/128",
    "2a03:90c0:6d1:2801::19/128",
    "2a03:90c0:6d1:2801::20/128",
    "2a03:90c0:6d1:2801::21/128",
    "2a03:90c0:6d1:2801::22/128",
    "2a03:90c0:6d1:2801::23/128",
    "2a03:90c0:6d1:2801::24/128",
    "2a03:90c0:6d1:2801::25/128",
    "2a03:90c0:6d1:2801::26/128",
    "2a03:90c0:6d1:2801::27/128",
    "2a03:90c0:6d1:2801::28/128",
    "2a03:90c0:6d1:2801::29/128",
    "2a03:90c0:6d1:2801::30/128",
    "2a03:90c0:6d1:2801::31/128",
    "2a03:90c0:6d1:2801::4/128",
    "2a03:90c0:6d1:2801::5/128",
    "2a03:90c0:6d1:2801::6/128",
    "2a03:90c0:6d1:2801::7/128",
    "2a03:90c0:6d1:2801::8/128",
    "2a03:90c0:6d1:2801::9/128",
    "2a03:90c0:6e1:2801::4/128",
    "2a03:90c0:6e1:2801::5/128",
    "2a03:90c0:6e1:2801::6/128",
    "2a03:90c0:6f1:2801::10/128",
    "2a03:90c0:6f1:2801::11/128",
    "2a03:90c0:6f1:2801::12/128",
    "2a03:90c0:6f1:2801::13/128",
    "2a03:90c0:6f1:2801::14/128",
    "2a03:90c0:6f1:2801::4/128",
    "2a03:90c0:6f1:2801::5/128",
    "2a03:90c0:6f1:2801::6/128",
    "2a03:90c0:6f1:2801::7/128",
    "2a03:90c0:6f1:2801::8/128",
    "2a03:90c0:6f1:2801::9/128",
    "2a03:90c0:70:2801::4/128",
    "2a03:90c0:70:2801::5/128",
    "2a03:90c0:711:2801::10/128",
    "2a03:90c0:711:2801::4/128",
    "2a03:90c0:711:2801::5/128",
    "2a03:90c0:711:2801::6/128",
    "2a03:90c0:711:2801::7/128",
    "2a03:90c0:711:2801::8/128",
    "2a03:90c0:711:2801::9/128",
    "2a03:90c0:721:2801::4/128",
    "2a03:90c0:721:2801::5/128",
    "2a03:90c0:721:2801::6/128",
    "2a03:90c0:721:2801::7/128",
    "2a03:90c0:731:2801::5/128",
    "2a03:90c0:731:2801::6/128",
    "2a03:90c0:731:2801::8/128",
    "2a03:90c0:751:2801::10/128",
    "2a03:90c0:751:2801::13/128",
    "2a03:90c0:751:2801::14/128",
    "2a03:90c0:751:2801::18/128",
    "2a03:90c0:751:2801::19/128",
    "2a03:90c0:751:2801::20/128",
    "2a03:90c0:751:2801::21/128",
    "2a03:90c0:751:2801::22/128",
    "2a03:90c0:751:2801::4/128",
    "2a03:90c0:751:2801::5/128",
    "2a03:90c0:751:2801::6/128",
    "2a03:90c0:751:2801::7/128",
    "2a03:90c0:751:2801::8/128",
    "2a03:90c0:771:2801::4/128",
    "2a03:90c0:771:2801::5/128",
    "2a03:90c0:771:2801::6/128",
    "2a03:90c0:781:2801::10/128",
    "2a03:90c0:781:2801::11/128",
    "2a03:90c0:781:2801::12/128",
    "2a03:90c0:781:2801::13/128",
    "2a03:90c0:781:2801::14/128",
    "2a03:90c0:781:2801::15/128",
    "2a03:90c0:781:2801::16/128",
    "2a03:90c0:781:2801::17/128",
    "2a03:90c0:781:2801::18/128",
    "2a03:90c0:781:2801::19/128",
    "2a03:90c0:781:2801::20/128",
    "2a03:90c0:781:2801::21/128",
    "2a03:90c0:781:2801::7/128",
    "2a03:90c0:781:2801::8/128",
    "2a03:90c0:781:2801::9/128",
    "2a03:90c0:7e1:2801::4/128",
    "2a03:90c0:7e1:2801::5/128",
    "2a03:90c0:7e1:2801::6/128",
    "2a03:90c0:7e1:2801::7/128",
    "2a03:90c0:801:2801::4/128",
    "2a03:90c0:801:2801::5/128",
    "2a03:90c0:801:2801::6/128",
    "2a03:90c0:801:2801::7/128",
    "2a03:90c0:a1:2801::13/128",
    "2a03:90c0:a1:2801::14/128",
    "2a03:90c0:a1:2801::15/128",
    "2a03:90c0:a1:2801::16/128",
    "2a03:90c0:a1:2801::17/128",
    "2a03:90c0:a1:2801::18/128",
    "2a03:90c0:a1:2801::19/128",
    "2a03:90c0:a1:2801::20/128",
    "2a03:90c0:a1:2801::21/128",
    "2a03:90c0:a1:2801::22/128",
    "2a03:90c0:a1:2801::23/128",
    "2a03:90c0:a1:2801::24/128",
    "2a03:90c0:b1:2801::4/128",
    "2a03:90c0:b1:2801::5/128",
    "2a03:90c0:b1:2801::6/128",
    "2a03:90c0:b1:2801::7/128",
    "2a03:90c0:b1:2801::8/128",
    "2a03:90c0:c1:2801::132/128",
    "2a03:90c0:c1:2801::133/128",
    "2a03:90c0:c1:2801::134/128",
    "2a03:90c0:c1:2801::135/128",
    "2a03:90c0:c1:2801::136/128",
    "2a03:90c0:c1:2801::137/128",
    "2a03:90c0:c1:2801::138/128",
    "2a03:90c0:c1:2801::139/128",
    "2a03:90c0:c1:2801::140/128",
    "2a03:90c0:c1:2801::141/128",
    "2a03:90c0:c1:2801::142/128",
    "2a03:90c0:c1:2801::143/128",
    "2a03:90c0:c1:2801::144/128",
    "2a03:90c0:c1:2801::145/128",
    "2a03:90c0:c1:2801::146/128",
    "2a03:90c0:c1:2801::147/128",
    "2a03:90c0:c1:2801::148/128",
    "2a03:90c0:c1:2801::149/128",
    "2a03:90c0:c1:2801::150/128",
    "2a03:90c0:c1:2801::151/128",
    "2a03:90c0:c1:2801::152/128",
    "2a03:90c0:c1:2801::36/128",
    "2a03:90c0:c1:2801::38/128",
    "2a03:90c0:c1:2801::39/128",
    "2a03:90c0:c1:2801::53/128",
    "2a03:90c0:c1:2801::54/128",
    "2a03:90c0:c1:2801::55/128",
    "2a03:90c0:e1:2801::20/128",
    "2a03:90c0:e1:2801::21/128",
    "2a03:90c0:e1:2801::26/128",
    "2a03:90c0:f1:2801::132/128",
    "2a03:90c0:f1:2801::133/128",
    "2a03:90c0:f1:2801::134/128",
    "2a03:90c0:f1:2801::135/128",
    "2a03:90c0:f1:2801::136/128",
    "2a03:90c0:f1:2801::20/128",
    "2a03:90c0:f1:2801::21/128",
    "2a03:90c0:f1:2801::22/128",
    "2a03:90c0:f1:2801::26/128",
    "2a03:90c0:f1:2801::27/128",
    "2a03:90c0:f1:2801::28/128",
    "2a03:c343:1::12/128",
    "2a04:2e80:5:7::162/128",
    "2a04:2e80:5:7::163/128",
    "2a05:8200::36/128",
    "2a05:8200::37/128",
    "2a05:8200::38/128",
    "2a05:8200::39/128",
    "2a05:8200::3a/128",
    "2a05:8200::3b/128",
    "2a0b:1880:14::94/128",
    "2a0b:6200:60:f::229/128",
    "2a0b:6200:60:f::231/128",
    "2a0b:6e40:0:3::187/128",
    "2c0e:0:22::1/128",
    "2c0f:4280:6400:2::202/128",
    "2c0f:ee00:1:c0eb::50/128",
    "2c0f:f578:0:c::106/128",
    "2c0f:f7c0:3800:10::bc2/128",
    "2c0f:f7c0:3800:10::bc3/128",
    "2c0f:f828:2::114/128",
    "2c0f:fe38:7:50::2/128",
    "31.184.207.10/32",
    "31.184.207.11/32",
    "31.184.207.12/32",
    "31.184.207.4/32",
    "31.184.207.5/32",
    "31.184.207.6/32",
    "31.184.207.7/32",
    "31.184.207.8/32",
    "31.184.207.9/32",
    "37.110.209.228/32",
    "37.156.224.13/32",
    "37.156.224.15/32",
    "37.17.119.210/32",
    "37.17.119.211/32",
    "37.17.119.212/32",
    "37.239.145.2/32",
    "37.9.33.122/32",
    "37.9.33.130/32",
    "37.9.33.184/32",
    "37.9.33.198/32",
    "37.9.33.230/32",
    "37.9.33.240/32",
    "41.210.189.22/32",
    "41.216.70.58/32",
    "41.226.6.202/32",
    "45.135.228.113/32",
    "45.135.228.173/32",
    "45.135.228.226/32",
    "45.32.212.15/32",
    "45.68.4.2/32",
    "45.68.52.66/32",
    "45.80.213.4/32",
    "45.80.213.5/32",
    "45.80.213.6/32",
    "45.80.213.7/32",
    "45.80.213.8/32",
    "45.82.100.4/32",
    "45.82.100.5/32",
    "45.82.101.10/32",
    "45.82.101.16/32",
    "45.82.101.17/32",
    "45.82.101.4/32",
    "45.82.101.5/32",
    "45.82.101.6/32",
    "45.82.101.7/32",
    "45.82.101.8/32",
    "45.82.101.9/32",
    "45.82.103.4/32",
    "45.82.103.6/32",
    "45.82.103.8/32",
    "45.82.160.111/32",
    "45.82.160.143/32",
    "45.82.160.171/32",
    "45.82.160.49/32",
    "45.82.160.62/32",
    "46.49.10.229/32",
    "46.49.10.231/32",
    "5.1.107.249/32",
    "5.101.217.4/32",
    "5.101.217.5/32",
    "5.101.217.6/32",
    "5.101.219.5/32",
    "5.101.219.6/32",
    "5.101.219.7/32",
    "5.101.219.8/32",
    "5.101.220.9/32",
    "5.101.222.10/32",
    "5.101.222.11/32",
    "5.101.222.4/32",
    "5.101.222.5/32",
    "5.101.222.6/32",
    "5.101.222.7/32",
    "5.188.126.10/32",
    "5.188.126.11/32",
    "5.188.126.4/32",
    "5.188.126.5/32",
    "5.188.126.6/32",
    "5.188.126.7/32",
    "5.188.126.8/32",
    "5.188.126.9/32",
    "5.188.132.5/32",
    "5.188.132.6/32",
    "5.188.133.10/32",
    "5.188.133.11/32",
    "5.188.133.13/32",
    "5.188.133.4/32",
    "5.188.133.5/32",
    "5.188.133.6/32",
    "5.188.94.5/32",
    "5.189.207.4/32",
    "5.189.207.5/32",
    "5.8.92.4/32",
    "5.8.92.5/32",
    "5.8.92.6/32",
    "5.8.92.7/32",
    "5.8.92.8/32",
    "62.112.222.116/32",
    "62.112.222.143/32",
    "62.112.222.229/32",
    "62.112.222.45/32",
    "62.112.222.52/32",
    "62.112.222.96/32",
    "62.112.223.4/32",
    "62.112.223.5/32",
    "62.209.27.232/32",
    "65.20.85.192/32",
    "78.111.103.4/32",
    "78.111.103.5/32",
    "78.111.110.4/32",
    "78.111.110.5/32",
    "78.111.110.6/32",
    "79.133.108.13/32",
    "79.133.108.14/32",
    "79.133.108.15/32",
    "79.133.108.16/32",
    "79.133.108.17/32",
    "79.133.108.23/32",
    "79.133.108.24/32",
    "79.133.108.25/32",
    "79.133.108.26/32",
    "79.133.108.27/32",
    "79.133.108.28/32",
    "79.133.108.29/32",
    "79.133.108.30/32",
    "79.133.108.31/32",
    "79.133.108.32/32",
    "79.133.108.4/32",
    "79.133.108.5/32",
    "79.133.108.6/32",
    "79.133.108.7/32",
    "79.133.126.166/32",
    "80.15.228.1/32",
    "80.15.228.3/32",
    "80.15.229.1/32",
    "80.15.229.3/32",
    "80.15.230.1/32",
    "80.15.230.13/32",
    "80.15.230.15/32",
    "80.15.230.3/32",
    "80.15.231.1/32",
    "80.15.231.3/32",
    "80.15.232.1/32",
    "80.15.232.3/32",
    "80.15.233.1/32",
    "80.15.233.3/32",
    "80.15.235.17/32",
    "80.15.235.19/32",
    "80.15.235.25/32",
    "80.15.235.27/32",
    "80.15.235.5/32",
    "80.15.235.7/32",
    "80.15.243.17/32",
    "80.15.243.5/32",
    "80.15.244.17/32",
    "80.15.244.5/32",
    "80.15.245.1/32",
    "80.15.245.13/32",
    "80.15.245.15/32",
    "80.15.245.3/32",
    "80.15.245.5/32",
    "80.15.246.1/32",
    "80.15.246.13/32",
    "80.15.246.15/32",
    "80.15.246.3/32",
    "80.15.247.17/32",
    "80.15.247.5/32",
    "80.15.248.1/32",
    "80.15.248.13/32",
    "80.15.248.15/32",
    "80.15.248.3/32",
    "80.15.250.1/32",
    "80.15.250.9/32",
    "80.15.251.1/32",
    "80.15.251.11/32",
    "80.15.251.13/32",
    "80.15.251.15/32",
    "80.15.251.21/32",
    "80.15.251.23/32",
    "80.15.251.25/32",
    "80.15.251.29/32",
    "80.15.251.31/32",
    "80.15.251.9/32",
    "80.15.252.17/32",
    "80.15.252.19/32",
    "80.15.252.209/32",
    "80.15.252.21/32",
    "80.15.252.41/32",
    "80.15.252.43/32",
    "80.15.252.45/32",
    "80.15.252.47/32",
    "80.15.252.49/32",
    "80.15.252.61/32",
    "80.15.252.63/32",
    "80.15.252.65/32",
    "80.15.252.67/32",
    "80.15.252.81/32",
    "80.15.252.83/32",
    "80.15.252.85/32",
    "80.15.254.1/32",
    "80.240.113.4/32",
    "80.240.113.5/32",
    "80.240.113.6/32",
    "80.240.113.7/32",
    "80.240.113.8/32",
    "80.240.113.9/32",
    "80.240.124.10/32",
    "80.240.124.11/32",
    "80.240.124.4/32",
    "80.240.124.5/32",
    "80.240.124.6/32",
    "80.240.124.7/32",
    "80.240.124.8/32",
    "80.240.124.9/32",
    "80.93.210.4/32",
    "80.93.210.5/32",
    "80.93.210.6/32",
    "80.93.210.7/32",
    "80.93.215.10/32",
    "80.93.215.13/32",
    "80.93.215.14/32",
    "80.93.215.18/32",
    "80.93.215.19/32",
    "80.93.215.20/32",
    "80.93.215.21/32",
    "80.93.215.22/32",
    "80.93.215.4/32",
    "80.93.215.5/32",
    "80.93.215.6/32",
    "80.93.215.7/32",
    "80.93.215.8/32",
    "80.93.217.115/32",
    "80.93.217.163/32",
    "80.93.217.22/32",
    "80.93.217.225/32",
    "80.93.217.236/32",
    "80.93.217.245/32",
    "80.93.221.4/32",
    "80.93.221.5/32",
    "80.93.221.6/32",
    "80.93.221.7/32",
    "82.117.226.107/32",
    "82.117.226.126/32",
    "82.117.226.240/32",
    "82.148.98.42/32",
    "82.158.112.4/32",
    "82.158.112.5/32",
    "82.158.112.6/32",
    "82.158.112.7/32",
    "82.158.113.10/32",
    "82.158.113.11/32",
    "82.158.113.12/32",
    "82.158.113.13/32",
    "82.158.113.14/32",
    "82.158.113.15/32",
    "82.158.113.4/32",
    "82.158.113.5/32",
    "82.158.113.6/32",
    "82.158.113.7/32",
    "82.158.113.8/32",
    "82.213.5.50/32",
    "82.97.205.10/32",
    "82.97.205.11/32",
    "82.97.205.12/32",
    "82.97.205.13/32",
    "82.97.205.4/32",
    "82.97.205.5/32",
    "82.97.205.6/32",
    "82.97.205.7/32",
    "82.97.205.9/32",
    "84.38.4.4/32",
    "84.38.4.5/32",
    "84.38.4.6/32",
    "84.38.5.5/32",
    "84.38.5.6/32",
    "85.234.68.10/32",
    "85.234.68.11/32",
    "85.234.68.12/32",
    "85.234.68.4/32",
    "85.234.68.5/32",
    "85.234.68.6/32",
    "85.234.68.7/32",
    "85.234.68.8/32",
    "85.234.74.4/32",
    "85.234.74.5/32",
    "85.234.74.6/32",
    "85.234.74.7/32",
    "85.234.74.8/32",
    "85.234.75.10/32",
    "85.234.75.11/32",
    "85.234.75.12/32",
    "85.234.75.13/32",
    "85.234.75.14/32",
    "85.234.75.15/32",
    "85.234.75.16/32",
    "85.234.75.17/32",
    "85.234.75.18/32",
    "85.234.75.19/32",
    "85.234.75.20/32",
    "85.234.75.21/32",
    "85.234.75.22/32",
    "85.234.75.23/32",
    "85.234.75.24/32",
    "85.234.75.25/32",
    "85.234.75.26/32",
    "85.234.75.27/32",
    "85.234.75.28/32",
    "85.234.75.29/32",
    "85.234.75.30/32",
    "85.234.75.31/32",
    "85.234.75.4/32",
    "85.234.75.5/32",
    "85.234.75.6/32",
    "85.234.75.7/32",
    "85.234.75.8/32",
    "85.234.75.9/32",
    "85.234.77.10/32",
    "85.234.77.11/32",
    "85.234.77.12/32",
    "85.234.77.13/32",
    "85.234.77.14/32",
    "85.234.77.15/32",
    "85.234.77.16/32",
    "85.234.77.17/32",
    "85.234.77.4/32",
    "85.234.77.5/32",
    "85.234.77.6/32",
    "85.234.77.7/32",
    "85.234.77.8/32",
    "85.234.77.9/32",
    "85.234.83.177/32",
    "85.234.83.224/32",
    "85.234.83.253/32",
    "85.234.95.10/32",
    "85.234.95.4/32",
    "85.234.95.5/32",
    "85.234.95.6/32",
    "85.234.95.7/32",
    "85.234.95.8/32",
    "85.234.95.9/32",
    "85.92.120.117/32",
    "87.120.167.42/32",
    "87.120.167.43/32",
    "87.120.167.72/32",
    "87.120.167.96/32",
    "87.120.252.166/32",
    "87.120.252.185/32",
    "87.120.252.19/32",
    "87.120.252.22/32",
    "87.120.252.243/32",
    "87.120.252.83/32",
    "89.38.166.242/32",
    "89.38.166.243/32",
    "90.84.153.129/32",
    "90.84.153.130/32",
    "90.84.153.131/32",
    "90.84.153.161/32",
    "90.84.153.162/32",
    "90.84.153.163/32",
    "90.84.153.17/32",
    "90.84.153.18/32",
    "90.84.153.19/32",
    "90.84.153.193/32",
    "90.84.153.194/32",
    "90.84.153.195/32",
    "90.84.153.225/32",
    "90.84.153.226/32",
    "90.84.153.227/32",
    "90.84.153.33/32",
    "90.84.153.34/32",
    "90.84.153.35/32",
    "90.84.153.65/32",
    "90.84.153.66/32",
    "90.84.153.67/32",
    "90.84.153.97/32",
    "90.84.153.98/32",
    "90.84.153.99/32",
    "91.149.176.68/32",
    "91.149.176.70/32",
    "91.185.14.226/32",
    "91.243.81.199/32",
    "91.243.81.20/32",
    "91.243.81.66/32",
    "91.243.87.4/32",
    "91.243.87.5/32",
    "92.223.107.132/32",
    "92.223.107.133/32",
    "92.223.107.134/32",
    "92.223.107.135/32",
    "92.223.107.136/32",
    "92.223.107.137/32",
    "92.223.107.138/32",
    "92.223.107.139/32",
    "92.223.107.140/32",
    "92.223.107.141/32",
    "92.223.107.142/32",
    "92.223.107.143/32",
    "92.223.107.144/32",
    "92.223.107.145/32",
    "92.223.107.146/32",
    "92.223.107.147/32",
    "92.223.107.149/32",
    "92.223.107.150/32",
    "92.223.107.151/32",
    "92.223.107.152/32",
    "92.223.107.167/32",
    "92.223.107.36/32",
    "92.223.107.38/32",
    "92.223.107.39/32",
    "92.223.107.53/32",
    "92.223.107.54/32",
    "92.223.107.55/32",
    "92.223.116.200/32",
    "92.223.116.201/32",
    "92.223.116.204/32",
    "92.223.116.205/32",
    "92.223.116.206/32",
    "92.223.116.207/32",
    "92.223.116.208/32",
    "92.223.116.209/32",
    "92.223.116.210/32",
    "92.223.116.211/32",
    "92.223.116.212/32",
    "92.223.116.213/32",
    "92.223.116.214/32",
    "92.223.116.215/32",
    "92.223.116.216/32",
    "92.223.116.220/32",
    "92.223.116.221/32",
    "92.223.116.222/32",
    "92.223.116.223/32",
    "92.223.116.224/32",
    "92.223.116.225/32",
    "92.223.116.226/32",
    "92.223.116.227/32",
    "92.223.116.228/32",
    "92.223.116.229/32",
    "92.223.116.230/32",
    "92.223.116.231/32",
    "92.223.116.232/32",
    "92.223.116.233/32",
    "92.223.116.234/32",
    "92.223.116.235/32",
    "92.223.116.236/32",
    "92.223.116.237/32",
    "92.223.116.238/32",
    "92.223.116.239/32",
    "92.223.116.240/32",
    "92.223.116.241/32",
    "92.223.116.242/32",
    "92.223.116.243/32",
    "92.223.116.244/32",
    "92.223.117.68/32",
    "92.223.117.69/32",
    "92.223.117.70/32",
    "92.223.117.71/32",
    "92.223.117.72/32",
    "92.223.118.10/32",
    "92.223.118.11/32",
    "92.223.118.12/32",
    "92.223.118.13/32",
    "92.223.118.14/32",
    "92.223.118.15/32",
    "92.223.118.16/32",
    "92.223.118.17/32",
    "92.223.118.18/32",
    "92.223.118.19/32",
    "92.223.118.196/32",
    "92.223.118.197/32",
    "92.223.118.198/32",
    "92.223.118.20/32",
    "92.223.118.203/32",
    "92.223.118.204/32",
    "92.223.118.208/32",
    "92.223.118.209/32",
    "92.223.118.21/32",
    "92.223.118.210/32",
    "92.223.118.211/32",
    "92.223.118.212/32",
    "92.223.118.214/32",
    "92.223.118.215/32",
    "92.223.118.216/32",
    "92.223.118.217/32",
    "92.223.118.218/32",
    "92.223.118.219/32",
    "92.223.118.22/32",
    "92.223.118.220/32",
    "92.223.118.221/32",
    "92.223.118.222/32",
    "92.223.118.23/32",
    "92.223.118.24/32",
    "92.223.118.25/32",
    "92.223.118.26/32",
    "92.223.118.27/32",
    "92.223.118.28/32",
    "92.223.118.29/32",
    "92.223.118.30/32",
    "92.223.118.37/32",
    "92.223.118.6/32",
    "92.223.118.8/32",
    "92.223.12.10/32",
    "92.223.12.11/32",
    "92.223.12.12/32",
    "92.223.12.13/32",
    "92.223.12.18/32",
    "92.223.12.20/32",
    "92.223.12.21/32",
    "92.223.12.25/32",
    "92.223.12.26/32",
    "92.223.12.27/32",
    "92.223.12.9/32",
    "92.223.120.132/32",
    "92.223.120.133/32",
    "92.223.120.134/32",
    "92.223.120.135/32",
    "92.223.120.136/32",
    "92.223.120.137/32",
    "92.223.120.138/32",
    "92.223.120.139/32",
    "92.223.120.140/32",
    "92.223.120.141/32",
    "92.223.120.146/32",
    "92.223.124.10/32",
    "92.223.124.11/32",
    "92.223.124.12/32",
    "92.223.124.13/32",
    "92.223.124.14/32",
    "92.223.124.16/32",
    "92.223.124.17/32",
    "92.223.124.18/32",
    "92.223.124.19/32",
    "92.223.124.21/32",
    "92.223.124.22/32",
    "92.223.124.23/32",
    "92.223.124.24/32",
    "92.223.124.25/32",
    "92.223.124.26/32",
    "92.223.124.27/32",
    "92.223.124.28/32",
    "92.223.124.29/32",
    "92.223.124.30/32",
    "92.223.124.31/32",
    "92.223.124.32/32",
    "92.223.124.34/32",
    "92.223.124.36/32",
    "92.223.124.37/32",
    "92.223.124.38/32",
    "92.223.124.39/32",
    "92.223.124.4/32",
    "92.223.124.40/32",
    "92.223.124.41/32",
    "92.223.124.42/32",
    "92.223.124.44/32",
    "92.223.124.45/32",
    "92.223.124.46/32",
    "92.223.124.47/32",
    "92.223.124.48/32",
    "92.223.124.5/32",
    "92.223.124.50/32",
    "92.223.124.51/32",
    "92.223.124.52/32",
    "92.223.124.53/32",
    "92.223.124.54/32",
    "92.223.124.55/32",
    "92.223.124.56/32",
    "92.223.124.57/32",
    "92.223.124.58/32",
    "92.223.124.6/32",
    "92.223.124.7/32",
    "92.223.124.8/32",
    "92.223.124.9/32",
    "92.223.40.10/32",
    "92.223.40.12/32",
    "92.223.40.14/32",
    "92.223.40.15/32",
    "92.223.40.16/32",
    "92.223.40.17/32",
    "92.223.40.18/32",
    "92.223.40.4/32",
    "92.223.40.5/32",
    "92.223.40.6/32",
    "92.223.40.7/32",
    "92.223.40.8/32",
    "92.223.40.9/32",
    "92.223.47.10/32",
    "92.223.47.11/32",
    "92.223.47.12/32",
    "92.223.47.7/32",
    "92.223.47.8/32",
    "92.223.61.21/32",
    "92.223.63.10/32",
    "92.223.63.11/32",
    "92.223.63.21/32",
    "92.223.63.22/32",
    "92.223.63.23/32",
    "92.223.63.24/32",
    "92.223.63.25/32",
    "92.223.63.26/32",
    "92.223.63.27/32",
    "92.223.63.28/32",
    "92.223.63.29/32",
    "92.223.63.4/32",
    "92.223.63.5/32",
    "92.223.63.6/32",
    "92.223.63.8/32",
    "92.223.63.9/32",
    "92.223.74.20/32",
    "92.223.74.21/32",
    "92.223.74.26/32",
    "92.223.76.132/32",
    "92.223.76.133/32",
    "92.223.76.134/32",
    "92.223.76.135/32",
    "92.223.76.136/32",
    "92.223.76.20/32",
    "92.223.76.21/32",
    "92.223.76.22/32",
    "92.223.76.26/32",
    "92.223.76.27/32",
    "92.223.76.28/32",
    "92.223.78.22/32",
    "92.223.78.23/32",
    "92.223.78.24/32",
    "92.223.78.25/32",
    "92.223.78.26/32",
    "92.223.78.27/32",
    "92.223.78.28/32",
    "92.38.142.21/32",
    "92.38.142.25/32",
    "92.38.159.11/32",
    "92.38.159.12/32",
    "92.38.159.13/32",
    "92.38.159.15/32",
    "92.38.159.16/32",
    "92.38.159.17/32",
    "92.38.159.8/32",
    "92.38.168.5/32",
    "92.38.168.6/32",
    "92.38.168.7/32",
    "92.38.170.10/32",
    "92.38.170.6/32",
    "92.38.170.7/32",
    "92.38.170.8/32",
    "93.114.56.123/32",
    "93.114.56.29/32",
    "93.114.56.34/32",
    "93.114.56.45/32",
    "93.114.56.55/32",
    "93.114.56.76/32",
    "93.115.241.4/32",
    "93.115.241.5/32",
    "93.123.11.10/32",
    "93.123.11.16/32",
    "93.123.11.17/32",
    "93.123.11.18/32",
    "93.123.11.19/32",
    "93.123.11.21/32",
    "93.123.11.22/32",
    "93.123.11.23/32",
    "93.123.11.24/32",
    "93.123.11.25/32",
    "93.123.11.26/32",
    "93.123.11.27/32",
    "93.123.11.28/32",
    "93.123.11.29/32",
    "93.123.11.4/32",
    "93.123.11.5/32",
    "93.123.11.6/32",
    "93.123.11.7/32",
    "93.123.11.8/32",
    "93.123.11.9/32",
    "93.123.17.132/32",
    "93.123.17.133/32",
    "93.123.17.134/32",
    "93.123.17.135/32",
    "93.123.17.136/32",
    "93.123.17.137/32",
    "93.123.17.142/32",
    "93.123.17.143/32",
    "93.123.17.144/32",
    "93.123.17.145/32",
    "93.123.17.146/32",
    "93.123.17.147/32",
    "93.123.17.148/32",
    "93.123.17.149/32",
    "93.123.17.151/32",
    "93.123.17.158/32",
    "93.123.17.160/32",
    "93.123.17.161/32",
    "93.123.17.165/32",
    "93.123.17.166/32",
    "93.123.17.167/32",
    "93.123.17.168/32",
    "93.123.17.169/32",
    "93.123.17.170/32",
    "93.123.17.175/32",
    "93.123.17.176/32",
    "93.123.17.177/32",
    "93.123.17.178/32",
    "93.123.17.179/32",
    "93.123.17.180/32",
    "93.123.17.181/32",
    "93.123.17.182/32",
    "93.123.17.184/32",
    "93.123.17.186/32",
    "93.123.17.187/32",
    "93.123.17.188/32",
    "93.123.17.189/32",
    "93.123.17.190/32",
    "93.123.17.191/32",
    "93.123.17.192/32",
    "93.123.17.193/32",
    "93.123.17.194/32",
    "93.123.17.195/32",
    "93.123.38.4/32",
    "93.123.38.5/32",
    "93.174.165.10/32",
    "93.174.165.11/32",
    "93.174.165.12/32",
    "93.174.165.13/32",
    "93.174.165.14/32",
    "93.174.165.15/32",
    "93.174.165.16/32",
    "93.174.165.17/32",
    "93.174.165.18/32",
    "93.174.165.19/32",
    "93.174.165.20/32",
    "93.174.165.21/32",
    "93.174.165.7/32",
    "93.174.165.8/32",
    "93.174.165.9/32",
    "94.128.12.238/32",
    "94.129.12.210/32",
    "94.176.183.10/32",
    "94.176.183.13/32",
    "94.176.183.14/32",
    "94.176.183.15/32",
    "94.176.183.16/32",
    "94.176.183.17/32",
    "94.176.183.18/32",
    "94.176.183.19/32",
    "94.176.183.20/32",
    "94.176.183.21/32",
    "94.176.183.22/32",
    "94.176.183.24/32",
    "94.176.183.25/32",
    "94.176.183.4/32",
    "94.176.183.8/32",
    "94.177.131.25/32",
    "94.177.131.57/32",
    "94.177.131.92/32",
    "94.43.206.202/32",
    "95.85.68.4/32",
    "95.85.68.5/32",
    "95.85.68.6/32",
    "95.85.69.4/32",
    "95.85.69.5/32",
    "95.85.69.6/32",
    "95.85.69.7/32",
    "95.85.69.8/32",
    "95.85.92.4/32",
    "95.85.92.5/32",
    "95.85.92.6/32",
    "95.85.92.7/32",
    "95.85.92.8/32",
    "95.85.93.155/32",
    "95.85.93.160/32",
    "95.85.93.226/32",
    "95.85.93.236/32",
    "95.85.93.26/32",
    "95.85.93.31/32"
  ],
  "gocache": [
    "129.159.48.87/32",
    "140.82.27.226/32",
    "144.22.216.139/32",
    "150.230.84.126/32",
    "170.82.175.0/24",
    "170.84.29.208/29",
    "186.211.161.0/29",
    "186.211.188.192/28",
    "187.16.245.192/29",
    "187.85.159.176/29",
    "200.189.173.48/28",
    "200.98.28.70/32",
    "207.148.26.195/32",
    "207.246.123.237/32",
    "208.89.72.56/29",
    "34.95.148.131/32",
    "34.95.164.249/32",
    "34.95.168.58/32",
    "34.95.209.169/32",
    "34.95.213.225/32",
    "34.95.253.129/32",
    "35.247.222.78/32",
    "38.224.134.0/24",
    "45.77.97.241/32",
    "52.67.255.165/32"
  ],
  "google": [
    "104.154.0.0/15",
    "104.196.0.0/14",
    "104.237.160.0/19",
    "107.167.160.0/19",
    "107.178.192.0/18",
    "108.170.192.0/18",
    "108.177.0.0/17",
    "108.59.80.0/20",
    "130.211.0.0/16",
    "136.107.0.0/16",
    "136.108.0.0/14",
    "136.112.0.0/13",
    "136.120.0.0/22",
    "136.121.8.0/21",
    "136.124.0.0/15",
    "136.22.160.0/20",
    "136.22.176.0/21",
    "136.22.184.0/23",
    "136.22.186.0/24",
    "136.22.2.0/23",
    "136.22.4.0/23",
    "136.22.8.0/22",
    "136.23.39.0/24",
    "136.23.48.0/20",
    "136.23.64.0/18",
    "136.64.0.0/11",
    "142.250.0.0/15",
    "146.148.0.0/17",
    "162.120.128.0/17",
    "162.216.148.0/22",
    "162.222.176.0/21",
    "172.110.32.0/21",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "173.194.0.0/16",
    "173.255.112.0/20",
    "192.104.160.0/23",
    "192.158.28.0/22",
    "192.178.0.0/15",
    "193.186.4.0/24",
    "199.192.112.0/22",
    "199.223.232.0/21",
    "199.36.154.0/23",
    "199.36.156.0/24",
    "200.226.0.0/16",
    "2001:4860::/32",
    "207.175.0.0/16",
    "207.223.160.0/20",
    "208.117.224.0/19",
    "208.65.152.0/22",
    "208.68.108.0/22",
    "208.81.188.0/22",
    "209.85.128.0/17",
    "216.239.32.0/19",
    "216.252.220.0/22",
    "216.58.192.0/19",
    "216.73.80.0/20",
    "23.236.48.0/20",
    "23.251.128.0/19",
    "2404:6800::/32",
    "2404:f340::/32",
    "2600:1900::/28",
    "2605:ef80::/32",
    "2606:40::/32",
    "2606:73c0::/32",
    "2607:1c0:241:40::/60",
    "2607:1c0:300::/40",
    "2607:f8b0::/32",
    "2620:11a:a000::/40",
    "2620:120:e000::/40",
    "2800:3f0::/32",
    "2a00:1450::/32",
    "2c0f:fb50::/32",
    "34.0.0.0/15",
    "34.128.0.0/10",
    "34.16.0.0/12",
    "34.2.0.0/16",
    "34.3.0.0/23",
    "34.3.16.0/20",
    "34.3.3.0/24",
    "34.3.32.0/19",
    "34.3.4.0/24",
    "34.3.64.0/18",
    "34.3.8.0/21",
    "34.32.0.0/11",
    "34.4.0.0/14",
    "34.64.0.0/10",
    "34.8.0.0/13",
    "35.184.0.0/13",
    "35.192.0.0/14",
    "35.196.0.0/15",
    "35.198.0.0/16",
    "35.199.0.0/17",
    "35.199.128.0/18",
    "35.200.0.0/13",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
    "35.252.0.0/14",
    "64.15.112.0/20",
    "64.233.160.0/19",
    "66.102.0.0/20",
    "66.249.64.0/19",
    "70.32.128.0/19",
    "72.14.192.0/18",
    "74.114.24.0/21",
    "74.125.0.0/16",
    "8.228.0.0/14",
    "8.232.0.0/14",
    "8.236.0.0/15",
    "8.34.208.0/20",
    "8.35.192.0/20",
    "8.8.4.0/24",
    "8.8.8.0/24"
  ],
  "kinx": [
    "1.201.0.0/16",
    "103.6.100.0/22",
    "121.50.64.0/18",
    "121.78.0.0/16",
    "122.49.64.0/19",
    "122.49.96.0/20",
    "139.150.0.0/18",
    "139.150.128.0/17",
    "139.150.96.0/19",
    "182.161.96.0/19",
    "202.31.155.0/24",
    "203.236.192.0/18",
    "203.238.176.0/20",
    "203.246.160.0/20",
    "203.84.240.0/20",
    "210.97.240.0/20",
    "61.106.224.0/20",
    "61.251.16.0/20"
  ],
  "lgtelecom": [
    "180.210.192.0/21",
    "203.82.240.0/21"
  ],
  "qrator": [
    "185.104.208.0/22",
    "185.94.108.0/24",
    "66.110.32.128/30",
    "83.234.15.112/30",
    "87.245.197.192/30"
  ],
  "skbroadband": [
    "203.235.192.0/21",
    "203.235.202.0/23",
    "203.235.208.0/20",
    "203.235.224.0/19",
    "203.242.120.0/21",
    "203.242.64.0/19"
  ],
  "云盾": [
    "101.69.181.0/28",
    "103.100.71.0/24",
    "103.112.3.0/24",
    "103.136.251.0/28",
    "103.136.251.112/28",
    "103.219.29.64/26",
    "103.95.220.0/25",
    "103.95.221.0/24",
    "111.2.127.0/28",
    "111.61.59.160/27",
    "115.231.230.0/24",
    "116.136.249.0/24",
    "116.177.238.0/24",
    "117.18.111.128/25",
    "117.34.43.0/24",
    "118.121.192.0/24",
    "120.220.20.0/24",
    "120.53.244.232/32",
    "122.226.191.192/26",
    "122.9.54.0/24",
    "125.44.163.0/24",
    "128.1.170.0/24",
    "129.227.63.0/24",
    "129.28.193.74/32",
    "153.35.236.0/28",
    "156.241.6.0/24",
    "164.88.96.0/24",
    "164.88.98.0/24",
    "171.111.155.0/24",
    "175.6.227.128/26",
    "183.131.145.0/28",
    "183.131.200.0/24",
    "183.134.17.0/27",
    "183.232.187.0/24",
    "183.47.233.64/26",
    "202.181.144.128/25",
    "206.119.108.192/26",
    "206.119.109.192/26",
    "206.119.110.192/26",
    "206.119.114.192/26",
    "216.177.129.0/24",
    "223.111.172.128/28",
    "27.221.64.0/24",
    "27.221.68.0/24",
    "42.236.6.128/27",
    "45.159.59.0/24",
    "49.232.85.76/32",
    "58.222.57.0/28",
    "59.56.19.0/24",
    "59.56.78.0/24",
    "59.56.79.0/24",
    "60.163.162.32/27"
  ],
  "加速乐": [
    "1.255.100.0/24",
    "1.255.41.0/24",
    "1.31.128.0/24",
    "103.40.7.0/24",
    "106.119.182.0/24",
    "106.42.25.0/24",
    "111.13.147.0/24",
    "111.202.98.0/24",
    "111.47.226.0/24",
    "112.90.216.0/24",
    "113.107.238.0/24",
    "113.200.91.0/24",
    "113.207.76.0/24",
    "116.140.35.0/24",
    "116.211.155.0/24",
    "116.55.250.0/24",
    "117.21.219.0/24",
    "117.23.61.0/24",
    "118.212.233.0/24",
    "122.228.238.0/24",
    "123.155.158.0/24",
    "183.110.242.0/24",
    "183.222.96.0/24",
    "185.254.242.0/24",
    "203.90.247.0/24",
    "219.153.73.0/24",
    "58.58.81.0/24"
  ],
  "百度云加速": [
    "101.227.206.0/24",
    "101.227.207.0/24",
    "101.69.175.0/24",
    "111.132.134.0/24",
    "111.174.61.0/24",
    "111.174.63.0/24",
    "111.32.134.0/24",
    "111.32.135.0/24",
    "111.32.136.0/24",
    "111.63.67.0/24",
    "111.63.68.0/24",
    "112.25.89.0/24",
    "112.25.90.0/24",
    "112.25.91.0/24",
    "112.29.157.0/24",
    "112.29.158.0/24",
    "112.29.159.0/24",
    "113.207.100.0/24",
    "113.207.101.0/24",
    "113.207.102.0/24",
    "115.231.186.0/24",
    "115.231.187.0/24",
    "116.31.126.0/24",
    "116.31.127.0/24",
    "117.147.214.0/24",
    "117.147.215.0/24",
    "117.27.149.0/24",
    "117.34.13.0/24",
    "117.34.14.0/24",
    "117.34.28.0/24",
    "117.34.60.0/24",
    "117.34.61.0/24",
    "117.34.62.0/24",
    "119.147.134.0/24",
    "119.167.246.0/24",
    "119.188.132.0/24",
    "119.188.14.0/24",
    "119.188.9.0/24",
    "119.188.97.0/24",
    "119.84.1.0/24",
    "119.84.92.0/24",
    "119.84.93.0/24",
    "122.190.1.0/24",
    "122.190.2.0/24",
    "122.190.3.0/24",
    "122.246.5.0/24",
    "124.95.168.128/25",
    "124.95.188.0/24",
    "124.95.191.0/24",
    "125.39.174.0/24",
    "125.39.238.0/24",
    "125.39.239.0/24",
    "14.17.71.0/24",
    "150.138.149.0/24",
    "150.138.150.0/24",
    "150.138.151.0/24",
    "157.255.24.0/24",
    "157.255.25.0/24",
    "157.255.26.0/24",
    "180.163.113.0/24",
    "180.163.153.0/24",
    "180.163.154.0/24",
    "180.163.188.0/24",
    "180.163.189.0/24",
    "183.232.51.0/24",
    "183.232.53.0/24",
    "183.60.235.0/24",
    "183.61.177.0/24",
    "183.61.190.0/24",
    "183.61.236.0/24",
    "219.159.84.0/24",
    "220.170.184.0/24",
    "220.170.185.0/24",
    "220.170.186.0/24",
    "220.195.21.0/25",
    "220.195.22.0/24",
    "221.178.56.0/24",
    "221.178.57.0/24",
    "221.178.58.0/26",
    "222.216.190.0/24",
    "42.236.7.128/26",
    "42.236.7.64/27",
    "42.236.93.0/24",
    "42.236.94.0/24",
    "42.81.6.0/24",
    "42.81.8.0/24",
    "58.211.137.0/24",
    "58.211.2.0/24",
    "59.51.81.128/25",
    "60.217.232.0/24",
    "61.155.149.0/24",
    "61.155.165.0/24",
    "61.156.149.0/24",
    "61.182.136.0/24",
    "61.182.137.0/24",
    "61.241.118.0/24"
  ],
  "腾讯云": [
    "112.29.152.0/24",
    "112.90.51.0/24",
    "113.207.39.0/24",
    "115.231.37.0/24",
    "117.169.77.0/24",
    "117.34.36.0/24",
    "119.147.227.0/24",
    "120.41.44.0/24",
    "125.39.6.0/24",
    "180.163.68.0/24",
    "182.247.229.0/24",
    "218.60.33.0/24",
    "219.146.241.0/24",
    "220.170.91.0/24",
    "221.204.182.0/24",
    "222.161.220.0/24",
    "223.87.3.0/24",
    "42.236.2.0/24",
    "58.216.25.0/24",
    "60.174.156.0/24",
    "61.184.213.0/24",
    "61.240.150.0/24"
  ]
});

/** WAF provider address ranges (cdncheck sources_data.json `waf`). */
export const WAF_ADDRESS_RANGES = Object.freeze({
  "arvancloud": [
    "178.131.120.48/28",
    "185.143.232.0/22",
    "185.215.232.0/22",
    "188.229.116.16/30",
    "2.144.3.128/28",
    "37.32.16.0/27",
    "37.32.17.0/27",
    "37.32.18.0/27",
    "37.32.19.0/27",
    "78.157.36.112/28",
    "94.101.182.0/27",
    "94.101.183.0/28",
    "95.38.61.80/28"
  ],
  "cloudflare": [
    "1.0.0.0/24",
    "1.1.1.0/24",
    "103.21.244.0/23",
    "103.21.246.0/23",
    "103.22.200.0/23",
    "103.22.202.0/24",
    "103.22.203.0/24",
    "103.31.4.0/24",
    "103.31.5.0/24",
    "103.31.6.0/23",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "104.254.64.48/29",
    "104.28.0.0/15",
    "104.30.0.0/17",
    "104.30.128.0/22",
    "104.30.132.0/26",
    "104.30.132.112/31",
    "104.30.132.116/30",
    "104.30.132.120/29",
    "104.30.132.128/25",
    "104.30.132.64/27",
    "104.30.132.96/28",
    "104.30.133.0/24",
    "104.30.134.0/23",
    "104.30.136.0/21",
    "104.30.144.0/20",
    "104.30.160.128/27",
    "104.30.160.16/28",
    "104.30.160.160/29",
    "104.30.160.168/30",
    "104.30.160.172/31",
    "104.30.160.176/29",
    "104.30.160.184/30",
    "104.30.160.188/31",
    "104.30.160.192/27",
    "104.30.160.2/31",
    "104.30.160.224/28",
    "104.30.160.240/29",
    "104.30.160.248/30",
    "104.30.160.252/31",
    "104.30.160.32/27",
    "104.30.160.4/30",
    "104.30.160.64/26",
    "104.30.160.8/29",
    "104.30.161.128/26",
    "104.30.161.16/28",
    "104.30.161.192/29",
    "104.30.161.2/31",
    "104.30.161.202/31",
    "104.30.161.204/30",
    "104.30.161.208/28",
    "104.30.161.224/28",
    "104.30.161.240/29",
    "104.30.161.248/30",
    "104.30.161.252/31",
    "104.30.161.32/27",
    "104.30.161.4/30",
    "104.30.161.64/26",
    "104.30.161.8/29",
    "104.30.162.128/26",
    "104.30.162.16/28",
    "104.30.162.192/27",
    "104.30.162.2/31",
    "104.30.162.224/28",
    "104.30.162.240/29",
    "104.30.162.248/30",
    "104.30.162.252/31",
    "104.30.162.32/27",
    "104.30.162.4/30",
    "104.30.162.64/26",
    "104.30.162.8/29",
    "104.30.163.128/26",
    "104.30.163.16/28",
    "104.30.163.192/27",
    "104.30.163.2/31",
    "104.30.163.224/28",
    "104.30.163.240/29",
    "104.30.163.248/30",
    "104.30.163.252/31",
    "104.30.163.32/29",
    "104.30.163.4/30",
    "104.30.163.40/30",
    "104.30.163.44/31",
    "104.30.163.48/28",
    "104.30.163.64/26",
    "104.30.163.8/29",
    "104.30.164.0/27",
    "104.30.164.128/26",
    "104.30.164.192/27",
    "104.30.164.224/28",
    "104.30.164.240/29",
    "104.30.164.248/30",
    "104.30.164.252/31",
    "104.30.164.32/29",
    "104.30.164.42/31",
    "104.30.164.44/30",
    "104.30.164.48/28",
    "104.30.164.64/26",
    "104.30.165.128/26",
    "104.30.165.16/28",
    "104.30.165.192/27",
    "104.30.165.2/31",
    "104.30.165.224/28",
    "104.30.165.240/29",
    "104.30.165.248/30",
    "104.30.165.252/31",
    "104.30.165.32/27",
    "104.30.165.4/30",
    "104.30.165.64/26",
    "104.30.165.8/29",
    "104.30.166.128/26",
    "104.30.166.16/28",
    "104.30.166.192/27",
    "104.30.166.2/31",
    "104.30.166.224/28",
    "104.30.166.240/29",
    "104.30.166.248/30",
    "104.30.166.252/31",
    "104.30.166.32/27",
    "104.30.166.4/30",
    "104.30.166.64/26",
    "104.30.166.8/29",
    "104.30.167.128/26",
    "104.30.167.16/28",
    "104.30.167.192/27",
    "104.30.167.2/31",
    "104.30.167.224/28",
    "104.30.167.240/29",
    "104.30.167.248/30",
    "104.30.167.252/31",
    "104.30.167.32/27",
    "104.30.167.4/30",
    "104.30.167.64/26",
    "104.30.167.8/29",
    "104.30.168.128/26",
    "104.30.168.16/28",
    "104.30.168.192/27",
    "104.30.168.2/31",
    "104.30.168.224/28",
    "104.30.168.240/29",
    "104.30.168.248/30",
    "104.30.168.252/31",
    "104.30.168.32/27",
    "104.30.168.4/30",
    "104.30.168.64/26",
    "104.30.168.8/29",
    "104.30.169.128/26",
    "104.30.169.16/28",
    "104.30.169.192/27",
    "104.30.169.2/31",
    "104.30.169.224/28",
    "104.30.169.240/29",
    "104.30.169.248/30",
    "104.30.169.252/31",
    "104.30.169.32/27",
    "104.30.169.4/30",
    "104.30.169.64/26",
    "104.30.169.8/29",
    "104.30.170.128/26",
    "104.30.170.16/28",
    "104.30.170.192/27",
    "104.30.170.2/31",
    "104.30.170.224/28",
    "104.30.170.240/29",
    "104.30.170.248/30",
    "104.30.170.252/31",
    "104.30.170.32/27",
    "104.30.170.4/30",
    "104.30.170.64/26",
    "104.30.170.8/29",
    "104.30.171.128/26",
    "104.30.171.16/28",
    "104.30.171.192/27",
    "104.30.171.2/31",
    "104.30.171.224/28",
    "104.30.171.240/29",
    "104.30.171.248/30",
    "104.30.171.252/31",
    "104.30.171.32/27",
    "104.30.171.4/30",
    "104.30.171.64/26",
    "104.30.171.8/29",
    "104.30.172.128/26",
    "104.30.172.16/28",
    "104.30.172.192/27",
    "104.30.172.2/31",
    "104.30.172.224/28",
    "104.30.172.240/29",
    "104.30.172.248/30",
    "104.30.172.252/31",
    "104.30.172.32/27",
    "104.30.172.4/30",
    "104.30.172.64/26",
    "104.30.172.8/29",
    "104.30.173.128/26",
    "104.30.173.16/28",
    "104.30.173.192/27",
    "104.30.173.2/31",
    "104.30.173.224/28",
    "104.30.173.240/29",
    "104.30.173.248/30",
    "104.30.173.252/31",
    "104.30.173.32/27",
    "104.30.173.4/30",
    "104.30.173.64/26",
    "104.30.173.8/29",
    "104.30.174.128/26",
    "104.30.174.16/28",
    "104.30.174.192/27",
    "104.30.174.2/31",
    "104.30.174.224/28",
    "104.30.174.240/29",
    "104.30.174.248/30",
    "104.30.174.252/31",
    "104.30.174.32/27",
    "104.30.174.4/30",
    "104.30.174.64/26",
    "104.30.174.8/29",
    "104.30.175.128/26",
    "104.30.175.16/28",
    "104.30.175.192/28",
    "104.30.175.2/31",
    "104.30.175.208/31",
    "104.30.175.212/30",
    "104.30.175.216/29",
    "104.30.175.224/27",
    "104.30.175.32/27",
    "104.30.175.4/30",
    "104.30.175.64/26",
    "104.30.175.8/29",
    "104.30.176.128/26",
    "104.30.176.16/28",
    "104.30.176.192/27",
    "104.30.176.2/31",
    "104.30.176.224/28",
    "104.30.176.240/29",
    "104.30.176.248/30",
    "104.30.176.252/31",
    "104.30.176.32/27",
    "104.30.176.4/30",
    "104.30.176.64/26",
    "104.30.176.8/29",
    "104.30.177.128/26",
    "104.30.177.16/28",
    "104.30.177.192/27",
    "104.30.177.2/31",
    "104.30.177.224/28",
    "104.30.177.240/29",
    "104.30.177.248/30",
    "104.30.177.252/31",
    "104.30.177.32/27",
    "104.30.177.4/30",
    "104.30.177.64/26",
    "104.30.177.8/29",
    "104.30.178.128/26",
    "104.30.178.16/28",
    "104.30.178.192/27",
    "104.30.178.2/31",
    "104.30.178.224/28",
    "104.30.178.240/29",
    "104.30.178.248/30",
    "104.30.178.252/31",
    "104.30.178.32/27",
    "104.30.178.4/30",
    "104.30.178.64/26",
    "104.30.178.8/29",
    "104.30.179.128/26",
    "104.30.179.16/28",
    "104.30.179.192/27",
    "104.30.179.2/31",
    "104.30.179.224/28",
    "104.30.179.240/29",
    "104.30.179.248/30",
    "104.30.179.252/31",
    "104.30.179.32/27",
    "104.30.179.4/30",
    "104.30.179.64/26",
    "104.30.179.8/29",
    "104.30.180.128/25",
    "104.30.180.16/30",
    "104.30.180.2/31",
    "104.30.180.20/31",
    "104.30.180.22/31",
    "104.30.180.24/29",
    "104.30.180.32/27",
    "104.30.180.4/30",
    "104.30.180.64/26",
    "104.30.180.8/29",
    "104.30.181.0/24",
    "104.30.182.0/23",
    "104.30.184.0/21",
    "104.30.192.0/18",
    "104.31.0.0/16",
    "108.162.192.0/18",
    "12.105.93.232/29",
    "12.108.175.112/29",
    "12.108.175.96/29",
    "12.12.46.184/29",
    "12.12.48.248/29",
    "12.149.17.72/29",
    "12.149.17.88/29",
    "12.149.22.136/29",
    "12.149.22.64/29",
    "12.161.211.24/29",
    "12.161.215.128/28",
    "12.180.213.144/29",
    "12.180.215.192/29",
    "12.180.215.80/28",
    "12.6.193.184/29",
    "12.6.193.192/28",
    "12.6.207.192/29",
    "12.6.207.248/29",
    "12.7.136.80/29",
    "12.96.38.48/28",
    "12.96.38.96/28",
    "12.96.39.56/29",
    "131.0.72.0/22",
    "131.226.199.128/29",
    "131.226.204.136/29",
    "131.226.208.88/29",
    "131.226.216.200/29",
    "131.226.225.88/29",
    "131.239.93.232/30",
    "134.195.26.0/23",
    "141.101.112.0/21",
    "141.101.120.0/22",
    "141.101.124.0/23",
    "141.101.126.0/24",
    "141.101.127.0/24",
    "141.101.64.0/21",
    "141.101.72.0/23",
    "141.101.74.0/23",
    "141.101.76.0/23",
    "141.101.78.0/23",
    "141.101.80.0/20",
    "141.101.96.0/20",
    "148.109.52.160/29",
    "149.11.0.124/30",
    "149.11.120.88/29",
    "149.11.162.28/30",
    "149.11.170.80/29",
    "149.11.203.152/29",
    "149.11.204.216/29",
    "149.11.21.216/30",
    "149.11.36.40/29",
    "149.11.72.80/29",
    "149.137.222.24/29",
    "149.14.10.152/29",
    "149.14.102.64/29",
    "149.14.135.80/29",
    "149.14.192.8/29",
    "149.14.228.104/29",
    "149.14.228.136/29",
    "149.14.228.144/29",
    "149.14.232.120/31",
    "149.14.250.240/29",
    "149.14.36.184/29",
    "149.14.58.104/29",
    "149.14.68.24/29",
    "149.14.74.112/29",
    "149.14.83.56/29",
    "149.6.116.192/29",
    "149.6.12.24/29",
    "149.6.131.96/29",
    "149.6.137.0/29",
    "149.6.138.252/30",
    "149.6.142.128/29",
    "149.6.145.16/29",
    "149.6.150.12/31",
    "149.6.153.216/29",
    "149.6.154.128/30",
    "149.6.169.64/29",
    "149.6.174.64/29",
    "149.6.177.168/29",
    "149.6.182.72/29",
    "149.6.184.8/29",
    "149.6.188.40/29",
    "149.6.191.136/29",
    "149.6.191.232/29",
    "149.6.22.48/29",
    "149.6.23.16/29",
    "149.6.24.232/30",
    "149.6.30.208/29",
    "149.6.39.208/30",
    "149.6.50.72/29",
    "149.6.55.192/29",
    "149.6.58.192/29",
    "149.6.67.96/29",
    "149.6.68.96/29",
    "149.6.71.16/29",
    "151.243.133.0/24",
    "154.18.0.176/29",
    "154.18.100.48/29",
    "154.18.20.104/29",
    "154.18.20.80/29",
    "154.18.24.8/29",
    "154.18.28.112/29",
    "154.18.32.32/29",
    "154.18.33.32/29",
    "154.18.6.80/29",
    "154.18.7.192/29",
    "154.18.97.232/29",
    "154.18.98.136/29",
    "154.200.89.0/24",
    "154.51.129.0/24",
    "154.51.160.0/24",
    "158.51.64.0/23",
    "158.94.212.0/24",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "176.126.206.0/23",
    "177.128.204.0/22",
    "182.23.210.0/24",
    "184.104.191.96/30",
    "184.104.203.156/30",
    "184.105.39.104/29",
    "184.105.45.8/30",
    "185.122.0.0/24",
    "185.122.1.0/24",
    "185.122.2.0/23",
    "185.148.104.0/23",
    "185.162.157.0/29",
    "185.176.24.0/23",
    "185.176.26.0/24",
    "185.212.144.0/22",
    "188.114.104.0/23",
    "188.114.106.0/23",
    "188.114.108.0/22",
    "188.114.96.0/21",
    "190.93.240.0/20",
    "194.53.53.0/24",
    "197.234.240.0/22",
    "198.24.51.200/29",
    "198.41.128.0/17",
    "198.58.78.16/29",
    "199.100.12.8/29",
    "199.100.2.48/29",
    "199.100.2.96/29",
    "199.100.4.96/29",
    "199.27.128.0/21",
    "2001:1890:1d00:5c00::/56",
    "2001:1890:1d00:6a00::/56",
    "2001:1890:1d02:af00::/56",
    "2001:1890:1d02:b000::/55",
    "2001:1890:1d03:b300::/56",
    "2001:1890:1d03:b400::/56",
    "2001:1890:1d0c:3000::/56",
    "2001:1890:1d0c:3500::/56",
    "2001:1890:1d0d:1200::/56",
    "2001:1890:1d0d:2700::/56",
    "2001:1890:1d0d:2800::/56",
    "2001:1890:1d10:6000::/56",
    "2001:1890:1d10:8f00::/56",
    "2001:1890:1d28:3d00::/56",
    "2001:1890:1d28:7700::/56",
    "2001:1890:1d28:7800::/56",
    "2001:1890:1d28:9300::/56",
    "2001:1890:1d2a:ac00::/56",
    "2001:1890:1d2a:ae00::/56",
    "2001:1890:1d34:700::/56",
    "2001:1890:1d54:300::/56",
    "2001:1890:1d54:400::/56",
    "2001:868:100:5300::/56",
    "201.234.119.184/29",
    "201.33.208.0/23",
    "201.33.214.0/24",
    "201.33.221.0/24",
    "202.79.213.130/31",
    "202.79.213.132/31",
    "204.4.235.0/24",
    "206.249.0.168/29",
    "206.249.0.208/29",
    "206.249.2.96/29",
    "207.210.209.232/29",
    "208.184.102.134/31",
    "208.184.122.48/30",
    "208.184.122.52/31",
    "209.133.122.162/31",
    "209.51.175.216/30",
    "209.51.175.32/30",
    "209.66.114.234/31",
    "212.47.213.184/30",
    "212.98.116.40/30",
    "213.128.134.216/29",
    "213.61.237.208/29",
    "213.61.237.240/29",
    "216.163.179.0/24",
    "216.66.83.124/31",
    "216.66.89.228/30",
    "216.66.90.124/30",
    "217.110.33.56/29",
    "2400:cb00::/32",
    "2405:8100::/32",
    "2405:b500::/32",
    "2600:cc01:c003:2::/64",
    "2600:cc06:c003::/64",
    "2600:cc0a:c003::/64",
    "2600:cc0b:c003::/64",
    "2600:cc0c:c003::/64",
    "2602:fc28::/36",
    "2606:4700::/32",
    "2606:54c0::/28",
    "27.111.205.104/29",
    "2803:f800::/32",
    "2804:9018::/32",
    "2a06:98c0:1000::/38",
    "2a06:98c0:1400::/38",
    "2a06:98c0:1800::/38",
    "2a06:98c0:1c00::/38",
    "2a06:98c0:2000::/36",
    "2a06:98c0:3000::/36",
    "2a06:98c0:4000::/34",
    "2a06:98c0:8000::/33",
    "2a06:98c0::/36",
    "2a06:98c1::/32",
    "2a06:98c2::/31",
    "2a06:98c4::/30",
    "2a09:bac0:1000:1000::/53",
    "2a09:bac0:1000:1800::/62",
    "2a09:bac0:1000:1804::/63",
    "2a09:bac0:1000:1806::/64",
    "2a09:bac0:1000:1807::/64",
    "2a09:bac0:1000:1808::/61",
    "2a09:bac0:1000:1810::/60",
    "2a09:bac0:1000:1820::/59",
    "2a09:bac0:1000:1840::/58",
    "2a09:bac0:1000:1880::/57",
    "2a09:bac0:1000:1900::/56",
    "2a09:bac0:1000:1a00::/55",
    "2a09:bac0:1000:1c00::/54",
    "2a09:bac0:1000:2000::/60",
    "2a09:bac0:1000:200::/58",
    "2a09:bac0:1000:2010::/60",
    "2a09:bac0:1000:2020::/59",
    "2a09:bac0:1000:2040::/58",
    "2a09:bac0:1000:2080::/57",
    "2a09:bac0:1000:2100::/56",
    "2a09:bac0:1000:2200::/55",
    "2a09:bac0:1000:2400::/54",
    "2a09:bac0:1000:240::/59",
    "2a09:bac0:1000:260::/60",
    "2a09:bac0:1000:270::/62",
    "2a09:bac0:1000:274::/64",
    "2a09:bac0:1000:275::/64",
    "2a09:bac0:1000:276::/63",
    "2a09:bac0:1000:278::/61",
    "2a09:bac0:1000:2800::/53",
    "2a09:bac0:1000:280::/57",
    "2a09:bac0:1000:3000::/52",
    "2a09:bac0:1000:300::/57",
    "2a09:bac0:1000:380::/58",
    "2a09:bac0:1000:3c0::/59",
    "2a09:bac0:1000:3e0::/61",
    "2a09:bac0:1000:3e8::/63",
    "2a09:bac0:1000:3ea::/64",
    "2a09:bac0:1000:3eb::/64",
    "2a09:bac0:1000:3ec::/62",
    "2a09:bac0:1000:3f0::/60",
    "2a09:bac0:1000:4000::/50",
    "2a09:bac0:1000:400::/54",
    "2a09:bac0:1000:8000::/49",
    "2a09:bac0:1000:800::/57",
    "2a09:bac0:1000:880::/58",
    "2a09:bac0:1000:8c0::/59",
    "2a09:bac0:1000:8e0::/62",
    "2a09:bac0:1000:8e4::/64",
    "2a09:bac0:1000:8e5::/64",
    "2a09:bac0:1000:8e6::/63",
    "2a09:bac0:1000:8e8::/61",
    "2a09:bac0:1000:8f0::/60",
    "2a09:bac0:1000:900::/56",
    "2a09:bac0:1000::/55",
    "2a09:bac0:1000:a00::/55",
    "2a09:bac0:1000:c00::/58",
    "2a09:bac0:1000:c40::/63",
    "2a09:bac0:1000:c42::/64",
    "2a09:bac0:1000:c43::/64",
    "2a09:bac0:1000:c44::/62",
    "2a09:bac0:1000:c48::/61",
    "2a09:bac0:1000:c50::/63",
    "2a09:bac0:1000:c52::/64",
    "2a09:bac0:1000:c53::/64",
    "2a09:bac0:1000:c54::/62",
    "2a09:bac0:1000:c58::/61",
    "2a09:bac0:1000:c60::/59",
    "2a09:bac0:1000:c80::/59",
    "2a09:bac0:1000:ca0::/64",
    "2a09:bac0:1000:ca1::/64",
    "2a09:bac0:1000:ca2::/63",
    "2a09:bac0:1000:ca4::/62",
    "2a09:bac0:1000:ca8::/62",
    "2a09:bac0:1000:cac::/64",
    "2a09:bac0:1000:cad::/64",
    "2a09:bac0:1000:cae::/63",
    "2a09:bac0:1000:cb0::/60",
    "2a09:bac0:1000:cc0::/58",
    "2a09:bac0:1000:d00::/58",
    "2a09:bac0:1000:d40::/61",
    "2a09:bac0:1000:d48::/62",
    "2a09:bac0:1000:d4c::/63",
    "2a09:bac0:1000:d4e::/63",
    "2a09:bac0:1000:d50::/60",
    "2a09:bac0:1000:d60::/61",
    "2a09:bac0:1000:d68::/62",
    "2a09:bac0:1000:d6c::/64",
    "2a09:bac0:1000:d6d::/64",
    "2a09:bac0:1000:d6e::/63",
    "2a09:bac0:1000:d70::/63",
    "2a09:bac0:1000:d72::/64",
    "2a09:bac0:1000:d73::/64",
    "2a09:bac0:1000:d74::/62",
    "2a09:bac0:1000:d78::/63",
    "2a09:bac0:1000:d7a::/64",
    "2a09:bac0:1000:d7b::/64",
    "2a09:bac0:1000:d7c::/62",
    "2a09:bac0:1000:d80::/64",
    "2a09:bac0:1000:d81::/64",
    "2a09:bac0:1000:d82::/63",
    "2a09:bac0:1000:d84::/63",
    "2a09:bac0:1000:d86::/64",
    "2a09:bac0:1000:d87::/64",
    "2a09:bac0:1000:d88::/64",
    "2a09:bac0:1000:d89::/64",
    "2a09:bac0:1000:d8a::/63",
    "2a09:bac0:1000:d8c::/62",
    "2a09:bac0:1000:d90::/63",
    "2a09:bac0:1000:d92::/64",
    "2a09:bac0:1000:d93::/64",
    "2a09:bac0:1000:d94::/64",
    "2a09:bac0:1000:d95::/64",
    "2a09:bac0:1000:d96::/64",
    "2a09:bac0:1000:d97::/64",
    "2a09:bac0:1000:d98::/61",
    "2a09:bac0:1000:da0::/64",
    "2a09:bac0:1000:da1::/64",
    "2a09:bac0:1000:da2::/64",
    "2a09:bac0:1000:da3::/64",
    "2a09:bac0:1000:da4::/62",
    "2a09:bac0:1000:da8::/62",
    "2a09:bac0:1000:dac::/63",
    "2a09:bac0:1000:dae::/64",
    "2a09:bac0:1000:daf::/64",
    "2a09:bac0:1000:db0::/62",
    "2a09:bac0:1000:db4::/64",
    "2a09:bac0:1000:db5::/64",
    "2a09:bac0:1000:db6::/63",
    "2a09:bac0:1000:db8::/62",
    "2a09:bac0:1000:dbc::/64",
    "2a09:bac0:1000:dbd::/64",
    "2a09:bac0:1000:dbe::/63",
    "2a09:bac0:1000:dc0::/59",
    "2a09:bac0:1000:de0::/60",
    "2a09:bac0:1000:df0::/62",
    "2a09:bac0:1000:df4::/64",
    "2a09:bac0:1000:df5::/64",
    "2a09:bac0:1000:df6::/63",
    "2a09:bac0:1000:df8::/61",
    "2a09:bac0:1000:e00::/58",
    "2a09:bac0:1000:e40::/60",
    "2a09:bac0:1000:e50::/63",
    "2a09:bac0:1000:e52::/64",
    "2a09:bac0:1000:e53::/64",
    "2a09:bac0:1000:e54::/62",
    "2a09:bac0:1000:e58::/62",
    "2a09:bac0:1000:e5c::/64",
    "2a09:bac0:1000:e5d::/64",
    "2a09:bac0:1000:e5e::/63",
    "2a09:bac0:1000:e60::/59",
    "2a09:bac0:1000:e80::/57",
    "2a09:bac0:1000:f00::/60",
    "2a09:bac0:1000:f10::/64",
    "2a09:bac0:1000:f11::/64",
    "2a09:bac0:1000:f12::/63",
    "2a09:bac0:1000:f14::/62",
    "2a09:bac0:1000:f18::/63",
    "2a09:bac0:1000:f1a::/64",
    "2a09:bac0:1000:f1b::/64",
    "2a09:bac0:1000:f1c::/62",
    "2a09:bac0:1000:f20::/59",
    "2a09:bac0:1000:f40::/58",
    "2a09:bac0:1000:f80::/57",
    "2a09:bac0:1001:1000::/63",
    "2a09:bac0:1001:1002::/64",
    "2a09:bac0:1001:1003::/64",
    "2a09:bac0:1001:1004::/62",
    "2a09:bac0:1001:1008::/61",
    "2a09:bac0:1001:100::/57",
    "2a09:bac0:1001:1010::/60",
    "2a09:bac0:1001:1020::/59",
    "2a09:bac0:1001:1040::/58",
    "2a09:bac0:1001:1080::/57",
    "2a09:bac0:1001:1100::/56",
    "2a09:bac0:1001:1200::/55",
    "2a09:bac0:1001:1400::/54",
    "2a09:bac0:1001:1800::/53",
    "2a09:bac0:1001:180::/59",
    "2a09:bac0:1001:1a0::/60",
    "2a09:bac0:1001:1b0::/62",
    "2a09:bac0:1001:1b4::/63",
    "2a09:bac0:1001:1b6::/64",
    "2a09:bac0:1001:1b7::/64",
    "2a09:bac0:1001:1b8::/61",
    "2a09:bac0:1001:1c0::/58",
    "2a09:bac0:1001:2000::/51",
    "2a09:bac0:1001:200::/55",
    "2a09:bac0:1001:4000::/50",
    "2a09:bac0:1001:400::/55",
    "2a09:bac0:1001:600::/57",
    "2a09:bac0:1001:680::/58",
    "2a09:bac0:1001:6c0::/60",
    "2a09:bac0:1001:6d0::/61",
    "2a09:bac0:1001:6d8::/63",
    "2a09:bac0:1001:6da::/63",
    "2a09:bac0:1001:6dc::/62",
    "2a09:bac0:1001:6e0::/59",
    "2a09:bac0:1001:700::/56",
    "2a09:bac0:1001:8000::/49",
    "2a09:bac0:1001:800::/56",
    "2a09:bac0:1001:900::/59",
    "2a09:bac0:1001:920::/60",
    "2a09:bac0:1001:930::/63",
    "2a09:bac0:1001:932::/64",
    "2a09:bac0:1001:933::/64",
    "2a09:bac0:1001:934::/62",
    "2a09:bac0:1001:938::/61",
    "2a09:bac0:1001:940::/60",
    "2a09:bac0:1001:950::/63",
    "2a09:bac0:1001:952::/64",
    "2a09:bac0:1001:953::/64",
    "2a09:bac0:1001:954::/62",
    "2a09:bac0:1001:958::/61",
    "2a09:bac0:1001:960::/59",
    "2a09:bac0:1001:980::/57",
    "2a09:bac0:1001::/56",
    "2a09:bac0:1001:a00::/55",
    "2a09:bac0:1001:c00::/57",
    "2a09:bac0:1001:c80::/58",
    "2a09:bac0:1001:cc0::/64",
    "2a09:bac0:1001:cc1::/64",
    "2a09:bac0:1001:cc2::/63",
    "2a09:bac0:1001:cc4::/62",
    "2a09:bac0:1001:cc8::/62",
    "2a09:bac0:1001:ccc::/64",
    "2a09:bac0:1001:ccd::/64",
    "2a09:bac0:1001:cce::/63",
    "2a09:bac0:1001:cd0::/60",
    "2a09:bac0:1001:ce0::/59",
    "2a09:bac0:1001:d00::/57",
    "2a09:bac0:1001:d80::/58",
    "2a09:bac0:1001:dc0::/60",
    "2a09:bac0:1001:dd0::/64",
    "2a09:bac0:1001:dd1::/64",
    "2a09:bac0:1001:dd2::/63",
    "2a09:bac0:1001:dd4::/62",
    "2a09:bac0:1001:dd8::/61",
    "2a09:bac0:1001:de0::/59",
    "2a09:bac0:1001:e00::/57",
    "2a09:bac0:1001:e80::/58",
    "2a09:bac0:1001:ec0::/63",
    "2a09:bac0:1001:ec2::/63",
    "2a09:bac0:1001:ec4::/62",
    "2a09:bac0:1001:ec8::/63",
    "2a09:bac0:1001:eca::/64",
    "2a09:bac0:1001:ecb::/64",
    "2a09:bac0:1001:ecc::/62",
    "2a09:bac0:1001:ed0::/62",
    "2a09:bac0:1001:ed4::/64",
    "2a09:bac0:1001:ed5::/64",
    "2a09:bac0:1001:ed6::/63",
    "2a09:bac0:1001:ed8::/61",
    "2a09:bac0:1001:ee0::/64",
    "2a09:bac0:1001:ee1::/64",
    "2a09:bac0:1001:ee2::/63",
    "2a09:bac0:1001:ee4::/62",
    "2a09:bac0:1001:ee8::/61",
    "2a09:bac0:1001:ef0::/60",
    "2a09:bac0:1001:f00::/57",
    "2a09:bac0:1001:f80::/58",
    "2a09:bac0:1001:fc0::/59",
    "2a09:bac0:1001:fe0::/60",
    "2a09:bac0:1001:ff0::/64",
    "2a09:bac0:1001:ff1::/64",
    "2a09:bac0:1001:ff2::/63",
    "2a09:bac0:1001:ff4::/62",
    "2a09:bac0:1001:ff8::/61",
    "2a09:bac0:1002::/47",
    "2a09:bac0:1004::/46",
    "2a09:bac0:1008::/45",
    "2a09:bac0:1010::/44",
    "2a09:bac0:1020::/43",
    "2a09:bac0:1040::/42",
    "2a09:bac0:1080::/41",
    "2a09:bac0:1100::/40",
    "2a09:bac0:1200::/39",
    "2a09:bac0:1400::/38",
    "2a09:bac0:1800::/37",
    "2a09:bac0:2000::/35",
    "2a09:bac0:4000::/34",
    "2a09:bac0:8000::/33",
    "2a09:bac0::/36",
    "2a09:bac1::/32",
    "2a09:bac2::/31",
    "2a09:bac4::/30",
    "2a14:a087:1::/48",
    "2c0f:f248:1000::/36",
    "2c0f:f248:2000::/35",
    "2c0f:f248:4000::/34",
    "2c0f:f248:8000::/33",
    "2c0f:f248::/36",
    "38.104.105.248/29",
    "38.104.108.176/29",
    "38.104.108.208/29",
    "38.104.108.48/30",
    "38.104.109.12/31",
    "38.104.135.16/29",
    "38.104.154.184/29",
    "38.104.163.152/31",
    "38.104.174.152/29",
    "38.104.190.228/31",
    "38.104.212.120/29",
    "38.104.234.160/29",
    "38.104.44.12/31",
    "38.104.44.8/30",
    "38.104.49.112/29",
    "38.104.50.96/31",
    "38.104.54.232/29",
    "38.104.83.168/29",
    "38.104.84.252/30",
    "38.104.87.248/29",
    "38.122.1.72/29",
    "38.122.1.80/29",
    "38.122.124.96/29",
    "38.122.181.132/30",
    "38.122.229.0/29",
    "38.122.41.184/29",
    "38.122.42.112/29",
    "38.122.46.216/31",
    "38.122.49.104/29",
    "38.122.74.136/29",
    "38.122.74.152/29",
    "38.122.74.160/29",
    "38.122.78.240/29",
    "38.122.79.56/29",
    "38.122.79.80/29",
    "38.140.104.96/29",
    "38.140.136.72/29",
    "38.140.148.104/29",
    "38.140.149.80/29",
    "38.140.174.232/29",
    "38.140.176.80/29",
    "38.140.177.64/29",
    "38.140.185.232/29",
    "38.140.187.56/29",
    "38.140.213.168/29",
    "38.140.30.208/30",
    "38.140.36.192/31",
    "38.140.49.40/29",
    "38.140.98.184/29",
    "38.142.1.192/29",
    "38.142.1.64/29",
    "38.142.110.96/29",
    "38.142.120.80/29",
    "38.142.2.104/29",
    "38.142.50.152/29",
    "38.142.51.248/29",
    "38.142.64.152/29",
    "38.142.88.208/29",
    "38.32.1.120/29",
    "38.32.111.184/31",
    "38.32.111.40/29",
    "38.32.132.16/29",
    "38.32.176.56/29",
    "38.32.185.176/29",
    "38.32.186.176/29",
    "38.32.212.128/29",
    "38.32.228.0/29",
    "38.32.60.88/29",
    "38.88.164.216/29",
    "38.88.165.36/30",
    "38.88.189.12/31",
    "38.88.189.248/29",
    "38.88.196.164/31",
    "38.88.214.140/30",
    "38.88.224.84/30",
    "38.88.232.224/29",
    "38.88.240.184/30",
    "38.88.53.56/29",
    "38.88.56.104/29",
    "38.88.7.56/29",
    "40.133.36.40/29",
    "45.131.208.0/22",
    "45.131.4.0/22",
    "45.8.211.0/24",
    "57.133.194.40/29",
    "62.96.156.96/29",
    "64.137.111.0/24",
    "65.205.150.0/24",
    "74.209.240.160/29",
    "77.232.140.0/24",
    "8.10.148.0/24",
    "8.14.199.0/24",
    "8.14.201.0/24",
    "8.14.202.0/23",
    "8.14.204.0/24",
    "8.17.205.0/24",
    "8.17.206.0/24",
    "8.17.207.0/24",
    "8.18.113.0/24",
    "8.18.194.0/23",
    "8.18.196.0/24",
    "8.18.50.0/24",
    "8.19.8.0/24",
    "8.20.100.0/23",
    "8.20.103.0/24",
    "8.20.122.0/23",
    "8.20.124.0/24",
    "8.20.125.0/24",
    "8.20.126.0/23",
    "8.20.253.0/24",
    "8.21.10.0/24",
    "8.21.11.0/24",
    "8.21.110.0/23",
    "8.21.12.0/24",
    "8.21.13.0/24",
    "8.21.238.0/23",
    "8.21.8.0/23",
    "8.23.139.0/24",
    "8.23.240.0/24",
    "8.24.242.0/23",
    "8.24.244.0/24",
    "8.24.87.0/24",
    "8.25.249.0/24",
    "8.25.96.0/23",
    "8.26.180.0/24",
    "8.26.182.0/24",
    "8.27.64.0/24",
    "8.27.66.0/23",
    "8.27.68.0/23",
    "8.27.70.0/24",
    "8.27.79.0/24",
    "8.28.126.0/23",
    "8.28.20.0/24",
    "8.28.213.0/24",
    "8.28.82.0/24",
    "8.29.105.0/24",
    "8.29.109.0/24",
    "8.29.228.0/24",
    "8.29.230.0/23",
    "8.30.234.0/24",
    "8.31.160.0/23",
    "8.31.163.0/24",
    "8.31.2.0/24",
    "8.34.146.0/24",
    "8.34.200.0/23",
    "8.34.202.0/24",
    "8.34.69.0/24",
    "8.34.70.0/24",
    "8.34.71.0/24",
    "8.35.149.0/24",
    "8.35.211.0/24",
    "8.35.216.0/24",
    "8.35.57.0/24",
    "8.35.58.0/23",
    "8.36.216.0/22",
    "8.36.220.0/24",
    "8.37.41.0/24",
    "8.37.43.0/24",
    "8.38.147.0/24",
    "8.38.148.0/23",
    "8.38.172.0/24",
    "8.39.125.0/24",
    "8.39.126.0/23",
    "8.39.18.0/24",
    "8.39.201.0/24",
    "8.39.202.0/23",
    "8.39.204.0/24",
    "8.39.205.0/24",
    "8.39.206.0/24",
    "8.39.207.0/24",
    "8.39.212.0/23",
    "8.39.214.0/24",
    "8.39.215.0/24",
    "8.39.6.0/24",
    "8.40.107.0/24",
    "8.40.111.0/24",
    "8.40.140.0/24",
    "8.40.26.0/23",
    "8.40.28.0/22",
    "8.41.129.0/24",
    "8.41.36.0/23",
    "8.41.39.0/24",
    "8.41.5.0/24",
    "8.41.6.0/23",
    "8.42.161.0/24",
    "8.42.164.0/24",
    "8.42.172.0/24",
    "8.42.245.0/24",
    "8.42.51.0/24",
    "8.42.52.0/24",
    "8.42.54.0/23",
    "8.43.121.0/24",
    "8.43.122.0/23",
    "8.43.224.0/23",
    "8.43.226.0/24",
    "8.44.0.0/22",
    "8.44.58.0/23",
    "8.44.6.0/24",
    "8.44.60.0/24",
    "8.44.61.0/24",
    "8.44.62.0/23",
    "8.45.100.0/23",
    "8.45.102.0/24",
    "8.45.108.0/24",
    "8.45.111.0/24",
    "8.45.144.0/22",
    "8.45.151.0/24",
    "8.45.41.0/24",
    "8.45.42.0/23",
    "8.45.44.0/23",
    "8.45.46.0/24",
    "8.45.47.0/24",
    "8.45.97.0/24",
    "8.46.113.0/24",
    "8.46.114.0/23",
    "8.46.116.0/22",
    "8.47.12.0/22",
    "8.47.69.0/24",
    "8.47.71.0/24",
    "8.47.9.0/24",
    "8.48.130.0/24",
    "8.48.131.0/24",
    "8.48.132.0/23",
    "8.48.134.0/24",
    "8.6.112.0/24",
    "8.6.144.0/23",
    "8.6.146.0/24",
    "8.9.231.0/24",
    "88.205.100.68/30",
    "88.205.102.244/30",
    "89.202.33.124/30",
    "89.202.71.184/30",
    "89.47.56.0/23",
    "92.8.0.0/15",
    "93.114.64.0/23"
  ],
  "incapsula": [
    "103.28.248.0/22",
    "107.154.0.0/16",
    "131.125.128.0/17",
    "149.126.72.0/21",
    "185.11.124.0/22",
    "192.230.64.0/18",
    "198.143.32.0/19",
    "199.83.128.0/21",
    "2a02:e980::/29",
    "45.223.0.0/16",
    "45.60.0.0/16",
    "45.64.64.0/22"
  ]
});

/**
 * CNAME suffix rules (cdncheck `common`). The explicit `type` is ported from the pinned
 * CheckSuffix implementation; it is not inferred from provider-name overlap.
 */
export const EDGE_CNAME_RULES = Object.freeze([
  {
    "provider": "360 云 CDN (由奇安信运营)",
    "type": "waf",
    "suffixes": [
      "qhcdn.com"
    ]
  },
  {
    "provider": "360 云 CDN (由奇虎 360 运营)",
    "type": "waf",
    "suffixes": [
      "60cdn.com",
      "qihucdn.com"
    ]
  },
  {
    "provider": "360 云加速 CDN",
    "type": "waf",
    "suffixes": [
      "qh-cdn.com",
      "qss-lb.com"
    ]
  },
  {
    "provider": "akamai",
    "type": "waf",
    "suffixes": [
      "akamaiedge.net",
      "akamaihd.net",
      "akamaitechnologies.com",
      "edgekey.net",
      "edgesuite.net"
    ]
  },
  {
    "provider": "amazon",
    "type": "waf",
    "suffixes": [
      "amazonaws.com",
      "cloudfront.net"
    ]
  },
  {
    "provider": "arvancloud",
    "type": "waf",
    "suffixes": [
      "arvancdn.ir",
      "arvancloud.ir",
      "arvancloud.ru"
    ]
  },
  {
    "provider": "cloudflare",
    "type": "waf",
    "suffixes": [
      "cloudflare.com"
    ]
  },
  {
    "provider": "edgecast",
    "type": "waf",
    "suffixes": [
      "edgecastcdn.net",
      "edgesuite.net"
    ]
  },
  {
    "provider": "fastly",
    "type": "waf",
    "suffixes": [
      "fastly.net"
    ]
  },
  {
    "provider": "incapsula",
    "type": "waf",
    "suffixes": [
      "impervadns.net"
    ]
  },
  {
    "provider": "qrator",
    "type": "waf",
    "suffixes": [
      "qrator.net"
    ]
  },
  {
    "provider": "七牛云",
    "type": "waf",
    "suffixes": [
      "iniudns.com",
      "qbox.me",
      "qiniu.com"
    ]
  },
  {
    "provider": "云盾 CDN",
    "type": "waf",
    "suffixes": [
      "yunduncdn.com"
    ]
  },
  {
    "provider": "京东云 CDN",
    "type": "waf",
    "suffixes": [
      "jcloud-cdn.com",
      "jcloudcs.com",
      "jcloudlb.com",
      "jdcdn.com",
      "qianxun.com"
    ]
  },
  {
    "provider": "加速乐 CDN",
    "type": "waf",
    "suffixes": [
      "cdn.jiashule.com",
      "cname.365cyd.cn",
      "vip.jiasule.org"
    ]
  },
  {
    "provider": "华为云 CDN",
    "type": "waf",
    "suffixes": [
      "cdnhwc1.com",
      "cdnhwc2.com",
      "cdnhwc3.com"
    ]
  },
  {
    "provider": "华为云 WAF",
    "type": "waf",
    "suffixes": [
      "huaweicloud.com",
      "huaweicloudwaf.com"
    ]
  },
  {
    "provider": "又拍云 CDN",
    "type": "waf",
    "suffixes": [
      "aicdn.com"
    ]
  },
  {
    "provider": "奇安信网站卫士",
    "type": "waf",
    "suffixes": [
      "360anyu.com",
      "360cloudwaf.com",
      "360safedns.com",
      "360wzws.com",
      "qaxwzws.com"
    ]
  },
  {
    "provider": "安恒玄武盾",
    "type": "waf",
    "suffixes": [
      "dbappwaf.cn",
      "saaswaf.com"
    ]
  },
  {
    "provider": "帝联 CDN",
    "type": "waf",
    "suffixes": [
      "fastcdn.com"
    ]
  },
  {
    "provider": "广东网堤 CDN",
    "type": "waf",
    "suffixes": [
      "2cname.com"
    ]
  },
  {
    "provider": "深信服云盾",
    "type": "waf",
    "suffixes": [
      "sangfordns.com"
    ]
  },
  {
    "provider": "白山云科技 CDN",
    "type": "waf",
    "suffixes": [
      "bsclink.cn",
      "bsgslb.cn",
      "qingcdn.com",
      "trpcdn.net"
    ]
  },
  {
    "provider": "绿盟云 WAF",
    "type": "waf",
    "suffixes": [
      "nscloudwaf.com"
    ]
  },
  {
    "provider": "网宿 CDN",
    "type": "waf",
    "suffixes": [
      "51cdn.com",
      "cdn20.com",
      "cdn30.com",
      "chinanetcenter.com",
      "customcdn.cn",
      "customcdn.com.cn",
      "lxdns.com",
      "mwcloudcdn.com",
      "mwcname.com",
      "ourplat.net",
      "speedcdns.com",
      "wscdns.com",
      "wscloudcdn.com",
      "wsdvs.com",
      "wsglb0.com",
      "wsssec.com",
      "wswebcdn.com",
      "wswebpic.com",
      "wtxcdn.com"
    ]
  },
  {
    "provider": "网神 CDN",
    "type": "waf",
    "suffixes": [
      "360wzws.com",
      "qaxcloudwaf.com",
      "qaxwzws.com"
    ]
  },
  {
    "provider": "美橙 CDN",
    "type": "waf",
    "suffixes": [
      "51hostonline.cn",
      "cndns5.com",
      "websitecname.cn"
    ]
  },
  {
    "provider": "腾正安全加速 (原 15CDN)",
    "type": "waf",
    "suffixes": [
      "15cdn.com",
      "tzcdn.cn"
    ]
  },
  {
    "provider": "腾讯云 CDN",
    "type": "waf",
    "suffixes": [
      "cdn.dnsv1.com",
      "cdntip.com",
      "dnsv1.com",
      "qcloudcjgj.com",
      "qcloudwaf.com",
      "qcloudwzgj.com",
      "qcloudzygj.com",
      "tdnsv5.com",
      "tencdns.net"
    ]
  },
  {
    "provider": "蓝盾云 CDN",
    "type": "waf",
    "suffixes": [
      "cloudfence.cn"
    ]
  },
  {
    "provider": "阿里云 CDN",
    "type": "waf",
    "suffixes": [
      "alicloudwaf.com",
      "alikunlun.com",
      "cdngslb.com",
      "kunlunca.com",
      "kunluncan.com",
      "kunlunea.com",
      "kunlunpi.com",
      "yundunwaf1.com",
      "yundunwaf2.com",
      "yundunwaf3.com",
      "yundunwaf4.com",
      "yundunwaf5.com"
    ]
  }
]);

export const EDGE_CORPUS_STATS = Object.freeze({
  waf_plugins_total: 172,
  waf_plugins_supported: 172,
  waf_plugins_unsupported: 0,
  waf_vendors: 172,
  passive_signatures: 188,
  block_page_signatures: 330,
  cdn_providers: 16,
  waf_range_providers: 3,
  cname_providers: 32,
  cdn_ranges: 2462,
  waf_ranges: 1071,
  cname_suffixes: 103,
});
