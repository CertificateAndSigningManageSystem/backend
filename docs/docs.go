// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/upload/initialUpload": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "file-api"
                ],
                "summary": "初始化分片上传",
                "parameters": [
                    {
                        "type": "string",
                        "description": "jwt凭证",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "reqBody",
                        "name": "reqBody",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/protocol.InitialUploadReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/protocol.InitialUploadRsp"
                        }
                    }
                }
            }
        },
        "/api/upload/mergePart": {
            "post": {
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "tags": [
                    "file-api"
                ],
                "summary": "合并分片",
                "parameters": [
                    {
                        "type": "string",
                        "description": "jwt凭证",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "文件Id",
                        "name": "fileId",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    }
                }
            }
        },
        "/api/upload/uploadPart": {
            "patch": {
                "consumes": [
                    "multipart/form-data"
                ],
                "tags": [
                    "file-api"
                ],
                "summary": "上传分片",
                "parameters": [
                    {
                        "type": "string",
                        "description": "jwt凭证",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "type": "file",
                        "description": "文件",
                        "name": "file",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "分片序号",
                        "name": "fileId",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "文件Id",
                        "name": "chunkNum",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    }
                }
            }
        }
    },
    "definitions": {
        "protocol.InitialUploadReq": {
            "type": "object",
            "properties": {
                "md5": {
                    "type": "string"
                },
                "name": {
                    "type": "string"
                },
                "sha1": {
                    "type": "string"
                },
                "sha256": {
                    "type": "string"
                },
                "size": {
                    "type": "integer"
                }
            }
        },
        "protocol.InitialUploadRsp": {
            "type": "object",
            "properties": {
                "exists": {
                    "type": "boolean"
                },
                "id": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}