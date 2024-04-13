/*
 * Copyright (c) 2023 ivfzhou
 * backend is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package route

import (
	"github.com/gin-gonic/gin"

	"backend/api"
)

func initAPIRoute(r *gin.RouterGroup) {
	upload := &api.FileAPI{}
	uploadGroup := r.Group("/upload")
	uploadGroup.POST("/initialUpload", upload.InitialUpload)
	uploadGroup.PATCH("/uploadPart", upload.UploadPart)
	uploadGroup.POST("/mergePart", upload.MergePart)
}
