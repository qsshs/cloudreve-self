package middleware

import (
	"fmt"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"

	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

// Public组文件非匿名用户验证
func PublicAuthFileRequested() gin.HandlerFunc {
	return func(c *gin.Context) {
		qPath := c.Request.URL.Query().Get("uri")
		if qPath == "" {
			c.Next()
			return
		}

		u := inventory.UserFromContext(c)
		if u.ID == 0 && strings.HasSuffix(qPath, "@share") && strings.HasPrefix(qPath, "cloudreve://") {
			id_ps := strings.TrimPrefix(strings.TrimSuffix(qPath, "@share"), "cloudreve://")
			ss := strings.Split(id_ps, ":")
			shareID := ""
			if len(ss) == 2 || len(ss) == 1 {
				shareID = ss[0]
			} else {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeParamErr, "Invalid file URI", nil))
				c.Abort()
				return
			}
			dep := dependency.FromContext(c)
			shareClient := dep.ShareClient()

			share, err := shareClient.GetByHashID(c, shareID)
			if err != nil {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeParamErr, fmt.Sprintf("Invalid share ID: %d", shareID), nil))
				c.Abort()
				return
			}

			user, err := share.QueryUser().Only(c)
			if err != nil {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeParamErr, "Failed to retrieve share owner", nil))
				c.Abort()
				return
			}

			group, err := user.QueryGroup().Only(c)
			if err != nil {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeParamErr, "Failed to retrieve share owner's group", nil))
				c.Abort()
				return
			}

			if group.Name == "Public" {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeGroupNotAllowed, "cannot be accessed anonymously", nil))
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
