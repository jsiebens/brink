package version

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

var (
	Version    string
	GitCommit  string
	DevVersion = "dev"
)

func BuildVersion() string {
	if len(Version) == 0 {
		return DevVersion
	}
	return Version
}

func GetReleaseInfo() (string, string) {
	return BuildVersion(), GitCommit
}

func GetReleaseInfoHandler(c echo.Context) error {
	v, r := GetReleaseInfo()
	m := map[string]string{
		"version":  v,
		"revision": r,
	}
	return c.JSON(http.StatusOK, m)
}
