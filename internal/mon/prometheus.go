package mon

import (
	echo_prometheus "github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
)

var (
	e          *echo.Echo
	middleware echo.MiddlewareFunc
)

func init() {
	p := echo_prometheus.NewPrometheus("http", nil)
	e = echo.New()
	e.HidePort = true
	e.HideBanner = true
	p.SetMetricsPath(e)

	middleware = p.HandlerFunc
}

func Middleware() echo.MiddlewareFunc {
	return middleware
}

func Echo() *echo.Echo {
	return e
}
