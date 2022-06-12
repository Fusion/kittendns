package fetch

import (
	"io/ioutil"
	"net/http"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
	_ "github.com/dop251/goja_nodejs/util"
)

type Fetch struct {
	runtime *goja.Runtime
	util    *goja.Object
}

type Response struct {
	StatusCode int
	Body       string
}

func (f *Fetch) getter(v goja.Value, thenAction goja.Callable, rejectAction goja.Callable) {
	res, err := http.Get(v.String())
	if err != nil {
		rejectAction(goja.Undefined(), f.runtime.ToValue("Error: "+err.Error()))
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		rejectAction(goja.Undefined(), f.runtime.ToValue("Error: "+err.Error()))
		return
	}
	thenAction(goja.Undefined(), f.runtime.ToValue(Response{StatusCode: res.StatusCode, Body: string(body)}))
}

func Require(runtime *goja.Runtime, module *goja.Object) {
	func(runtime *goja.Runtime, module *goja.Object) {
		f := &Fetch{
			runtime: runtime,
		}
		f.util = require.Require(runtime, "util").(*goja.Object)
		o := module.Get("exports").(*goja.Object)
		o.Set("get", f.getter)
	}(runtime, module)
}

func Enable(runtime *goja.Runtime) {
	runtime.Set("fetch", require.Require(runtime, "fetch"))
}

func init() {
	require.RegisterNativeModule("fetch", Require)
}
